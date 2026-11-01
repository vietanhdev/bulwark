//! Windows security posture: Defender, the firewall profiles, BitLocker on the system drive, UAC,
//! Remote Desktop, SMBv1, the Guest account, automatic sign-in and how recently Windows updated —
//! the settings that decide how exposed a Windows machine is.
//!
//! One PowerShell invocation reads everything and prints a single JSON object. Each value is read
//! inside its own `try`, so one unreadable setting (BitLocker needs an elevated session, for
//! example) becomes `null` — "unknown" — without hiding the others. Every fact carries a `*_known`
//! flag and no rule fires on an unknown value: a scanner that reads "couldn't query BitLocker" as
//! "BitLocker is off" would raise a high-severity alarm on an encrypted machine.
//!
//! The JSON parsing is pure and unit-tested on every OS against the exact shapes a real Windows 11
//! machine returns (PowerShell renders the firewall's `Enabled` as `1`, not `true`, and an unset
//! policy as nothing at all); only `collect()` needs Windows.

use super::Collector;
use crate::models::{Fact, OperatingSystem};
use serde_json::Value;

const WINDOWS_ONLY: &[OperatingSystem] = &[OperatingSystem::Windows];

/// Every read is independent and failure-tolerant; the script always prints one JSON object.
const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$r = @{}
try { $d = Get-MpComputerStatus; $r.defender_realtime = [bool]$d.RealTimeProtectionEnabled; $r.defender_av = [bool]$d.AntivirusEnabled; $r.defender_signature_age = [int]$d.AntivirusSignatureAge } catch {}
try { $p = @(Get-NetFirewallProfile); $r.firewall_profiles = @($p | ForEach-Object { @{ name = [string]$_.Name; enabled = ([string]$_.Enabled -in @('1','True')) } }) } catch {}
try { $b = Get-BitLockerVolume -MountPoint $env:SystemDrive; $r.bitlocker_protection = [int]$b.ProtectionStatus } catch {}
try { $r.uac_enable_lua = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA } catch {}
try { $r.rdp_deny = [int](Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections } catch {}
try { $r.rdp_nla = [int](Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication } catch {}
try { $r.smb1 = [bool](Get-SmbServerConfiguration).EnableSMB1Protocol } catch {}
try { $g = Get-LocalUser | Where-Object { "$($_.SID)" -like '*-501' } | Select-Object -First 1; if ($g) { $r.guest_enabled = [bool]$g.Enabled } } catch {}
try { $w = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; $r.autologon_enabled = ([string]$w.AutoAdminLogon -eq '1'); $r.autologon_password_stored = [bool]($w.PSObject.Properties.Name -contains 'DefaultPassword') } catch {}
try { $h = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1; if ($h) { $r.last_update_days = [int]((Get-Date) - $h.InstalledOn).TotalDays } } catch {}
$r | ConvertTo-Json -Compress -Depth 4
"#;

pub struct WindowsSecurityCollector;

fn set_bool(f: &mut Fact, key: &str, v: Option<bool>) {
    f.insert(format!("{key}_known"), Value::Bool(v.is_some()));
    f.insert(key.to_string(), Value::Bool(v.unwrap_or(false)));
}

/// Turns the script's JSON into the single fact row the rules read.
pub(crate) fn fact_from_json(v: &Value) -> Fact {
    let b = |k: &str| v.get(k).and_then(Value::as_bool);
    let i = |k: &str| v.get(k).and_then(Value::as_i64);
    let mut f = Fact::new();

    set_bool(&mut f, "defender_realtime", b("defender_realtime"));
    let age = i("defender_signature_age");
    f.insert(
        "defender_signature_age_known".into(),
        Value::Bool(age.is_some()),
    );
    f.insert(
        "defender_signature_age".into(),
        Value::from(age.unwrap_or(0)),
    );

    // Firewall: off if any profile is off; the names of the off ones for the explanation.
    let profiles: Option<Vec<(String, bool)>> = v.get("firewall_profiles").map(|p| {
        // A single profile can come back as an object rather than a one-element array.
        let list: Vec<&Value> = match p {
            Value::Array(a) => a.iter().collect(),
            other => vec![other],
        };
        list.iter()
            .filter_map(|e| {
                Some((
                    e.get("name")?.as_str()?.to_string(),
                    e.get("enabled")?.as_bool()?,
                ))
            })
            .collect()
    });
    let profiles = profiles.filter(|p| !p.is_empty());
    set_bool(
        &mut f,
        "firewall_all_on",
        profiles.as_ref().map(|p| p.iter().all(|(_, on)| *on)),
    );
    f.insert(
        "firewall_off_profiles".into(),
        Value::String(
            profiles
                .unwrap_or_default()
                .into_iter()
                .filter(|(_, on)| !on)
                .map(|(n, _)| n)
                .collect::<Vec<_>>()
                .join(", "),
        ),
    );

    // BitLocker ProtectionStatus: 1 = On, 0 = Off, 2 = Unknown (treated as unknown).
    set_bool(
        &mut f,
        "bitlocker_on",
        match i("bitlocker_protection") {
            Some(1) => Some(true),
            Some(0) => Some(false),
            _ => None,
        },
    );
    set_bool(&mut f, "uac_enabled", i("uac_enable_lua").map(|x| x != 0));
    set_bool(&mut f, "rdp_enabled", i("rdp_deny").map(|x| x == 0));
    set_bool(&mut f, "rdp_nla", i("rdp_nla").map(|x| x == 1));
    set_bool(&mut f, "smb1_enabled", b("smb1"));
    // The built-in Guest account, found by its well-known RID (-501) because its name is localised.
    set_bool(&mut f, "guest_enabled", b("guest_enabled"));
    // Automatic sign-in only matters with a password stored for it: that one sits in the registry
    // in plain text. Only whether it exists is read — never the value.
    set_bool(
        &mut f,
        "autologon_password_stored",
        match (b("autologon_enabled"), b("autologon_password_stored")) {
            (Some(on), Some(stored)) => Some(on && stored),
            _ => None,
        },
    );
    let days = i("last_update_days");
    f.insert("last_update_days_known".into(), Value::Bool(days.is_some()));
    f.insert("last_update_days".into(), Value::from(days.unwrap_or(0)));
    f
}

impl Collector for WindowsSecurityCollector {
    fn name(&self) -> &'static str {
        "windows_security"
    }

    fn supported_os(&self) -> &'static [OperatingSystem] {
        WINDOWS_ONLY
    }

    fn is_applicable(&self) -> bool {
        cfg!(target_os = "windows")
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        let out = crate::sandbox::quiet_command("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                SCRIPT,
            ])
            .output()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let v: Value = serde_json::from_str(text.trim()).map_err(|e| {
            anyhow::anyhow!("PowerShell returned something that isn't the expected JSON: {e}")
        })?;
        Ok(vec![fact_from_json(&v)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get<'a>(f: &'a Fact, k: &str) -> &'a Value {
        f.get(k).unwrap_or_else(|| panic!("missing {k}"))
    }

    #[test]
    fn a_hardened_windows_11_machine_reads_as_hardened() {
        // The shape a real, well-configured Windows 11 machine produces.
        let v: Value = serde_json::from_str(
            r#"{"defender_realtime":true,"defender_av":true,"defender_signature_age":0,
                "firewall_profiles":[{"name":"Domain","enabled":true},{"name":"Private","enabled":true},{"name":"Public","enabled":true}],
                "bitlocker_protection":1,"uac_enable_lua":1,"rdp_deny":1,"rdp_nla":1,"smb1":false}"#,
        )
        .unwrap();
        let f = fact_from_json(&v);
        assert_eq!(get(&f, "defender_realtime"), &Value::Bool(true));
        assert_eq!(get(&f, "firewall_all_on"), &Value::Bool(true));
        assert_eq!(get(&f, "bitlocker_on"), &Value::Bool(true));
        assert_eq!(get(&f, "uac_enabled"), &Value::Bool(true));
        assert_eq!(get(&f, "rdp_enabled"), &Value::Bool(false));
        assert_eq!(get(&f, "smb1_enabled"), &Value::Bool(false));
        assert_eq!(get(&f, "smb1_enabled_known"), &Value::Bool(true));
    }

    #[test]
    fn unreadable_settings_are_unknown_not_off() {
        // A non-elevated session can't read BitLocker; nothing else came back either.
        let f = fact_from_json(&serde_json::json!({}));
        for k in [
            "defender_realtime",
            "firewall_all_on",
            "bitlocker_on",
            "uac_enabled",
            "rdp_enabled",
            "smb1_enabled",
        ] {
            assert_eq!(get(&f, &format!("{k}_known")), &Value::Bool(false), "{k}");
        }
        // ProtectionStatus 2 ("Unknown") stays unknown.
        let f = fact_from_json(&serde_json::json!({"bitlocker_protection": 2}));
        assert_eq!(get(&f, "bitlocker_on_known"), &Value::Bool(false));
    }

    #[test]
    fn a_disabled_firewall_profile_is_named() {
        let f = fact_from_json(&serde_json::json!({"firewall_profiles": [
            {"name":"Domain","enabled":true},{"name":"Public","enabled":false}]}));
        assert_eq!(get(&f, "firewall_all_on"), &Value::Bool(false));
        assert_eq!(
            get(&f, "firewall_off_profiles"),
            &Value::String("Public".into())
        );
        // One profile serialised as an object, not an array.
        let f = fact_from_json(
            &serde_json::json!({"firewall_profiles": {"name":"Public","enabled":true}}),
        );
        assert_eq!(get(&f, "firewall_all_on"), &Value::Bool(true));
    }

    #[test]
    fn guest_autologon_and_update_age_are_read_and_unknown_when_absent() {
        let f = fact_from_json(&serde_json::json!({
            "guest_enabled": true, "autologon_enabled": true,
            "autologon_password_stored": true, "last_update_days": 74}));
        assert_eq!(get(&f, "guest_enabled"), &Value::Bool(true));
        assert_eq!(get(&f, "autologon_password_stored"), &Value::Bool(true));
        assert_eq!(get(&f, "last_update_days"), &Value::from(74));
        // A stored password with automatic sign-in switched off is a leftover, not a live risk.
        let f = fact_from_json(&serde_json::json!({
            "autologon_enabled": false, "autologon_password_stored": true}));
        assert_eq!(get(&f, "autologon_password_stored"), &Value::Bool(false));
        assert_eq!(
            get(&f, "autologon_password_stored_known"),
            &Value::Bool(true)
        );
        // Nothing read: every one is unknown, so no rule can fire.
        let f = fact_from_json(&serde_json::json!({}));
        for k in [
            "guest_enabled",
            "autologon_password_stored",
            "last_update_days",
        ] {
            assert_eq!(get(&f, &format!("{k}_known")), &Value::Bool(false), "{k}");
        }
    }

    #[test]
    fn only_declares_windows_support() {
        assert_eq!(
            WindowsSecurityCollector.supported_os(),
            &[OperatingSystem::Windows]
        );
    }
}
