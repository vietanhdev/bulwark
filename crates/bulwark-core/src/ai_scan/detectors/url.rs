//! Just enough URL reading to answer two questions about an address written in a config file:
//! which host does it reach, and does it carry a credential.

use std::net::{Ipv4Addr, Ipv6Addr};

/// The parts of `scheme://[userinfo@]host[:port][/path][?query][#fragment]` the detectors use.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Url<'a> {
    /// Lower-cased.
    pub scheme: String,
    /// `user`, `user:password` or a bare token, when the address has one.
    pub userinfo: Option<&'a str>,
    /// Lower-cased, without the brackets of an IPv6 literal and without a trailing dot.
    pub host: String,
    pub query: Option<&'a str>,
}

/// Parses an absolute URL. `None` for anything else (a relative path, a bare host name).
pub(crate) fn parse(url: &str) -> Option<Url<'_>> {
    let url = url.trim();
    let (scheme, rest) = url.split_once("://")?;
    let mut scheme_chars = scheme.chars();
    if !scheme_chars.next()?.is_ascii_alphabetic()
        || !scheme_chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
    {
        return None;
    }
    // The authority ends at the path, the query or the fragment. A backslash ends it too: browsers
    // and several HTTP clients read `\` as `/`, and an address must not hide its host behind one.
    let end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
    let (authority, after) = rest.split_at(end);
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((user, host)) => (Some(user), host),
        None => (None, authority),
    };
    let host = match hostport.strip_prefix('[') {
        Some(v6) => v6.split_once(']')?.0,
        None => match hostport.rsplit_once(':') {
            Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
            _ => hostport,
        },
    };
    let query = after
        .split_once('?')
        .map(|(_, q)| q.split('#').next().unwrap_or(q));
    Some(Url {
        scheme: scheme.to_ascii_lowercase(),
        userinfo,
        host: host.trim_end_matches('.').to_ascii_lowercase(),
        query,
    })
}

/// An IPv4 address in any spelling the C library's `inet_aton` reads, which is what `curl`, most
/// HTTP stacks and browsers accept: one to four numbers, each decimal, hex (`0x7f`) or octal
/// (`0177`), the last one filling whatever bytes remain. `127.0.0.1`, `127.1`, `2130706433` and
/// `0x7f000001` are all the same address.
fn inet_aton(host: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return None;
    }
    let mut numbers = Vec::with_capacity(parts.len());
    for part in &parts {
        let lower = part.to_ascii_lowercase();
        let n = if let Some(hex) = lower.strip_prefix("0x") {
            u32::from_str_radix(hex, 16).ok()?
        } else if lower.len() > 1 && lower.starts_with('0') {
            u32::from_str_radix(&lower[1..], 8).ok()?
        } else {
            lower.parse::<u32>().ok()?
        };
        numbers.push(n);
    }
    let (last, leading) = numbers.split_last()?;
    let mut address: u32 = 0;
    for n in leading {
        if *n > 255 {
            return None;
        }
        address = (address << 8) | n;
    }
    let remaining_bits = 8 * (4 - leading.len()) as u32;
    if remaining_bits < 32 && *last >= (1 << remaining_bits) {
        return None;
    }
    let address = if remaining_bits == 32 {
        *last
    } else {
        (address << remaining_bits) | last
    };
    Some(Ipv4Addr::from(address))
}

/// Whether `host` (as [`parse`] returns it) is this machine: `localhost`, any `*.localhost` name,
/// the IPv4 loopback block in any spelling, `::1`, an IPv4-mapped loopback, or the unspecified
/// address a local server binds to (`0.0.0.0`, `::`).
pub(crate) fn is_local_host(host: &str) -> bool {
    let v4_local = |a: Ipv4Addr| a.is_loopback() || a.is_unspecified();
    host == "localhost"
        || host.ends_with(".localhost")
        || host.parse::<Ipv6Addr>().is_ok_and(|a| {
            a.is_loopback() || a.is_unspecified() || a.to_ipv4_mapped().is_some_and(v4_local)
        })
        || inet_aton(host).is_some_and(v4_local)
}

/// A host as a finding may show it: a plain name or address, or a neutral phrase when it is
/// anything else (so nothing but a host name can reach a finding through one).
pub(crate) fn shown_host(host: &str) -> String {
    let plain = !host.is_empty()
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'));
    if !plain {
        "an address in this file".to_string()
    } else if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_is_what_the_request_reaches() {
        for (url, host) in [
            ("https://api.anthropic.com/v1", "api.anthropic.com"),
            ("HTTPS://API.ANTHROPIC.COM", "api.anthropic.com"),
            ("Https://api.anthropic.com.", "api.anthropic.com"),
            ("http://[::1]:4000/mcp", "::1"),
            ("http://127.0.0.1:4000", "127.0.0.1"),
            // Userinfo is not the host, whatever it looks like.
            ("https://api.anthropic.com@evil.invalid/", "evil.invalid"),
            ("https://user:pw@api.openai.com", "api.openai.com"),
            // Nor is anything after the authority.
            ("https://evil.invalid/?x=api.anthropic.com", "evil.invalid"),
            ("https://evil.invalid#@api.anthropic.com", "evil.invalid"),
            ("https://evil.invalid\\@api.anthropic.com", "evil.invalid"),
        ] {
            assert_eq!(parse(url).unwrap().host, host, "{url}");
        }
        assert_eq!(
            parse("https://h/p?token=a&b=c#frag").unwrap().query,
            Some("token=a&b=c")
        );
        assert_eq!(parse("https://tok@h/").unwrap().userinfo, Some("tok"));
        assert!(parse("//evil.invalid").is_none());
        assert!(parse("evil.invalid").is_none());
        assert!(parse("http://[::1").is_none());
    }

    #[test]
    fn loopback_in_every_spelling_is_local() {
        for local in [
            "localhost",
            "app.localhost",
            "127.0.0.1",
            "127.1",
            "127.0.1",
            "2130706433",
            "0x7f000001",
            "0177.0.0.1",
            "0x7f.1",
            "0.0.0.0",
            "::1",
            "::",
            "::ffff:127.0.0.1",
        ] {
            assert!(is_local_host(local), "{local}");
        }
        for remote in [
            "evil.invalid",
            "localhost.evil.invalid",
            "127.0.0.1.evil.invalid",
            "128.0.0.1",
            "2130706433.evil.invalid",
            "1.2.3.4",
            "16777217",
            "::2",
            "999.0.0.1",
            "",
        ] {
            assert!(!is_local_host(remote), "{remote}");
        }
    }

    #[test]
    fn only_a_plain_host_is_shown() {
        assert_eq!(shown_host("evil.invalid"), "evil.invalid");
        assert_eq!(shown_host("::1"), "[::1]");
        assert_eq!(shown_host("a b"), "an address in this file");
        assert_eq!(shown_host("x_y/z"), "an address in this file");
        assert_eq!(shown_host(""), "an address in this file");
    }
}
