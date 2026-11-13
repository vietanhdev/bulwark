#!/usr/bin/env bash
# Sign and notarize Bulwark's macOS artifacts in CI — or, without Apple credentials, sign them
# ad-hoc — and prove the result with Gatekeeper's own verdict.
#
#   scripts/macos-sign.sh setup             import the Developer ID certificate into a temporary
#                                           keychain; prints KEY=value lines for $GITHUB_ENV
#   scripts/macos-sign.sh cli <binary>      sign the CLI (hardened runtime) and notarize it
#   scripts/macos-sign.sh dmg <dmg>         sign, notarize and staple the disk image
#   scripts/macos-sign.sh verify <app> <dmg> <binary>
#
# Credentials come from the environment (GitHub secrets), never from arguments:
#   APPLE_CERTIFICATE           base64 of the exported "Developer ID Application" .p12
#   APPLE_CERTIFICATE_PASSWORD  its export password
#   APPLE_SIGNING_IDENTITY      "Developer ID Application: <name> (<team id>)"
#   APPLE_API_ISSUER            App Store Connect API issuer id   (notarization)
#   APPLE_API_KEY               App Store Connect API key id      (notarization)
#   APPLE_API_PRIVATE_KEY       contents of that key's AuthKey_<id>.p8
#
# With no certificate the artifacts are signed ad-hoc: a complete, valid signature, so macOS
# offers "Open Anyway" in Privacy & Security instead of calling the app damaged — but not
# trusted. `verify` holds each mode to what it can deliver; with a certificate it requires
# Gatekeeper to report "Notarized Developer ID", so a signing step that silently did nothing
# fails the release instead of shipping.
set -euo pipefail

signed() { [ -n "${APPLE_SIGNING_IDENTITY:-}" ] && [ "${APPLE_SIGNING_IDENTITY}" != "-" ]; }

api_key_file() {
  local f="${RUNNER_TEMP:-/tmp}/AuthKey_${APPLE_API_KEY}.p8"
  if [ ! -s "$f" ]; then
    (umask 077 && printf '%s\n' "$APPLE_API_PRIVATE_KEY" >"$f")
  fi
  echo "$f"
}

notarize() { # file — submit to Apple's notary service and wait; fail unless "Accepted"
  local out
  out=$(xcrun notarytool submit "$1" --wait --timeout 30m \
    --key "$(api_key_file)" --key-id "$APPLE_API_KEY" --issuer "$APPLE_API_ISSUER" 2>&1) || true
  echo "$out"
  if ! grep -q "status: Accepted" <<<"$out"; then
    local id
    id=$(sed -n 's/^ *id: //p' <<<"$out" | head -1)
    [ -n "$id" ] && xcrun notarytool log "$id" --key "$(api_key_file)" \
      --key-id "$APPLE_API_KEY" --issuer "$APPLE_API_ISSUER" || true
    echo "::error::notarization of $1 was not accepted"
    exit 1
  fi
}

case "${1:-}" in
setup)
  if [ -z "${APPLE_CERTIFICATE:-}" ]; then
    echo "::warning::No Apple Developer ID certificate configured: the macOS app is signed ad-hoc. Users must allow it in System Settings → Privacy & Security." >&2
    echo "APPLE_SIGNING_IDENTITY=-"
    exit 0
  fi
  for v in APPLE_CERTIFICATE_PASSWORD APPLE_SIGNING_IDENTITY APPLE_API_ISSUER APPLE_API_KEY APPLE_API_PRIVATE_KEY; do
    [ -n "${!v:-}" ] || { echo "::error::$v is not set; a certificate without it can't sign and notarize" >&2; exit 1; }
  done
  KC="${RUNNER_TEMP}/bulwark-signing.keychain-db"
  KCPW=$(openssl rand -hex 24)
  P12="${RUNNER_TEMP}/cert.p12"
  (umask 077 && base64 --decode >"$P12" <<<"$APPLE_CERTIFICATE")
  security create-keychain -p "$KCPW" "$KC" >&2
  security set-keychain-settings -lut 21600 "$KC" >&2
  security unlock-keychain -p "$KCPW" "$KC" >&2
  security import "$P12" -k "$KC" -P "$APPLE_CERTIFICATE_PASSWORD" -T /usr/bin/codesign -T /usr/bin/security >&2
  rm -f "$P12"
  security set-key-partition-list -S apple-tool:,apple: -s -k "$KCPW" "$KC" >/dev/null
  # Search this keychain first, keeping the existing ones (system roots, intermediates).
  existing=()
  while IFS= read -r kc; do
    kc="${kc//\"/}"
    kc="${kc#"${kc%%[![:space:]]*}"}"
    [ -n "$kc" ] && existing+=("$kc")
  done < <(security list-keychains -d user)
  # The `+` form because macOS ships bash 3.2, where an empty array is "unbound" under `set -u`.
  security list-keychains -d user -s "$KC" ${existing[@]+"${existing[@]}"} >&2
  if ! security find-identity -v -p codesigning "$KC" | grep -qF "$APPLE_SIGNING_IDENTITY"; then
    security find-identity -v -p codesigning "$KC" >&2
    echo "::error::the certificate doesn't contain the identity APPLE_SIGNING_IDENTITY names" >&2
    exit 1
  fi
  # What `tauri build` reads to sign the app with this keychain's identity and notarize it.
  echo "APPLE_SIGNING_IDENTITY=$APPLE_SIGNING_IDENTITY"
  echo "APPLE_API_ISSUER=$APPLE_API_ISSUER"
  echo "APPLE_API_KEY=$APPLE_API_KEY"
  echo "APPLE_API_KEY_PATH=$(api_key_file)"
  ;;

cli)
  BIN="$2"
  if signed; then
    codesign --force --options runtime --timestamp --sign "$APPLE_SIGNING_IDENTITY" "$BIN"
    ZIP="${RUNNER_TEMP:-/tmp}/bulwarkctl-notarize.zip"
    rm -f "$ZIP" && ditto -c -k --keepParent "$BIN" "$ZIP"
    # A bare executable can't carry a stapled ticket; Gatekeeper looks it up online instead.
    notarize "$ZIP"
  else
    codesign --force --sign - "$BIN"
  fi
  ;;

dmg)
  DMG="$2"
  if signed; then
    codesign --force --timestamp --sign "$APPLE_SIGNING_IDENTITY" "$DMG"
    notarize "$DMG"
    xcrun stapler staple "$DMG"
  fi
  ;;

verify)
  APP="$2" DMG="$3" BIN="$4"
  codesign --verify --deep --strict --verbose=2 "$APP"
  codesign --verify --strict --verbose=2 "$BIN"
  # The sidecar the app runs for privileged scans must be signed as part of the bundle.
  codesign --verify --strict --verbose=2 "$APP/Contents/MacOS/bulwark"
  if signed; then
    for f in "$APP" "$BIN"; do
      codesign -dv --verbose=2 "$f" 2>&1 | grep -q "^Authority=Developer ID Application" ||
        { echo "::error::$f is not signed with the Developer ID certificate"; exit 1; }
      codesign -dv "$f" 2>&1 | grep -q "flags=.*runtime" ||
        { echo "::error::$f is signed without the hardened runtime notarization needs"; exit 1; }
    done
    spctl --assess --type execute -vv "$APP" 2>&1 | tee /dev/stderr | grep -q "source=Notarized Developer ID" ||
      { echo "::error::Gatekeeper doesn't accept the app as notarized"; exit 1; }
    spctl --assess --type open --context context:primary-signature -vv "$DMG" 2>&1 | tee /dev/stderr |
      grep -q "source=Notarized Developer ID" ||
      { echo "::error::Gatekeeper doesn't accept the disk image as notarized"; exit 1; }
    xcrun stapler validate "$DMG"
  else
    codesign -dv "$APP" 2>&1 | grep -q "Signature=adhoc" ||
      { echo "::error::expected an ad-hoc signature on the app"; exit 1; }
  fi
  echo "macOS signatures verified ($(signed && echo 'Developer ID, notarized' || echo ad-hoc))"
  ;;

*)
  sed -n '2,24p' "$0"
  exit 2
  ;;
esac
