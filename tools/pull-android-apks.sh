#!/usr/bin/env bash
set -euo pipefail

fail() {
  printf 'Android APK capture: %s\n' "$1" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
Usage: tools/pull-android-apks.sh --out <new-directory> [--serial <adb-serial>] [package ...]

With no package arguments, pulls the official app package IDs used by this project:
  com.coolkit
  cn.com.broadlink.econtrol.international
  com.xiaomi.smarthome
  com.yoosee
  com.juanvision.eseecloud30

All APK splits are copied without installing or launching the apps. A SHA256SUMS
file is generated. If apksigner is installed, each APK signature is checked
and its certificate digest is recorded. This checks signature integrity, not
publisher identity: compare the certificate digest with a trusted official
copy before treating the APK as authentic. Without apksigner, the capture is
marked UNVERIFIED.
EOF
}

out_dir=
serial=
packages=()
while (($#)); do
  case "$1" in
    --out)
      (($# >= 2)) || { usage; fail "--out requires a directory"; }
      out_dir="$2"
      shift 2
      ;;
    --serial)
      (($# >= 2)) || { usage; fail "--serial requires a device serial"; }
      serial="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      packages+=("$@")
      break
      ;;
    -* )
      usage
      fail "unknown option: $1"
      ;;
    *)
      packages+=("$1")
      shift
      ;;
  esac
done

[[ -n "$out_dir" ]] || { usage; fail "--out is required"; }
command -v adb >/dev/null 2>&1 || fail "adb is not installed; install Android platform-tools first"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required"

if ((${#packages[@]} == 0)); then
  packages=(
    com.coolkit
    cn.com.broadlink.econtrol.international
    com.xiaomi.smarthome
    com.yoosee
    com.juanvision.eseecloud30
  )
fi

for package in "${packages[@]}"; do
  [[ "$package" =~ ^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+$ ]] \
    || fail "invalid Android package name: $package"
done

mapfile -t ready_devices < <(adb devices | awk 'NR > 1 && $2 == "device" { print $1 }')
if [[ -z "$serial" ]]; then
  ((${#ready_devices[@]} == 1)) \
    || fail "connect exactly one authorized Android device or pass --serial"
  serial="${ready_devices[0]}"
else
  serial_found=false
  for ready_serial in "${ready_devices[@]}"; do
    if [[ "$ready_serial" == "$serial" ]]; then
      serial_found=true
      break
    fi
  done
  [[ "$serial_found" == true ]] || fail "ADB device $serial is not connected and authorized"
fi
adb_args=(-s "$serial")

if [[ -e "$out_dir" || -L "$out_dir" ]]; then
  fail "output path already exists; choose a new empty path: $out_dir"
fi
mkdir -p -- "$out_dir"
chmod 700 -- "$out_dir"
out_dir="$(cd -- "$out_dir" && pwd -P)"

if command -v apksigner >/dev/null 2>&1; then
  capture_state=signature-integrity-checked
else
  capture_state=UNVERIFIED
fi
manifest="$out_dir/CAPTURE.txt"
{
  printf 'device_serial=%s\n' "$serial"
  printf 'captured_at_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'signature_verification=%s\n' "$capture_state"
  printf 'source=APK files pulled from installed Android packages; files were not executed\n'
} > "$manifest"
chmod 600 -- "$manifest"

for package in "${packages[@]}"; do
  paths_output="$(adb "${adb_args[@]}" shell pm path "$package" | tr -d '\r')" \
    || fail "could not query installed APK paths for $package"
  [[ -n "$paths_output" ]] || fail "$package is not installed on device $serial"

  package_dir="$out_dir/$package"
  mkdir -m 700 -- "$package_dir"
  mapfile -t remote_paths <<< "$paths_output"
  for entry in "${remote_paths[@]}"; do
    [[ "$entry" == package:* ]] || fail "unexpected pm path response for $package"
    remote_path="${entry#package:}"
    [[ "$remote_path" == /* && ! "$remote_path" =~ (^|/)\.\.?(/|$) ]] \
      || fail "unsafe APK path reported for $package"
    filename="${remote_path##*/}"
    [[ "$filename" =~ ^[A-Za-z0-9._-]+\.apk$ ]] \
      || fail "unexpected APK filename for $package"
    adb "${adb_args[@]}" pull "$remote_path" "$package_dir/$filename" >/dev/null \
      || fail "could not pull $package/$filename"
    chmod 600 -- "$package_dir/$filename"
    if command -v apksigner >/dev/null 2>&1; then
      apksigner verify --verbose --print-certs "$package_dir/$filename" \
        >> "$manifest" 2>&1 \
        || fail "APK signature verification failed for $package/$filename"
    fi
  done
  (
    cd -- "$package_dir"
    sha256sum -- *.apk > SHA256SUMS
    chmod 600 -- SHA256SUMS
  )
  printf 'package=%s splits=%s\n' "$package" "${#remote_paths[@]}" >> "$manifest"
done

printf 'Android APK capture saved to %s (%s signature verification)\n' \
  "$out_dir" "$capture_state"
