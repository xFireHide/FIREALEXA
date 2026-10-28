#!/usr/bin/env bash
set -euo pipefail

readonly JAR_SHA256="6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75"
readonly REA_PACKAGE="rea-agents@4.1.0"

fail() {
  printf 'REA preflight: %s\n' "$1" >&2
  exit 1
}

version_at_least() {
  local major="$1" minor="$2" patch="$3"
  local required_major="$4" required_minor="$5" required_patch="$6"

  (( major > required_major )) && return 0
  (( major < required_major )) && return 1
  (( minor > required_minor )) && return 0
  (( minor < required_minor )) && return 1
  (( patch >= required_patch ))
}

preflight_only=false
if [[ "${1:-}" == "--preflight" ]]; then
  preflight_only=true
  shift
  (( $# == 0 )) || fail "--preflight does not accept additional arguments"
elif (( $# < 2 )); then
  cat >&2 <<'EOF'
Usage: tools/rea-android.sh [--preflight] <REA Android command> <apk-path> [REA arguments...]

Example:
  tools/rea-android.sh inspect-android-package /absolute/path/app.apk
  tools/rea-android.sh search-android-classes /absolute/path/app.apk zeroconf
  tools/rea-android.sh --preflight

Set REA_JADX_MCP_JAR to the verified jadx-headless-mcp 0.7.1 JAR path.
EOF
  exit 2
fi

if [[ "$preflight_only" == false ]]; then
  [[ -f "$2" ]] || fail "APK path does not exist or is not a file: $2"
fi
[[ -n "${REA_JADX_MCP_JAR:-}" && -f "$REA_JADX_MCP_JAR" ]] \
  || fail "set REA_JADX_MCP_JAR to the pinned jadx-headless-mcp 0.7.1 JAR"

command -v node >/dev/null 2>&1 || fail "Node.js is not installed"
node_version="$(node -p 'process.versions.node')"
if [[ ! "$node_version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)([-+].*)?$ ]]; then
  fail "cannot parse Node.js version: $node_version"
fi
node_major="${BASH_REMATCH[1]}"
node_minor="${BASH_REMATCH[2]}"
node_patch="${BASH_REMATCH[3]}"
[[ "$node_version" != *-* ]] || fail "REA does not support prerelease Node.js builds: $node_version"
case "$node_major" in
  22) version_at_least "$node_major" "$node_minor" "$node_patch" 22 23 4 \
      || fail "REA needs Node.js 22.23.4+; found $node_version" ;;
  24) version_at_least "$node_major" "$node_minor" "$node_patch" 24 22 1 \
      || fail "REA needs Node.js 24.22.1+; found $node_version" ;;
  *) version_at_least "$node_major" "$node_minor" "$node_patch" 26 12 1 \
      || fail "REA supports Node.js 22.23.4+, 24.22.1+, or 26.12.1+; found $node_version" ;;
esac

command -v java >/dev/null 2>&1 || fail "JDK 17+ is required (java not found)"
command -v javac >/dev/null 2>&1 || fail "a full JDK 17+ is required (javac not found)"
java_version="$(java -version 2>&1 | sed -n '1s/.*version "\([0-9][0-9]*\).*/\1/p')"
[[ "$java_version" =~ ^[0-9]+$ ]] || fail "cannot determine Java version"
(( java_version >= 17 )) || fail "REA needs a full JDK 17+; found Java $java_version"
command -v ps >/dev/null 2>&1 || fail "procps-compatible ps is required"
ps --version >/dev/null 2>&1 || fail "ps is not procps-compatible"
compiler_version="$(javac -version 2>&1)"
if [[ ! "$compiler_version" =~ ^javac[[:space:]]([0-9]+)(\.|$) ]]; then
  fail "cannot determine javac version: $compiler_version"
fi
compiler_major="${BASH_REMATCH[1]}"
(( compiler_major >= 17 )) || fail "REA needs javac 17+; found $compiler_version"
(( compiler_major == java_version )) \
  || fail "java and javac versions differ (java $java_version, $compiler_version)"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required to verify the JADX JAR"
printf '%s  %s\n' "$JAR_SHA256" "$REA_JADX_MCP_JAR" | sha256sum --check --status \
  || fail "JADX JAR SHA-256 mismatch: $REA_JADX_MCP_JAR"
command -v npx >/dev/null 2>&1 || fail "npm/npx is required to launch REA"
if [[ "$preflight_only" == true ]]; then
  printf 'REA preflight: all prerequisites are available\n'
  exit 0
fi

exec npx --offline --yes "$REA_PACKAGE" "$@"
