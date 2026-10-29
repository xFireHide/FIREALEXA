#!/usr/bin/env bash
# Run a pre-staged REA Android toolchain without exposing host credentials.
set -euo pipefail

fail() { printf 'REA isolation: %s\n' "$*" >&2; exit 1; }

if (( $# < 2 )); then
  printf 'Usage: REA_ANALYSIS_IMAGE=sha256:<image-id> bash tools/rea-isolated.sh <android-command> <apk> [selectors...]\n' >&2
  exit 2
fi
case "$1" in
  inspect-android-package|search-android-classes|inspect-android-class|inspect-android-method|trace-android-references) ;;
  *) fail 'only static Android analysis commands are accepted' ;;
esac
[[ "${REA_ANALYSIS_IMAGE:-}" =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'set REA_ANALYSIS_IMAGE to a locally staged, reviewed image ID'
command -v docker >/dev/null 2>&1 || fail 'Docker with a running Linux VM is required on macOS'
[[ -f "$2" ]] || fail 'APK file does not exist'
apk_dir="$(cd -- "$(dirname -- "$2")" && pwd -P)"
apk_path="$apk_dir/$(basename -- "$2")"
[[ "$apk_path" != *,* ]] || fail 'Docker bind-mount paths cannot contain commas'
analysis_command="$1"
shift 2
docker image inspect "$REA_ANALYSIS_IMAGE" >/dev/null || fail 'the selected image is not staged locally'

# Image contract: /opt/rea/rea is the offline CLI entry point; the pinned
# headless JADX JAR is /opt/rea/jadx-headless-mcp-0.7.1-all.jar; Java is on PATH.
# No package fetching, target execution, host sockets or host output mounts.
exec docker run --rm --pull=never --network=none --read-only \
  --user 65534:65534 --cap-drop=ALL --security-opt=no-new-privileges \
  --pids-limit=128 --memory=3g --memory-swap=3g --cpus=2 \
  --tmpfs /tmp:rw,nosuid,nodev,size=1g,mode=1777 \
  --mount "type=bind,source=$apk_path,target=/input/target.apk,readonly" \
  --env HOME=/tmp --env TMPDIR=/tmp \
  --env REA_JADX_MCP_JAR=/opt/rea/jadx-headless-mcp-0.7.1-all.jar \
  --entrypoint /opt/rea/rea "$REA_ANALYSIS_IMAGE" \
  "$analysis_command" /input/target.apk "$@"
