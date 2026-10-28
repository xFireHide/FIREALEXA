#!/bin/bash
set -euo pipefail
umask 077

root_dir="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
app_dir="$HOME/Library/Application Support/FIREALEXA"
venv_dir="$root_dir/.venv-macos"

[[ "$(uname -s)" == Darwin ]] || {
  echo 'Execute este script no Mac.' >&2
  exit 1
}

if [[ "${1:-}" == --setup ]]; then
  [[ $# == 1 ]] || { echo 'Uso: bash tools/run-macos.sh [--setup]' >&2; exit 2; }
  command -v python3 >/dev/null || { echo 'Instale Python 3.11 ou superior.' >&2; exit 1; }
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else "Python 3.11+ necessário")'
  command -v node >/dev/null || { echo 'Instale Node.js 22.13 ou superior.' >&2; exit 1; }
  command -v npm >/dev/null || { echo 'npm não encontrado.' >&2; exit 1; }
  python3 -m venv "$venv_dir"
  "$venv_dir/bin/python" -m pip install "$root_dir"
  npm install --ignore-scripts --prefix "$root_dir/matter_bridge/matter_node"
  echo 'Preparação concluída. Inicie com: bash tools/run-macos.sh'
  exit 0
fi

[[ $# == 0 ]] || { echo 'Uso: bash tools/run-macos.sh [--setup]' >&2; exit 2; }
[[ -x "$venv_dir/bin/matter-bridge" ]] || {
  echo 'Primeiro execute: bash tools/run-macos.sh --setup' >&2
  exit 1
}
mkdir -p "$app_dir"
chmod 700 "$app_dir"
# Use the project runtime whose dependencies were prepared above.
export PYTHONPATH="$root_dir"
exec "$venv_dir/bin/python" -m matter_bridge.core.main --config "$app_dir/matter-bridge.json"
