#!/bin/bash
set -euo pipefail
umask 077

root_dir="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
app_dir="$HOME/Library/Application Support/FIREALEXA"
venv_dir="$root_dir/.venv-macos"
registry="$app_dir/matter-bridge.json"
label="com.firealexa.bridge"
plist="$HOME/Library/LaunchAgents/$label.plist"
log_file="$app_dir/bridge.log"

usage() {
  cat >&2 <<'EOF'
Uso: bash tools/run-macos.sh [comando]

  (sem comando)        inicia o bridge neste terminal
  --setup              prepara Python e Node (rode uma vez)
  --install-service    inicia o bridge sozinho ao entrar no Mac e reinicia se cair
  --uninstall-service  remove o serviço
  --status             mostra se o serviço está rodando e o fim do log
  pairing              mostra o código de pareamento Matter
  ir-wizard            assistente para aprender controles IR do Broadlink
  ewelink-import       importa os dispositivos da conta eWeLink (OAuth oficial)
EOF
}

[[ "$(uname -s)" == Darwin ]] || {
  echo 'Execute este script no Mac.' >&2
  exit 1
}

require_setup() {
  [[ -x "$venv_dir/bin/matter-bridge" ]] || {
    echo 'Primeiro execute: bash tools/run-macos.sh --setup' >&2
    exit 1
  }
}

run_tool() {
  require_setup
  local tool="$1"
  shift
  export PYTHONPATH="$root_dir"
  exec "$venv_dir/bin/python" "$root_dir/tools/$tool" "$@"
}

case "${1:-}" in
  --setup)
    [[ $# == 1 ]] || { usage; exit 2; }
    command -v python3 >/dev/null || { echo 'Instale Python 3.11 ou superior.' >&2; exit 1; }
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else "Python 3.11+ necessário")'
    command -v node >/dev/null || { echo 'Instale Node.js 22.13 ou superior.' >&2; exit 1; }
    command -v npm >/dev/null || { echo 'npm não encontrado.' >&2; exit 1; }
    python3 -m venv "$venv_dir"
    "$venv_dir/bin/python" -m pip install "$root_dir"
    npm install --ignore-scripts --prefix "$root_dir/matter_bridge/matter_node"
    echo 'Preparação concluída. Inicie com: bash tools/run-macos.sh'
    exit 0
    ;;
  --install-service)
    [[ $# == 1 ]] || { usage; exit 2; }
    require_setup
    mkdir -p "$app_dir" "$HOME/Library/LaunchAgents"
    chmod 700 "$app_dir"
    node_dir="$(dirname -- "$(command -v node)")"
    "$venv_dir/bin/python" - "$plist" "$label" "$root_dir/tools/run-macos.sh" \
      "$log_file" "$node_dir" <<'PY'
import plistlib, sys
path, label, script, log, node_dir = sys.argv[1:]
with open(path, "wb") as f:
    plistlib.dump({
        "Label": label,
        "ProgramArguments": ["/bin/bash", script],
        "RunAtLoad": True,
        "KeepAlive": True,
        "ThrottleInterval": 10,
        "StandardOutPath": log,
        "StandardErrorPath": log,
        # launchd starts with a minimal PATH; keep the node used during setup.
        "EnvironmentVariables": {"PATH": f"{node_dir}:/usr/bin:/bin:/usr/sbin:/sbin"},
    }, f)
PY
    chmod 600 "$plist"
    launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
    launchctl bootstrap "gui/$(id -u)" "$plist"
    echo "Serviço instalado e iniciado. Log: $log_file"
    echo 'Ver código de pareamento: bash tools/run-macos.sh pairing'
    exit 0
    ;;
  --uninstall-service)
    [[ $# == 1 ]] || { usage; exit 2; }
    launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
    rm -f "$plist"
    echo 'Serviço removido.'
    exit 0
    ;;
  --status)
    [[ $# == 1 ]] || { usage; exit 2; }
    if launchctl print "gui/$(id -u)/$label" >/dev/null 2>&1; then
      echo 'Serviço: instalado'
      launchctl print "gui/$(id -u)/$label" | grep -E '^\s*(state|pid|last exit code) =' || true
    else
      echo 'Serviço: não instalado'
    fi
    [[ -f "$log_file" ]] && { echo '--- fim do log ---'; tail -n 20 "$log_file"; }
    exit 0
    ;;
  pairing)
    shift
    run_tool matter-pairing.py "$@"
    ;;
  ir-wizard)
    shift
    run_tool broadlink-ir-wizard.py --config "$registry" "$@"
    ;;
  ewelink-import)
    shift
    run_tool ewelink-import.py --config "$registry" "$@"
    ;;
  "")
    require_setup
    mkdir -p "$app_dir"
    chmod 700 "$app_dir"
    # Use the project runtime whose dependencies were prepared above.
    export PYTHONPATH="$root_dir"
    exec "$venv_dir/bin/python" -m matter_bridge.core.main --config "$registry"
    ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage
    exit 2
    ;;
esac
