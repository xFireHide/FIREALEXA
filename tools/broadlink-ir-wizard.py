#!/usr/bin/env python3
"""Interactive wizard to learn Broadlink IR remotes into config.json.

With the bridge running, it lists your Broadlink IR blasters, asks which
appliance you want to add (for example "TV da Sala"), captures the ON and OFF
buttons from your physical remote, optionally test-sends them, and saves the
pair under ``broadlink_ir_mappings``. After a restart, each appliance appears
as an On/Off device in Matter (Apple Home, Google Home, Alexa).

    python3 tools/broadlink-ir-wizard.py --config matter-bridge.json

``--config`` is the bridge registry file (the same value as the bridge's
--config); config.json beside it is updated in place.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from matter_bridge.adapters.broadlink_ir_config import add_mapping
from matter_bridge.core.storage import write_private_json

# Learning mode on the device lasts a few seconds, so give the user retries.
LEARN_ATTEMPTS = 5
LEARN_TIMEOUT = 30.0


class BridgeClient:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")

    def _request(self, method: str, path: str, body: Any = None,
                 timeout: float = 10.0) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            f"{self.base_url}{path}", data=data, method=method,
            headers={"Content-Type": "application/json"} if data else {},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
        return json.loads(raw) if raw else None

    def ir_remotes(self) -> list[dict[str, Any]]:
        devices = self._request("GET", "/api/devices")
        return [
            device for device in devices if isinstance(device, dict)
            and device.get("brand") == "broadlink" and device.get("type") == "IR_REMOTE"
        ]

    def learn(self, remote_id: str) -> str | None:
        """Return the learned code as hex, or None if nothing was captured."""
        try:
            result = self._request(
                "POST", f"/api/devices/broadlink/{quote(remote_id, safe='')}/learn-ir",
                timeout=LEARN_TIMEOUT,
            )
        except urllib.error.HTTPError as exc:
            if exc.code == 502:  # Learning window expired without a code.
                return None
            raise
        code = result.get("ir_data") if isinstance(result, dict) else None
        return code if isinstance(code, str) and code else None

    def send(self, remote_id: str, code_hex: str) -> None:
        self._request(
            "PUT", f"/api/devices/broadlink/{quote(remote_id, safe='')}/state",
            {"ir_data": code_hex},
        )


def ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except EOFError:
        raise SystemExit(1) from None


def yes(prompt: str, default: bool = True) -> bool:
    hint = "S/n" if default else "s/N"
    answer = ask(f"{prompt} [{hint}] ").lower()
    return default if not answer else answer in {"s", "sim", "y", "yes"}


def choose_remote(remotes: list[dict[str, Any]]) -> dict[str, Any]:
    if len(remotes) == 1:
        remote = remotes[0]
        print(f"Usando o Broadlink: {remote.get('name')} ({remote.get('device_id')})")
        return remote
    print("Broadlinks encontrados:")
    for index, remote in enumerate(remotes, 1):
        status = "online" if remote.get("online") else "offline"
        print(f"  {index}. {remote.get('name')} ({remote.get('device_id')}, {status})")
    while True:
        answer = ask("Qual deles fica perto do aparelho? (número) ")
        if answer.isdigit() and 1 <= int(answer) <= len(remotes):
            return remotes[int(answer) - 1]


def learn_button(client: BridgeClient, remote_id: str, label: str) -> str:
    for attempt in range(1, LEARN_ATTEMPTS + 1):
        ask(f"\nAponte o controle para o Broadlink e, depois de apertar Enter, "
            f"aperte o botão {label} (você tem alguns segundos)...")
        code = client.learn(remote_id)
        if code:
            print(f"  Código do botão {label} capturado.")
            return code
        print(f"  Nenhum código recebido (tentativa {attempt}/{LEARN_ATTEMPTS}).")
    raise RuntimeError(f"Não foi possível capturar o botão {label}")


def learn_appliance(client: BridgeClient, remote_id: str) -> tuple[str, str, str]:
    name = ""
    while not name:
        name = ask("\nNome do aparelho (ex.: TV da Sala, Ar do Quarto): ")
    if yes("O mesmo botão liga e desliga (ex.: botão POWER da TV)?", default=True):
        code = learn_button(client, remote_id, "POWER")
        on_code = off_code = code
    else:
        on_code = learn_button(client, remote_id, "LIGAR")
        off_code = learn_button(client, remote_id, "DESLIGAR")
    if yes("Quer testar enviando o comando de ligar agora?", default=True):
        client.send(remote_id, on_code)
        if not yes("O aparelho respondeu?", default=True):
            raise RuntimeError("O teste falhou; tente aprender os botões de novo")
    return name, on_code, off_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Learn Broadlink IR remotes into config.json")
    parser.add_argument("--config", type=Path, default=Path("matter-bridge.json"),
                        help="Bridge registry file; config.json beside it is updated")
    parser.add_argument("--api", default="http://127.0.0.1:8765",
                        help="Bridge local API URL (default http://127.0.0.1:8765)")
    args = parser.parse_args(argv)

    client = BridgeClient(args.api)
    try:
        remotes = client.ir_remotes()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"Não consegui falar com o bridge em {args.api}: {exc}\n"
              "Inicie o bridge primeiro e tente de novo.", file=sys.stderr)
        return 1
    if not remotes:
        print("Nenhum Broadlink com IR foi encontrado. Confira se ele está ligado na "
              "mesma rede e se o bridge já o descobriu.", file=sys.stderr)
        return 1

    remote = choose_remote(remotes)
    remote_id = str(remote["device_id"])
    config_file = args.config.with_name("config.json")
    added: list[str] = []
    while True:
        try:
            name, on_code, off_code = learn_appliance(client, remote_id)
        except (RuntimeError, urllib.error.URLError, OSError) as exc:
            print(f"  {exc}", file=sys.stderr)
        else:
            try:
                existing = json.loads(config_file.read_text()) if config_file.exists() else {}
                if not isinstance(existing, dict):
                    raise ValueError("config.json must contain a JSON object")
                merged, mapping_id = add_mapping(existing, remote_id, name, on_code, off_code)
            except (OSError, ValueError) as exc:
                print(f"Não consegui atualizar {config_file}: {exc}", file=sys.stderr)
                return 1
            write_private_json(config_file, merged)
            added.append(f"{name} ({mapping_id})")
            print(f"  '{name}' salvo em {config_file}.")
        if not yes("\nAdicionar outro aparelho?", default=False):
            break

    if added:
        print("\nAparelhos adicionados:\n  - " + "\n  - ".join(added))
        print("Reinicie o bridge para eles aparecerem no Apple Home / Google Home / Alexa.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
