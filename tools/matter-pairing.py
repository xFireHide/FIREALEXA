#!/usr/bin/env python3
"""Show the Matter pairing code of the running bridge.

    python3 tools/matter-pairing.py

Open Apple Home, Google Home or the Alexa app, choose "Add device" -> "Matter",
and scan the QR code (open the printed link on another screen) or type the
11-digit manual code. The codes only work while the bridge is not yet paired;
to add a second ecosystem later, use "pairing mode" / "share" in the first one.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from urllib.parse import quote


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Show the bridge's Matter pairing code")
    parser.add_argument("--api", default="http://127.0.0.1:8765",
                        help="Bridge local API URL (default http://127.0.0.1:8765)")
    args = parser.parse_args(argv)
    try:
        with urllib.request.urlopen(f"{args.api.rstrip('/')}/api/matter/pairing",
                                    timeout=5) as response:
            info = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            print("Matter está desativado no config.json (matter.enabled).", file=sys.stderr)
            return 1
        print(f"O bridge respondeu HTTP {exc.code}.", file=sys.stderr)
        return 1
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"Não consegui falar com o bridge em {args.api}: {exc}\n"
              "Inicie o bridge primeiro.", file=sys.stderr)
        return 1

    status = info.get("status")
    if info.get("commissioned") is True:
        print("O bridge já está pareado. Para adicionar outro app (ex.: Google além da "
              "Apple), ative o modo de pareamento/compartilhamento no app onde ele já está.")
        return 0
    code, qr = info.get("manual_pairing_code"), info.get("qr_payload")
    if not code:
        print(f"Matter ainda não está pronto (status: {status}). Espere alguns segundos "
              "e rode de novo; se continuar, veja o log do bridge.", file=sys.stderr)
        return 1
    print(f"Código manual de pareamento: {code[:4]}-{code[4:7]}-{code[7:]}")
    if qr:
        print("QR code (abra num computador e escaneie com o celular):\n  "
              "https://project-chip.github.io/connectedhomeip/qrcode.html?data="
              + quote(qr, safe=":"))
    print("\nNo app: Adicionar dispositivo -> Matter -> escaneie o QR ou digite o código.\n"
          "O celular precisa estar no mesmo Wi-Fi que este computador.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
