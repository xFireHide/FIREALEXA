#!/usr/bin/env python3
"""One-time importer for an eWeLink account via the official OAuth 2.0 flow.

It opens the eWeLink login page in your browser, captures the authorization
code on a loopback redirect, exchanges it for a short-lived access token, lists
your devices, and writes each device's LAN control key into config.json's
``ewelink_apikeys``. The access and refresh tokens are never written to disk.

Register a free integration at https://dev.ewelink.cc, add a redirect URL of
http://127.0.0.1:8766/callback (or pass --redirect-url / --port to match), then:

    export EWELINK_APP_ID=...        # avoid putting secrets in argv / shell history
    export EWELINK_APP_SECRET=...
    python3 tools/ewelink-import.py --config matter-bridge.json

Credentials are read from those environment variables, or prompted for if unset.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from matter_bridge.adapters.ewelink_oauth import (
    build_authorize_url,
    create_nonce,
    device_list_headers,
    host_for_region,
    merge_apikeys,
    parse_device_list,
    parse_token_response,
    token_request,
)
from matter_bridge.core.storage import write_private_json

CALLBACK_TIMEOUT = 300.0
HTTP_TIMEOUT = 15.0


class _CallbackResult:
    code: str | None = None
    region: str | None = None
    state: str | None = None


def _wait_for_callback(host: str, port: int, path: str) -> _CallbackResult:
    """Serve one loopback request and return the OAuth code/region/state."""
    result = _CallbackResult()
    done = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            if parts.path != path:
                self.send_error(404)
                return
            params = parse_qs(parts.query)
            result.code = (params.get("code") or [None])[0]
            result.region = (params.get("region") or [None])[0]
            result.state = (params.get("state") or [None])[0]
            body = (
                b"<html><body><h2>eWeLink authorization received.</h2>"
                b"<p>You can close this tab and return to the terminal.</p></body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            done.set()

        def log_message(self, *_: object) -> None:
            pass  # Keep the OAuth code out of stderr logs.

    server = HTTPServer((host, port), Handler)
    try:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        if not done.wait(CALLBACK_TIMEOUT):
            raise TimeoutError("Timed out waiting for the eWeLink redirect")
    finally:
        server.shutdown()
        server.server_close()
    return result


def _post_json(url: str, body: bytes, headers: dict[str, str]) -> object:
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
        return json.loads(response.read())


def _get_json(url: str, headers: dict[str, str]) -> object:
    request = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
        return json.loads(response.read())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import an eWeLink account via OAuth 2.0")
    parser.add_argument(
        "--config", type=Path, default=Path("matter-bridge.json"),
        help="Bridge registry file (same as the bridge's --config); "
             "config.json beside it is updated in place",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Loopback redirect host")
    parser.add_argument("--port", type=int, default=8766, help="Loopback redirect port")
    parser.add_argument(
        "--redirect-url", default=None,
        help="Redirect URL registered in the dev console "
             "(default http://<host>:<port>/callback)",
    )
    parser.add_argument(
        "--no-browser", action="store_true",
        help="Print the authorization URL instead of opening a browser",
    )
    args = parser.parse_args(argv)

    app_id = os.environ.get("EWELINK_APP_ID") or input("eWeLink App ID: ").strip()
    app_secret = os.environ.get("EWELINK_APP_SECRET") or getpass.getpass("eWeLink App Secret: ")
    if not app_id or not app_secret:
        print("App ID and App Secret are required.", file=sys.stderr)
        return 2

    redirect_url = args.redirect_url or f"http://{args.host}:{args.port}/callback"
    callback_path = urlsplit(redirect_url).path or "/callback"
    state = secrets.token_urlsafe(16)
    authorize_url = build_authorize_url(
        app_id, app_secret, redirect_url, state,
        seq=int(time.time() * 1000), nonce=create_nonce(),
    )

    print(f"Open this URL and sign in to your eWeLink account:\n  {authorize_url}\n")
    if not args.no_browser:
        webbrowser.open(authorize_url)

    callback = _wait_for_callback(args.host, args.port, callback_path)
    if callback.state != state:
        print("Redirect state did not match; aborting to avoid a forged code.",
              file=sys.stderr)
        return 1
    if not callback.code or not callback.region:
        print("The redirect did not include a code and region.", file=sys.stderr)
        return 1

    host = host_for_region(callback.region)
    try:
        body, headers = token_request(
            app_id, app_secret, callback.code, redirect_url, nonce=create_nonce(),
        )
        access_token = parse_token_response(
            _post_json(f"{host}/v2/user/oauth/token", body, headers)
        )
        devices = parse_device_list(_get_json(
            f"{host}/v2/device/thing",
            device_list_headers(app_id, access_token, nonce=create_nonce()),
        ))
    except urllib.error.HTTPError as exc:
        print(f"eWeLink API call failed: HTTP {exc.code}", file=sys.stderr)
        return 1
    except (urllib.error.URLError, ValueError, TimeoutError) as exc:
        print(f"eWeLink import failed: {exc}", file=sys.stderr)
        return 1
    finally:
        access_token = ""  # Drop the token; it is never written to disk.

    if not devices:
        print("No controllable devices were returned for this account.")
        return 0

    config_file = args.config.with_name("config.json")
    try:
        existing = json.loads(config_file.read_text()) if config_file.exists() else {}
        if not isinstance(existing, dict):
            raise ValueError("config.json must contain a JSON object")
    except (OSError, ValueError) as exc:
        print(f"Could not read {config_file}: {exc}", file=sys.stderr)
        return 1

    merged, added, updated = merge_apikeys(existing, devices)
    write_private_json(config_file, merged)
    print(f"Imported {len(devices)} device(s) into {config_file} "
          f"({added} new, {updated} updated key(s)):")
    for device in sorted(devices, key=lambda item: item.name.lower()):
        suffix = f" (uiid {device.uiid})" if device.uiid is not None else ""
        print(f"  - {device.name} [{device.device_id}]{suffix}")
    print("Access and refresh tokens were not stored. Restart the bridge to pick up "
          "the new keys.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
