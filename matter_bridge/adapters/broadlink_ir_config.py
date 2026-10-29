"""Helpers for adding learned Broadlink IR code pairs to ``config.json``.

The format matches what ``BroadlinkAdapter`` loads from
``broadlink_ir_mappings``: remote device ID → list of
``{"id", "name", "on", "off"}`` entries with hex IR payloads.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

MAX_CODE_HEX = 8192
MAX_NAME_LENGTH = 128


def slugify(name: str) -> str:
    """Turn an appliance name into a mapping ID (ASCII letters, digits, '-')."""
    ascii_name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    slug = re.sub(r"[^A-Za-z0-9]+", "-", ascii_name).strip("-").lower()
    return slug[:64] or "aparelho"


def unique_id(base: str, taken: set[str]) -> str:
    """Return ``base`` or ``base-2``, ``base-3``... so it does not clash."""
    candidate, suffix = base, 2
    while candidate in taken:
        candidate = f"{base[:60]}-{suffix}"
        suffix += 1
    return candidate


def validate_code(code_hex: str) -> str:
    """Return the IR code as lowercase hex, or raise ValueError."""
    if not isinstance(code_hex, str) or not code_hex or len(code_hex) > MAX_CODE_HEX:
        raise ValueError("IR code must be non-empty hex of at most 8192 characters")
    try:
        code = bytes.fromhex(code_hex)
    except ValueError as exc:
        raise ValueError("IR code must be valid hex") from exc
    if not code:
        raise ValueError("IR code cannot be empty")
    return code.hex()


def add_mapping(
    config: dict[str, Any], remote_id: str, name: str, on_hex: str, off_hex: str,
) -> tuple[dict[str, Any], str]:
    """Return a copy of ``config`` with one new IR mapping, plus its ID.

    Existing mappings and other config fields are preserved.
    """
    clean = "".join(ch for ch in name if ch.isprintable()).strip()[:MAX_NAME_LENGTH]
    if not clean:
        raise ValueError("Appliance name cannot be empty")
    if not remote_id:
        raise ValueError("Remote device ID cannot be empty")
    on_code, off_code = validate_code(on_hex), validate_code(off_hex)
    merged = dict(config)
    existing = merged.get("broadlink_ir_mappings")
    mappings: dict[str, Any] = dict(existing) if isinstance(existing, dict) else {}
    entries = list(mappings.get(remote_id) or [])
    taken = {entry.get("id") for entry in entries if isinstance(entry, dict)}
    mapping_id = unique_id(slugify(clean), {item for item in taken if isinstance(item, str)})
    entries.append({"id": mapping_id, "name": clean, "on": on_code, "off": off_code})
    mappings[remote_id] = entries
    merged["broadlink_ir_mappings"] = mappings
    return merged, mapping_id
