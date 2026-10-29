"""Operator profile — ~/.netrunner/config.toml"""

from __future__ import annotations

import json
import os
import socket
import tomllib
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("NETRUNNER_HOME", os.path.expanduser("~/.netrunner")))
CONFIG_FILE = CONFIG_DIR / "config.toml"
SHARD_DIR = CONFIG_DIR / "shards"

DEFAULTS = {
    "operator": "",            # defaults to $USER
    "corp": "ARASAKA SECURITY",
    "deck": "",                # defaults to hostname
    "accent": "cyan",
    # EDGERUNNER — local Halogen/OpenAI-compatible assistant endpoint.
    "edgerunner_name": "EDGERUNNER",   # what the operator calls their fixer
    "edgerunner_url": "http://10.0.1.103:8731",
    "edgerunner_model": "",    # blank = auto-detect from /v1/models
}


def load() -> dict:
    cfg = dict(DEFAULTS)
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "rb") as f:
                cfg.update(tomllib.load(f).get("netrunner", {}))
        except (tomllib.TOMLDecodeError, OSError):
            pass  # a damaged profile must never brick the deck: fall back to defaults
    if not cfg["operator"]:
        cfg["operator"] = (os.environ.get("USER") or "V").capitalize()
    if not cfg["deck"]:
        cfg["deck"] = socket.gethostname().upper()
    return cfg


def save(cfg: dict) -> Path:
    ensure_dirs()
    # json.dumps escapes quotes and backslashes; JSON strings are valid TOML basic strings
    body = "\n".join(f"{k} = {json.dumps(str(v), ensure_ascii=False)}" for k, v in cfg.items())
    CONFIG_FILE.write_text(f"[netrunner]\n{body}\n")
    return CONFIG_FILE


def ensure_dirs() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    SHARD_DIR.mkdir(parents=True, exist_ok=True)
