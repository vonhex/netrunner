"""Data shards — journalctl log mining + a personal shard vault.

In Cyberpunk, netrunner's collect data shards from the net. Here, every
journal entry becomes a shard, and the operator can store their own notes
in ~/.netrunner/shards/.
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone

from . import palette
from .config import SHARD_DIR, ensure_dirs
from .netinfo import _run

PRIORITY_MAP = {
    "0": ("EMERG", palette.RED),
    "1": ("ALERT", palette.RED),
    "2": ("CRIT", palette.RED),
    "3": ("ERROR", palette.RED),
    "4": ("WARNING", palette.YELLOW),
    "5": ("NOTICE", palette.CYAN),
    "6": ("INFO", palette.CYAN),
    "7": ("DEBUG", palette.DIM),
}


def journal_shards(n: int = 25) -> list[dict]:
    """Pull the last n journal entries as shards (system, then user journal)."""
    raw = ""
    for args in (
        ["journalctl", "--no-pager", "-o", "json", "-n", str(n)],
        ["journalctl", "--user", "--no-pager", "-o", "json", "-n", str(n)],
    ):
        raw = _run(args, timeout=15)
        if raw:
            break
    shards = []
    for line in raw.splitlines():
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        prio = str(e.get("PRIORITY", "6"))
        sev, style = PRIORITY_MAP.get(prio, ("INFO", palette.CYAN))
        ts = e.get("__REALTIME_TIMESTAMP")
        when = "?"
        if ts:
            when = datetime.fromtimestamp(int(ts) / 1e6, tz=timezone.utc).strftime("%m-%d %H:%M:%S")
        msg = e.get("MESSAGE", "")
        if isinstance(msg, list):
            # journalctl encodes some messages as a byte array, others as line lists
            if msg and all(isinstance(x, int) for x in msg):
                msg = bytes(msg).decode("utf-8", errors="replace")
            else:
                msg = "\n".join(str(x) for x in msg)
        shards.append({
            "time": when,
            "source": e.get("SYSLOG_IDENTIFIER") or e.get("_COMM") or "?",
            "severity": sev,
            "style": style,
            "message": " ".join(str(msg).split())[:200],
        })
    return shards


# ---------------------------------------------------------------- the vault

def write_shard(title: str, body: str) -> str:
    """Store a custom shard; returns the file path."""
    ensure_dirs()
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:48] or "shard"
    path = SHARD_DIR / f"{int(time.time())}-{slug}.md"
    path.write_text(f"# {title}\n\n_{datetime.now().astimezone():%Y-%m-%d %H:%M}_\n\n{body}\n")
    return str(path)


def list_shards() -> list[dict]:
    ensure_dirs()
    out = []
    for p in sorted(SHARD_DIR.glob("*.md"), reverse=True):
        text = p.read_text().splitlines()
        title = text[0].lstrip("# ").strip() if text else p.name
        out.append({"path": str(p), "title": title})
    return out


def build(n: int = 25):
    """Return the shard feed + vault as a renderable."""
    from rich.console import Group
    from rich.panel import Panel
    from rich.text import Text

    t = Text()
    for s in journal_shards(n):
        line = Text()
        line.append(f"{s['time']} ", style=palette.DIM)
        line.append(f"[{s['severity']}] ", style=s["style"])
        line.append(f"{s['source']}: ", style=palette.MAGENTA)
        line.append(f"{s['message']}\n")
        t.append_text(line)
    panels = [Panel(t or Text("[grey37]no shards recovered[/]"),
                    title="[magenta]DATA SHARDS — NET FEED[/]", border_style=palette.MAGENTA)]

    vault = list_shards()
    if vault:
        vt = Text()
        for v in vault[:10]:
            line = Text()
            line.append("◆ ", style=palette.CYAN)
            line.append(f"{v['title']}\n")
            vt.append_text(line)
        panels.append(Panel(vt, title="[bright_cyan]SHARD VAULT[/]", border_style=palette.CYAN))
    return Group(*panels)


def render(console, n: int = 25) -> None:
    console.print(build(n))
