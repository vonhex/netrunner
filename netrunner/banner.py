"""ASCII banner + boot sequence."""

from __future__ import annotations

import shutil
import time

from rich.panel import Panel
from rich.text import Text

from . import __version__, palette, netinfo
from .config import load

BANNER = r"""
███╗   ██╗███████╗████████╗██████╗ ██╗   ██╗███╗   ██╗███╗   ██╗███████╗██████╗
████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║   ██║████╗  ██║████╗  ██║██╔════╝██╔══██╗
██╔██╗ ██║█████╗     ██║   ██████╔╝██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██║╚██╗██║██╔══╝     ██║   ██╔══██╗██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║ ╚████║███████╗   ██║   ██║  ██║╚██████╔╝██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
"""

# Narrow-terminal fallback (44 cols) so the banner never wraps on an 80-col deck.
COMPACT_BANNER = r"""
 _  _ ___ _____ ___ _   _ _  _ _  _ ___ ___
| \| | __|_   _| _ \ | | | \| | \| | __| _ \
| .` | _|  | | |   / |_| | .` | .` | _||   /
|_|\_|___| |_| |_|_\\___/|_|\_|_|\_|___|_|_\
"""

# Width each banner needs including the panel border + padding.
_FULL_COLS = 84


def render_banner(width: int | None = None) -> Panel:
    cfg = load()
    if width is None:
        width = shutil.get_terminal_size(fallback=(100, 24)).columns
    art = BANNER if width >= _FULL_COLS else COMPACT_BANNER
    text = Text()
    for line in art.strip("\n").split("\n"):
        text.append(line, style=palette.CYAN)
        text.append("\n")
    text.append("//OS", style=f"{palette.MAGENTA} bold")
    text.append(f"  v{__version__}", style=palette.DIM)
    text.append("\n")
    sub = Text.assemble(
        ("OPERATOR: ", palette.DIM),
        (cfg["operator"], palette.WHITE),
        ("  \u2502  CORP: ", palette.DIM),
        (cfg["corp"], palette.WHITE),
        ("  \u2502  DECK: ", palette.DIM),
        (cfg["deck"], palette.WHITE),
    )
    text.append(sub)
    return Panel(
        text,
        border_style=palette.CYAN,
        padding=(0, 1),
        expand=False,
    )


def boot_lines() -> list[str]:
    """Build a boot sequence from live system data."""
    cfg = load()
    lines = [
        f"[{palette.DIM}][ 0.000000][/] NETRUNNER//OS v{__version__} \u2014 cold boot",
        f"[{palette.DIM}][ 0.002914][/] deck [{palette.WHITE}]{cfg['deck']}[/] ... [green]ONLINE[/]",
    ]
    t = 0.009
    for iface in netinfo.interfaces():
        if iface["name"] == "lo":
            continue
        state = "green" if iface["state"] == "UP" else "yellow"
        lines.append(
            f"[{palette.DIM}][ {t:.6f}][/] netdaemon: {iface['name']} [{state}]{iface['state']}[/]"
        )
        t += 0.008
    gw = netinfo.default_route()
    if gw.get("gateway"):
        lines.append(
            f"[{palette.DIM}][ {t:.6f}][/] grid: gateway {gw['gateway']} via {gw.get('dev','?')} \u2014 [green]HANDSHAKE OK[/]"
        )
        t += 0.008
    lines += [
        f"[{palette.DIM}][ {t:.6f}][/] cyberdeck: KIROSHI OPTICS Mk.IV \u2014 [green]SYNC OK[/]",
        f"[{palette.DIM}][ {t + 0.007:.6f}][/] ICE monitor: standby",
        f"[{palette.DIM}][ {t + 0.014:.6f}][/] breach protocol: [magenta]LOADED[/]",
    ]
    lines.append(
        f"[{palette.DIM}][ {t + 0.021:.6f}][/] "
        f"welcome, [{palette.WHITE}]{cfg['operator']}[/]. jacking in..."
    )
    return lines


def boot(console, fast: bool = False, delay: float = 0.09) -> None:
    """Typewriter boot sequence animation."""
    import sys

    for line in boot_lines():
        console.print(line)
        if not fast and sys.stdout.isatty():
            time.sleep(delay)
