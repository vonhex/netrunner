"""Daemons — systemd service management, the netrunner's daemon roster."""

from __future__ import annotations

from . import palette
from .netinfo import _run


def services(all_units: bool = True) -> list[dict]:
    """Parse `systemctl list-units --type=service` output."""
    args = ["systemctl", "list-units", "--type=service", "--plain", "--no-legend"]
    if all_units:
        args.append("--all")
    out = _run(args, timeout=15)
    rows = []
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 4:
            rows.append({
                "unit": parts[0],
                "load": parts[1],
                "active": parts[2],
                "sub": parts[3],
                "description": parts[4] if len(parts) > 4 else "",
            })
    return rows


def failed_units() -> list[dict]:
    out = _run(["systemctl", "list-units", "--failed", "--plain", "--no-legend"], timeout=15)
    rows = []
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 4:
            rows.append({
                "unit": parts[0], "load": parts[1], "active": parts[2],
                "sub": parts[3], "description": parts[4] if len(parts) > 4 else "",
            })
    return rows


def user_services() -> list[dict]:
    out = _run(["systemctl", "--user", "list-units", "--plain", "--no-legend"], timeout=15)
    rows = []
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 4:
            rows.append({
                "unit": parts[0], "load": parts[1], "active": parts[2],
                "sub": parts[3], "description": parts[4] if len(parts) > 4 else "",
            })
    return rows


def summary() -> dict:
    svcs = services()
    return {
        "total": len(svcs),
        "active": sum(1 for s in svcs if s["active"] == "active"),
        "inactive": sum(1 for s in svcs if s["active"] != "active"),
        "failed": len(failed_units()),
    }


def build(show_all: bool = False):
    """Return the daemon roster as a renderable."""
    from rich.console import Group
    from rich.panel import Panel
    from rich.table import Table

    s = summary()
    panels = [Panel(
        f"[{palette.DIM}]DAEMONS[/] [{palette.WHITE}]{s['total']}[/]  "
        f"[{palette.GREEN}]ACTIVE[/] [{palette.WHITE}]{s['active']}[/]  "
        f"[{palette.DIM}]INACTIVE[/] [{palette.WHITE}]{s['inactive']}[/]  "
        f"[{palette.RED}]FAILED[/] [{palette.WHITE}]{s['failed']}[/]",
        title="[bright_cyan]DAEMON ROSTER[/]", border_style=palette.CYAN)]

    rows = services() if show_all else [x for x in services() if x["active"] == "active"]
    t = Table(box=None, pad_edge=False, expand=True)
    t.add_column("UNIT", style=palette.CYAN)
    t.add_column("ACTIVE")
    t.add_column("SUB", style=palette.DIM)
    t.add_column("DESCRIPTION", style=palette.WHITE, overflow="ellipsis")
    for r in rows[:60]:
        act = f"[green]{r['active']}[/]" if r["active"] == "active" else f"[yellow]{r['active']}[/]"
        t.add_row(r["unit"], act, r["sub"], r["description"])
    panels.append(Panel(t, title="[bright_cyan]RUNNING DAEMONS[/]", border_style=palette.CYAN))

    failed = failed_units()
    if failed:
        ft = Table(box=None, pad_edge=False, expand=True)
        ft.add_column("UNIT", style=palette.RED)
        ft.add_column("SUB", style=palette.DIM)
        ft.add_column("DESCRIPTION", style=palette.WHITE, overflow="ellipsis")
        for r in failed:
            ft.add_row(r["unit"], r["sub"], r["description"])
        panels.append(Panel(ft, title="[red]FAILED DAEMONS[/]", border_style=palette.RED))
    return Group(*panels)


def render(console, show_all: bool = False) -> None:
    console.print(build(show_all))
