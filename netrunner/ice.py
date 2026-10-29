"""ICE — Intrusion Countermeasure Electronics.

Firewall state, listening sockets, and a threat assessment that rates the
deck's exposure on the Cyberpunk ICE tier scale (White → Violet).
"""

from __future__ import annotations

import shutil

import psutil

from . import palette
from .netinfo import _run, _run_priv, have_root
from .palette import ICE_TIERS

_ROOT_HINT = "status needs root — run `sudo -v` first, or add a passwordless sudoers rule"
_RULES_HINT = ("full ruleset needs root — add a sudoers rule for `ufw status` "
               "to see every rule")


def _unit_active(unit: str) -> bool:
    """`systemctl is-active <unit>` — works without root."""
    return _run(["systemctl", "is-active", unit]).strip() == "active"


def _ufw_conf_enabled() -> bool | None:
    """Read ENABLED from the world-readable /etc/ufw/ufw.conf (None if unknown)."""
    try:
        for line in open("/etc/ufw/ufw.conf"):
            line = line.strip()
            if line.startswith("ENABLED="):
                return line.split("=", 1)[1].strip().strip('"').lower() in ("yes", "true", "1")
    except OSError:
        return None
    return None


def firewall() -> tuple[str, str, str]:
    """(name, state, details) — probes firewalld, ufw, then raw nftables.

    Each backend escalates only its own query via ``sudo -n`` when needed, so
    NETRUNNER//OS never has to be launched as root. When a backend is present
    but we can't read it without privileges, the state is reported as
    ``UNKNOWN`` rather than falsely claiming the net is wide open.
    """
    if shutil.which("firewall-cmd"):
        st = _run(["firewall-cmd", "--state"]).strip()
        if st == "running":
            details = _run_priv(["firewall-cmd", "--list-all"])
            return ("firewalld", "ACTIVE", details or "firewalld running")
        if st == "not running":
            return ("firewalld", "INACTIVE", "firewalld installed but not running")
    if shutil.which("ufw"):
        st = _run_priv(["ufw", "status", "verbose"])
        if st:
            active = "Status: active" in st
            return ("ufw", "ACTIVE" if active else "INACTIVE", st)
        # No privileged read available — derive state WITHOUT root from the
        # systemd unit and the world-readable ufw.conf. Only the rule listing
        # actually needs root, so report the real ACTIVE/INACTIVE regardless.
        enabled = _ufw_conf_enabled()
        if enabled or _unit_active("ufw"):
            return ("ufw", "ACTIVE", f"ufw enabled — {_RULES_HINT}")
        if enabled is False:
            return ("ufw", "INACTIVE", "ufw installed but disabled")
        return ("ufw", "UNKNOWN", f"ufw installed — {_ROOT_HINT}")
    if shutil.which("nft"):
        ruleset = _run_priv(["nft", "list", "ruleset"])
        if ruleset and len(ruleset.splitlines()) > 3:
            return ("nftables", "ACTIVE", ruleset[:3000])
        if ruleset:
            return ("nftables", "INACTIVE", "nftables present, ruleset empty")
        if _unit_active("nftables"):
            return ("nftables", "ACTIVE", f"nftables.service active — {_ROOT_HINT}")
        if not have_root():
            return ("nftables", "UNKNOWN", f"nftables present — {_ROOT_HINT}")
    if shutil.which("iptables"):
        ruleset = _run_priv(["iptables", "-S"])
        if ruleset and not have_root() and not ruleset.strip():
            return ("iptables", "UNKNOWN", f"iptables present — {_ROOT_HINT}")
        if ruleset:
            active = any(ln.startswith(("-A", "-I")) for ln in ruleset.splitlines())
            return ("iptables", "ACTIVE" if active else "INACTIVE", ruleset[:3000])
        if not have_root():
            return ("iptables", "UNKNOWN", f"iptables present — {_ROOT_HINT}")
    return ("none", "NO ICE", "no firewall detected — the net is wide open")


def listening_sockets() -> list[dict]:
    """Every LISTEN socket: proto, local address, owning process."""
    rows = []
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        return rows
    for c in conns:
        if c.status != psutil.CONN_LISTEN:
            continue
        try:
            name = psutil.Process(c.pid).name() if c.pid else "?"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            name = "?"
        rows.append({
            "proto": {1: "tcp", 2: "udp"}.get(c.type, str(c.type)),
            "addr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "?",
            "pid": c.pid or 0,
            "process": name,
        })
    rows.sort(key=lambda r: (r["proto"], r["addr"]))
    return rows


LOOPBACK = ("127.", "::1")


def exposed(sockets: list[dict]) -> list[dict]:
    """Listening sockets reachable from the network (not bound to loopback only)."""
    return [s for s in sockets if not s["addr"].startswith(LOOPBACK)]


def score_ice(fw_state: str, n_exposed: int) -> int:
    """Defense score 0..9: higher = stronger ICE. Only things that change exposure count."""
    score = {"ACTIVE": 5, "UNKNOWN": 3}.get(fw_state, 0)   # firewall up is the big one
    if n_exposed == 0:
        score += 4      # nothing listening on the network at all
    elif n_exposed <= 3:
        score += 2
    elif n_exposed <= 8:
        score += 1      # more open doors = weaker ICE, never stronger
    return min(score, len(ICE_TIERS) - 1)


def assess(fw: tuple[str, str, str] | None = None,
           sockets: list[dict] | None = None) -> tuple[str, str, list[str]]:
    """Rate ICE strength from live findings. Returns (tier, style, findings)."""
    fw_name, fw_state, _ = fw or firewall()
    sockets = listening_sockets() if sockets is None else sockets
    open_doors = exposed(sockets)
    findings = []

    if fw_state == "ACTIVE":
        findings.append(f"[green]{fw_name} active[/] — perimeter ICE deployed")
    elif fw_state == "UNKNOWN":
        findings.append(f"[yellow]{fw_name} installed, status needs root[/] — ICE presumed present")
    elif fw_name != "none":
        findings.append(f"[yellow]{fw_name} installed but inactive[/] — ICE offline")
    else:
        findings.append("[red]no firewall detected[/] — zero ICE on this node")

    n = len(open_doors)
    if n == 0:
        findings.append("[green]no network-facing listeners[/] — nothing to breach from the net")
    else:
        style = "yellow" if n > 8 else "cyan"
        ports = ", ".join(sorted({s["addr"].rsplit(":", 1)[-1] for s in open_doors}, key=int)[:10])
        findings.append(f"[{style}]{n} network-facing listener(s)[/] — open ports {ports}")
    if len(sockets) > n:
        findings.append(f"[{palette.DIM}]{len(sockets) - n} loopback-only listener(s) — not reachable from the net[/]")

    # informational only: these don't change the rating
    try:
        procs = {(p.info.get("name") or "").lower() for p in psutil.process_iter(["name"])}
    except (psutil.AccessDenied, OSError):
        procs = set()
    if "sshd" in procs:
        findings.append("[cyan]sshd running[/] — remote access is open: keep it key-only")
    try:
        est = sum(1 for c in psutil.net_connections(kind="inet") if c.status == psutil.CONN_ESTABLISHED)
    except (psutil.AccessDenied, OSError):
        est = 0
    if est > 25:
        findings.append(f"[magenta]{est} established connections[/] — heavy net traffic")

    tier, style = ICE_TIERS[score_ice(fw_state, n)]
    return tier, style, findings


def build():
    """Return the full ICE report as a renderable."""
    from rich.console import Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    fw = firewall()  # probe once per refresh (it may shell out to sudo)
    sockets = listening_sockets()
    tier, style, findings = assess(fw, sockets)
    body = Text.from_markup(
        f"ICE CLASSIFICATION: [{style} bold]{tier.upper()}[/]\n"
        + "\n".join(f"  {f}" for f in findings)
    )
    panels = [Panel(body, title="[magenta]ICE ANALYSIS[/]", border_style=style)]

    fw_name, fw_state, details = fw
    if details:
        panels.append(Panel(
            Text(details[:2000]),  # raw tool output: never parse it as markup
            title=f"[bright_cyan]{fw_name.upper()} STATUS[/]",
            border_style=palette.CYAN))

    t = Table(box=None, pad_edge=False, expand=True)
    t.add_column("PROTO", style=palette.CYAN)
    t.add_column("LOCAL ADDRESS", style=palette.WHITE)
    t.add_column("PID", style=palette.DIM, justify="right")
    t.add_column("PROCESS", style=palette.MAGENTA)
    for s in sockets:
        t.add_row(s["proto"], s["addr"], str(s["pid"]), s["process"])
    panels.append(Panel(t, title="[bright_cyan]LISTENING SOCKETS — ICE LAYERS[/]",
                        border_style=palette.CYAN))
    return Group(*panels)


def render(console) -> None:
    console.print(build())
