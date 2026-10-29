"""ARMORY — quickhack execution. The damage half of NETRUNNER//OS.

Every weapon here performs a REAL action on the deck or the LAN, is gated
behind a confirmation (or --yes), and is recorded in the action log
(~/.netrunner/actions.jsonl) so nothing is ever executed silently.

Quickhack            Command                     Real effect
Downtime             kill <pid|name>             send a signal to a process
Short Circuit        cut <host>                  kill TCP sockets via ss -K
Wake on LAN          wake <mac>                  UDP magic packet
Daemon Control       svc <verb> <unit>           systemctl action
Remote Exec          ssh <host> <cmd>            run a command on another deck
Ping Flood           flood <host> -c N           ICMP load
Remote Reboot        reboot / suspend            the deck itself
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal as signal_mod
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

from . import palette
from .config import CONFIG_DIR, ensure_dirs

LOG_FILE = CONFIG_DIR / "actions.jsonl"

MAC_RE = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")
UNIT_RE = re.compile(r"^[A-Za-z0-9@._+~-]+$")
SVC_ACTIONS = ("start", "stop", "restart", "reload", "enable", "disable")


class ActionError(RuntimeError):
    """A quickhack failed its preconditions or its execution."""


# ---------------------------------------------------------------- plumbing

def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()
    except OSError as e:
        return 127, "", str(e)
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"


def _sudo_prefix() -> list[str]:
    """Interactive sudo on a TTY (user can answer the prompt); sudo -n elsewhere."""
    return ["sudo"] if sys.stdin.isatty() else ["sudo", "-n"]


def _maybe_privileged(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run directly first; escalate via sudo only if the direct attempt fails."""
    rc, out, err = _run(cmd, timeout)
    if rc == 0:
        return rc, out, err
    rc2, out2, err2 = _run(_sudo_prefix() + cmd, timeout)
    if rc2 == 0:
        return rc2, out2, err2
    if ("a password is required" in err2 or "sudo:" in err2) and not sys.stdin.isatty():
        raise ActionError(f"{cmd[0]}: needs root and no password available ({err2.splitlines()[0] if err2 else err})")
    return rc, out, err  # direct error is usually the more informative one


def log_action(action: str, target: str, result: str) -> None:
    """Append to the audit trail — every executed quickhack is recorded."""
    ensure_dirs()
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "action": action,
        "target": target,
        "result": result[:300],
    }
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def read_log(n: int = 15) -> list[dict]:
    if not LOG_FILE.exists():
        return []
    lines = LOG_FILE.read_text(encoding="utf-8").splitlines()[-n:]
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def confirm(question: str, assume_yes: bool = False) -> None:
    """Gate destructive actions: --yes, or an interactive prompt, or refuse."""
    if assume_yes:
        return
    if sys.stdin.isatty():
        try:
            ans = input(f"{question} [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            raise ActionError("aborted") from None
        if ans in ("y", "yes"):
            return
        raise ActionError("operator declined")
    raise ActionError(f"not a terminal — pass --yes to execute: {question}")


# ---------------------------------------------------------------- weapons

def parse_signal(sig: str) -> tuple[int, str]:
    """'9', 'KILL', 'sigkill' → (9, 'SIGKILL')."""
    s = sig.strip().upper()
    try:
        signum = int(s) if s.isdigit() else signal_mod.Signals[s if s.startswith("SIG") else f"SIG{s}"].value
        return signum, signal_mod.Signals(signum).name
    except (KeyError, ValueError):
        raise ActionError(f"unknown signal {sig!r}") from None


def kill(target: str, sig: str = "TERM", force: bool = False,
         assume_yes: bool = False) -> str:
    """DOWNTIME — signal a process by PID or name."""
    if target.isdigit():
        try:
            procs = [psutil.Process(int(target))]
        except psutil.NoSuchProcess:
            raise ActionError(f"no process with pid {target}") from None
    else:
        exact = [p for p in psutil.process_iter(["name"])
                 if (p.info.get("name") or "").lower() == target.lower()]
        partial = [p for p in psutil.process_iter(["name"])
                   if target.lower() in (p.info.get("name") or "").lower()]
        procs = exact or partial
        if not procs:
            raise ActionError(f"no process matches name {target!r}")
        if not exact and not force:
            # "kill ssh" would also hit sshd: partial matches need an explicit --force
            found = ", ".join(sorted({p.info.get('name') or '?' for p in partial})[:8])
            raise ActionError(f"no process is named exactly {target!r}; partial matches: {found} "
                              f"— use the exact name, a pid, or --force")
    protected = {0, 1, os.getpid(), os.getppid()}
    if not force:
        blocked = [p for p in procs if p.pid in protected]
        if blocked:
            raise ActionError(
                f"refusing to signal protected process "
                f"{blocked[0].pid}:{blocked[0].name()} (init/self — use --force)")
    signum, signame = parse_signal(sig)
    names = ", ".join(f"{p.pid}:{p.name()}" for p in procs[:5])
    more = f" (+{len(procs) - 5})" if len(procs) > 5 else ""
    confirm(f"send {signame} to {len(procs)} process(es): {names}{more}", assume_yes)
    results = []
    for p in procs:
        try:
            p.send_signal(signum)
            results.append(f"{p.pid} signalled")
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            results.append(f"{p.pid} {type(e).__name__}")
    msg = f"{signame} → {names}{more}: " + "; ".join(results[:5])
    log_action("kill", names + more, msg)
    return msg


def cut(host: str, port: int | None = None, assume_yes: bool = False) -> str:
    """SHORT CIRCUIT — kill established TCP connections to a host (ss -K)."""
    from .netinfo import dns_lookup, ip_records
    ips = ip_records([host]) or ip_records(dns_lookup(host).get("records") or [])
    if not ips:
        raise ActionError(f"cannot resolve {host!r}")
    ip = next((a for a in ips if ":" not in a), ips[0])  # prefer IPv4, fall back to IPv6
    try:
        conns = [c for c in psutil.net_connections(kind="inet")
                 if c.status == psutil.CONN_ESTABLISHED and c.raddr]
    except (psutil.AccessDenied, OSError) as e:
        raise ActionError(f"cannot enumerate sockets: {e}") from None
    matches = [c for c in conns if c.raddr.ip == ip and (port is None or c.raddr.port == port)]
    if not matches:
        raise ActionError(f"no established TCP connections to {ip}"
                          + (f":{port}" if port else ""))
    label = f"{len(matches)} connection(s) to {ip}" + (f":{port}" if port else "")
    confirm(f"sever {label}", assume_yes)
    cmd = ["ss", "-K", "state", "established", "dst", ip]
    if port is not None:
        cmd += ["dport", "=", str(port)]
    rc, out, err = _maybe_privileged(cmd)
    if rc != 0:
        raise ActionError(f"ss -K failed: {(err or out)[:200]}")
    msg = f"severed {label}"
    log_action("cut", ip + (f":{port}" if port else ""), msg)
    return msg


def wake(mac: str, via: str = "255.255.255.255", port: int = 9) -> str:
    """WAKE-ON-LAN — UDP magic packet. No root needed, safe to repeat."""
    if not MAC_RE.match(mac):
        raise ActionError(f"invalid MAC address: {mac!r}")
    pkt = b"\xff" * 6 + bytes.fromhex(mac.replace(":", "").replace("-", "")) * 16
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.sendto(pkt, (via, port))
    except OSError as e:
        raise ActionError(f"magic packet send failed: {e}") from None
    msg = f"magic packet → {mac} via {via}:{port} ({len(pkt)} bytes)"
    log_action("wake", mac, msg)
    return msg


def service(action: str, unit: str, user: bool = False,
            assume_yes: bool = False) -> str:
    """DAEMON CONTROL — systemctl action on a unit (user units need no root)."""
    if action not in SVC_ACTIONS:
        raise ActionError(f"unknown verb {action!r} (allowed: {', '.join(SVC_ACTIONS)})")
    if not UNIT_RE.match(unit):
        raise ActionError(f"invalid unit name: {unit!r}")
    cmd = ["systemctl"] + (["--user"] if user else []) + [action, unit]
    if user:
        rc, out, err = _run(cmd)
    else:
        confirm(f"{action.upper()} system unit {unit}", assume_yes)
        rc, out, err = _maybe_privileged(cmd)
    if rc != 0:
        raise ActionError(f"systemctl {action} {unit}: {(err or out)[:200]}")
    msg = f"systemctl --user {action} {unit}" if user else f"systemctl {action} {unit}"
    log_action("svc", unit, msg)
    return msg


def remote_exec(host: str, command: str, timeout: int = 60, assume_yes: bool = False) -> str:
    """REMOTE EXEC — run a command on another deck over ssh (BatchMode)."""
    if not shutil.which("ssh"):
        raise ActionError("ssh not installed")
    if host.startswith("-"):  # would be read as an ssh option, e.g. -oProxyCommand=...
        raise ActionError(f"invalid host {host!r}")
    confirm(f"run {command!r} on {host}", assume_yes)
    rc, out, err = _run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "--", host, command],
        timeout=timeout)
    if rc != 0:
        raise ActionError(f"ssh {host} {command!r}: rc={rc} {(err or out)[:200]}")
    # the log records what ran, not the remote output (it can contain secrets)
    log_action("ssh", host, f"{command!r}: ok, {len(out)} bytes of output")
    return f"ssh {host} {command!r}:\n{out or '(no output)'}"


def flood(host: str, count: int = 64, assume_yes: bool = False) -> str:
    """PING FLOOD — ICMP load. Uses ping -f (root) with a fast-ping fallback."""
    if count < 1 or count > 1000:
        raise ActionError("count must be 1..1000")
    confirm(f"flood {host} with {count} packets", assume_yes)
    rc, out, err = _run(["ping", "-f", "-c", str(count), host], timeout=60)
    if rc == 0:
        mode = "flood (-f)"
    else:
        # -f needs root; fall back to a 10 pings/sec fast ping
        rc, out, err = _run(["ping", "-i", "0.1", "-c", str(count), host], timeout=60)
        mode = "fast-ping (-i 0.1)"
    if rc != 0:
        raise ActionError(f"ping {host}: {(err or out)[:200]}")
    summary = next((ln for ln in out.splitlines() if "packet loss" in ln), out[:120])
    msg = f"flood {mode} {host}: {summary}"
    log_action("flood", host, msg)
    return msg


def deck_reboot(assume_yes: bool = False) -> str:
    """REMOTE REBOOT (local) — reboot the deck itself."""
    confirm("REBOOT the deck", assume_yes)
    cmd = ["omarchy", "system", "reboot"] if shutil.which("omarchy") else ["systemctl", "reboot"]
    rc, out, err = _maybe_privileged(cmd, timeout=15)
    if rc != 0:
        raise ActionError(f"reboot failed: {(err or out)[:200]}")
    msg = f"deck rebooting via {cmd[0]}"
    log_action("reboot", "deck", msg)
    return msg


def deck_suspend(assume_yes: bool = False) -> str:
    """SLEEP PROTOCOL — suspend the deck."""
    confirm("SUSPEND the deck", assume_yes)
    rc, out, err = _maybe_privileged(["systemctl", "suspend"], timeout=15)
    if rc != 0:
        raise ActionError(f"suspend failed: {(err or out)[:200]}")
    msg = "deck suspending"
    log_action("suspend", "deck", msg)
    return msg


# ---------------------------------------------------------------- registry

ARSENAL = [
    ("Downtime",       "netrunner kill <pid|name> [-s SIG] [-y]",  "signal a process"),
    ("Short Circuit",  "netrunner cut <host> [--port N] [-y]",     "kill TCP sockets via ss -K"),
    ("Wake on LAN",    "netrunner wake <mac> [--via ip]",          "UDP magic packet"),
    ("Daemon Control", "netrunner svc <verb> <unit> [--user] [-y]", "systemctl start/stop/restart/…"),
    ("Remote Exec",    "netrunner ssh <host> <cmd> [-y]",          "execute on another deck"),
    ("Ping Flood",     "netrunner flood <host> [-c N] [-y]",       "ICMP load"),
    ("Remote Reboot",  "netrunner reboot [-y] / suspend [-y]",     "the deck itself"),
]


def build_log(n: int = 15):
    """Renderable: the action log (every executed quickhack)."""
    from rich.panel import Panel
    from rich.text import Text

    entries = read_log(n)
    t = Text()
    if not entries:
        t.append("no actions logged — the armory is silent", style=palette.DIM)
    for e in reversed(entries):
        t.append(f"{e['ts']} ", style=palette.DIM)
        t.append(f"{e['action']}", style=palette.MAGENTA)
        t.append(f" {e['target']} — {e['result']}\n")
    return Panel(t, title="[magenta]ACTION LOG[/]", border_style=palette.MAGENTA)


def build(n: int = 15):
    """Renderable: arsenal table + action log."""
    from rich.console import Group
    from rich.panel import Panel
    from rich.table import Table

    t = Table(box=None, expand=True)
    t.add_column("QUICKHACK", style=palette.MAGENTA)
    t.add_column("COMMAND", style=palette.CYAN)
    t.add_column("EFFECT", style=palette.DIM)
    for name, cmd, effect in ARSENAL:
        t.add_row(name, cmd, effect)
    return Group(
        Panel(t, title="[bright_cyan]ARMORY — QUICKHACK EXECUTION[/]",
              border_style=palette.CYAN),
        build_log(n),
    )
