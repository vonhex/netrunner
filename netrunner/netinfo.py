"""Net scanning — interfaces, routes, ARP, ping sweeps, port scans.

All discovery is real: `ip -j`, nmcli, ARP tables, threaded ICMP pings,
TCP connect scans, traceroute, DNS.
"""

from __future__ import annotations

import concurrent.futures as cf
import json
import os
import re
import shutil
import socket
import subprocess
import time
import urllib.request

from . import palette
from .palette import kv

COMMON_PORTS = [
    21, 22, 23, 25, 53, 69, 80, 110, 135, 139, 143, 443, 445, 546, 547,
    631, 808, 993, 995, 1433, 1723, 1883, 2375, 3000, 3306, 3389, 4444,
    5000, 5173, 5432, 5900, 6379, 6443, 8000, 8080, 8443, 8888, 9000,
    9100, 9200, 11211, 27017,
]


def _run(cmd: list[str], timeout: int = 10) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def have_root() -> bool:
    """True when the process already has effective root — no escalation needed."""
    try:
        return os.geteuid() == 0
    except AttributeError:  # non-POSIX
        return False


def _run_priv(cmd: list[str], timeout: int = 10) -> str:
    """Run a command that may need root.

    Tries it directly first (works if we are root, or if the binary is
    setuid/unprivileged for this query). If that yields nothing and a
    *passwordless* sudo rule exists, retry once via ``sudo -n`` so a single
    probe can elevate itself — the whole app never has to run under sudo.
    Never prompts: ``sudo -n`` fails silently when no rule is configured.
    """
    out = _run(cmd, timeout=timeout)
    if out or have_root():
        return out
    if shutil.which("sudo"):
        return _run(["sudo", "-n", *cmd], timeout=timeout)
    return ""


# ---------------------------------------------------------------- interfaces

def interfaces() -> list[dict]:
    """Parse `ip -j addr` into [{name, state, mtu, addrs:[...]}]."""
    out = _run(["ip", "-j", "addr"])
    if not out:
        return []
    result = []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    for e in data:
        addrs = []
        for a in e.get("addr_info", []):
            if a.get("family") == "inet":
                addrs.append(f"{a.get('local', a.get('address'))}/{a.get('prefixlen', '')}")
            elif a.get("family") == "inet6" and not a.get("scope", "").startswith("link"):
                addrs.append(f"{a.get('local', a.get('address'))}/64")
        result.append({
            "name": e.get("ifname", "?"),
            "state": e.get("operstate", "UNKNOWN").upper(),
            "mtu": e.get("mtu", 0),
            "addrs": addrs,
        })
    return result


def default_route() -> dict:
    """{dev, src, gateway} for the default route."""
    out = _run(["ip", "-j", "route", "get", "1.0.0.1"])
    try:
        data = json.loads(out)
        if data:
            e = data[0]
            # `ip route get` reports the chosen source address as `prefsrc`;
            # `ip route show` uses `src`. Accept either so the sweep/routing
            # panel always learns the deck's own address.
            return {"dev": e.get("dev", ""),
                    "src": e.get("prefsrc") or e.get("src", ""),
                    "gateway": e.get("gateway", "")}
    except (json.JSONDecodeError, IndexError):
        pass
    return {"dev": "", "src": "", "gateway": ""}


def nmcli_summary() -> list[dict]:
    """NetworkManager connections, if present."""
    out = _run(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"])
    rows = []
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) >= 3:
            rows.append({
                "device": parts[0], "type": parts[1],
                "state": parts[2], "connection": parts[3] if len(parts) > 3 else "",
            })
    return rows


def neighbors() -> list[dict]:
    """ARP table via `ip -j neigh` — devices the deck has seen on the LAN."""
    out = _run(["ip", "-j", "neigh"])
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    return [
        {"ip": e.get("dst") or e.get("address", "?"),
         "mac": e.get("lladdr", "?"),
         "state": ",".join(e["state"]) if isinstance(e.get("state"), list) else e.get("state", "?"),
         "dev": e.get("dev", "?")}
        for e in data
    ]


def dns_servers() -> list[str]:
    servers = []
    try:
        for line in open("/etc/resolv.conf"):
            m = re.match(r"^\s*nameserver\s+(\S+)", line)
            if m:
                servers.append(m.group(1))
    except OSError:
        pass
    return servers


# ---------------------------------------------------------------- scanning

def ping(host: str, count: int = 4) -> dict:
    """ICMP ping; returns {host, alive, min, avg, max, loss}."""
    out = _run(["ping", "-c", str(count), "-W", "2", host], timeout=count * 2 + 5)
    alive = "bytes from" in out
    loss = None
    m = re.search(r"(\d+(?:\.\d+)?)% packet loss", out)
    if m:
        loss = float(m.group(1))
    rtt = None
    m = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)", out)
    if m:
        rtt = {"min": float(m.group(1)), "avg": float(m.group(2)), "max": float(m.group(3))}
    return {"host": host, "alive": alive, "loss": loss, **(rtt or {})}


def _ping_one(ip: str) -> tuple[str, bool]:
    return ip, bool(_run(["ping", "-c", "1", "-W", "1", ip], timeout=3))


def ping_sweep(subnet: str | None = None, workers: int = 64) -> list[str]:
    """Threaded sweep of a /24 (default: the subnet the deck is on)."""
    if not subnet:
        src = default_route().get("src", "")
        if not src:
            return []
        subnet = ".".join(src.split(".")[:3])
    ips = [f"{subnet}.{i}" for i in range(1, 255)]
    alive = []
    with cf.ThreadPoolExecutor(workers) as ex:
        for ip, ok in ex.map(_ping_one, ips):
            if ok:
                alive.append(ip)
    return alive


def scan_subnet(subnet: str | None = None) -> dict:
    """Combined netscan: ARP cache + live sweep + NM info."""
    src = default_route().get("src", "")
    if not subnet and src:
        subnet = ".".join(src.split(".")[:3]) + ".0/24"
    return {
        "subnet": subnet or "?",
        "arp": neighbors(),
        "alive": ping_sweep(subnet.rsplit(".", 1)[0]) if subnet else [],
        "nm": nmcli_summary(),
        "dns": dns_servers(),
    }


# ---------------------------------------------------------------- quickhacks

def traceroute(host: str, max_hops: int = 15) -> list[str]:
    return _run(["traceroute", "-m", str(max_hops), "-w", "2", host], timeout=60).splitlines()


def dns_lookup(host: str) -> dict:
    """DNS decrypt — dig if available, else getaddrinfo."""
    out = _run(["dig", "+short", host])
    if out:
        return {"host": host, "records": out.splitlines(), "method": "dig"}
    try:
        addrs = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
        return {"host": host, "records": addrs, "method": "getaddrinfo"}
    except socket.gaierror as e:
        return {"host": host, "records": [], "method": "getaddrinfo", "error": str(e)}


def _tcp_probe(host: str, port: int, timeout: float) -> int | None:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port
    except OSError:
        return None


def tcp_scan(host: str, ports: list[int] | None = None, timeout: float = 0.4) -> list[int]:
    """TCP connect scan (the netrunner's `Port Analysis` quickhack)."""
    ports = ports or COMMON_PORTS
    open_ports = []
    with cf.ThreadPoolExecutor(min(len(ports), 60)) as ex:
        for port in ex.map(lambda p: _tcp_probe(host, p, timeout), ports):
            if port is not None:
                open_ports.append(port)
    return sorted(open_ports)


def http_inspect(url: str) -> dict:
    """HTTP request telemetry."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    req = urllib.request.Request(url, headers={"User-Agent": "netrunner/1.0 (NETRUNNER//OS)"})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read(65536)
            return {
                "url": url, "status": resp.status, "reason": resp.reason,
                "ms": round((time.time() - t0) * 1000, 1),
                "server": resp.headers.get("Server", "?"),
                "content_type": resp.headers.get("Content-Type", "?"),
                "bytes": len(body),
            }
    except Exception as e:  # noqa: BLE001 — report any HTTP failure
        return {"url": url, "error": str(e), "ms": round((time.time() - t0) * 1000, 1)}


# ---------------------------------------------------------------- rendering

def build_interfaces():
    """Return interfaces + routing as a renderable."""
    from rich.console import Group
    from rich.panel import Panel
    from rich.table import Table

    t = Table(box=None, pad_edge=False, expand=True)
    t.add_column("IFACE", style=palette.CYAN)
    t.add_column("STATE")
    t.add_column("ADDRESSES", style=palette.WHITE)
    t.add_column("MTU", style=palette.DIM, justify="right")
    for i in interfaces():
        st = f"[green]{i['state']}[/]" if i["state"] == "UP" else f"[yellow]{i['state']}[/]"
        t.add_row(i["name"], st, ", ".join(i["addrs"]) or "—", str(i["mtu"]))
    panels = [Panel(t, title="[bright_cyan]NET INTERFACES[/]", border_style=palette.CYAN)]

    gw = default_route()
    if gw["dev"]:
        panels.append(Panel(
            "\n".join([kv("GATEWAY", gw["gateway"] or "—"), kv("DEVICE", gw["dev"]),
                       kv("SOURCE", gw["src"] or "—"),
                       kv("DNS", ", ".join(dns_servers()) or "—")]),
            title="[bright_cyan]ROUTING[/]", border_style=palette.CYAN))
    return Group(*panels)


def render_interfaces(console) -> None:
    console.print(build_interfaces())


def build_arp():
    """Return the ARP table as a renderable."""
    from rich.panel import Panel
    from rich.table import Table

    t = Table(box=None, pad_edge=False, expand=True)
    t.add_column("IP", style=palette.CYAN)
    t.add_column("MAC", style=palette.WHITE)
    t.add_column("STATE", style=palette.DIM)
    t.add_column("VIA", style=palette.DIM)
    for n in neighbors():
        t.add_row(n["ip"], n["mac"], n["state"], n["dev"])
    return Panel(t, title="[bright_cyan]ARP TABLE — KNOWN HOSTS[/]", border_style=palette.CYAN)


def render_arp(console) -> None:
    console.print(build_arp())
