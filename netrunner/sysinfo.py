"""Cyberdeck vitals — local system telemetry via psutil."""

from __future__ import annotations

import shutil
import subprocess
import time

import psutil

from . import palette
from .palette import bar, kv

_PRIMED = False


def uptime_str() -> str:
    d, rem = divmod(int(time.time() - psutil.boot_time()), 86400)
    h, rem = divmod(rem, 3600)
    return f"{d}d {h:02d}h {rem // 60:02d}m"


def _gb(n: int) -> str:
    return f"{n / 2**30:.1f}GB"


def vitals() -> dict:
    """Sample CPU / memory / disk / temps."""
    per = psutil.cpu_percent(interval=0.15, percpu=True)
    vm = psutil.virtual_memory()
    sw = psutil.swap_memory()
    du = psutil.disk_usage("/")
    temps: dict[str, float] = {}
    for chip, entries in (psutil.sensors_temperatures() or {}).items():
        for e in entries:
            temps[f"{chip}:{e.label or 'core'}"] = e.current
    return {
        "cpu": sum(per) / max(len(per), 1),
        "percpu": per,
        "cores": len(per),
        "freq": psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None,
        "load": list(__import__("os").getloadavg()) if hasattr(__import__("os"), "getloadavg") else [],
        "mem_used": vm.used,
        "mem_total": vm.total,
        "mem_pct": vm.percent,
        "swap_used": sw.used,
        "swap_total": sw.total,
        "disk_used": du.used,
        "disk_total": du.total,
        "disk_pct": du.percent,
        "temps": temps,
        "uptime": uptime_str(),
    }


def top_processes(n: int = 12) -> list[tuple[int, str, float, str]]:
    """(pid, name, cpu%, user) — top n by CPU."""
    global _PRIMED
    procs = list(psutil.process_iter(["pid", "name", "username"]))
    if not _PRIMED:
        for p in procs:
            try:
                p.cpu_percent(None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        _PRIMED = True
        time.sleep(0.15)
    rows = []
    for p in procs:
        try:
            rows.append(
                (p.pid, p.info.get("name") or "?", p.cpu_percent(None), p.info.get("username") or "?")
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    rows.sort(key=lambda r: -r[2])
    return rows[:n]


def gpu() -> str | None:
    """NVIDIA GPU summary if nvidia-smi is present."""
    if not shutil.which("nvidia-smi"):
        return None
    out = subprocess.run(
        ["nvidia-smi", "--query-gpu=name,utilization.gpu,memory.used,memory.total",
         "--format=csv,noheader,nounits"],
        capture_output=True, text=True, timeout=5,
    ).stdout.strip()
    if not out:
        return None
    name, util, mu, mt = [x.strip() for x in out.split(",")]
    return f"{name} — {util}% · {_gb(int(mu) * 2**20)}/{_gb(int(mt) * 2**20)}"


def build():
    """Return the full cyberdeck status readout as a renderable."""
    from rich.console import Group
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    v = vitals()
    t = Table.grid(padding=(0, 1))
    t.add_column(justify="right", style=palette.DIM)
    t.add_column()
    t.add_row("CPU", bar(v["cpu"]))
    t.add_row("MEM", bar(v["mem_pct"]) + f"  {_gb(v['mem_used'])}/{_gb(v['mem_total'])}")
    t.add_row("DISK /", bar(v["disk_pct"]) + f"  {_gb(v['disk_used'])}/{_gb(v['disk_total'])}")
    if v["swap_total"]:
        t.add_row("SWAP", bar(100 * v["swap_used"] / v["swap_total"]))
    for label, temp in list(v["temps"].items())[:4]:
        style = palette.RED if temp > 80 else palette.YELLOW if temp > 65 else palette.CYAN
        t.add_row("TEMP", f"[{style}]{label}: {temp:.0f}°C[/]")
    if v["freq"]:
        t.add_row("CLOCK", f"[{palette.WHITE}]{v['freq']['current']:.0f} MHz[/]")
    t.add_row("CORES", f"[{palette.WHITE}]{v['cores']}[/]")
    t.add_row("LOAD", f"[{palette.WHITE}]{', '.join(f'{x:.2f}' for x in v['load'])}[/]")
    t.add_row("UPTIME", f"[{palette.WHITE}]{v['uptime']}[/]")
    g = gpu()
    if g:
        t.add_row("GPU", f"[{palette.WHITE}]{g}[/]")

    panels = [Panel(t, title="[bright_cyan]CYBERDECK STATUS[/]", border_style=palette.CYAN)]

    procs = top_processes()
    pt = Table(box=None, pad_edge=False, expand=False)
    pt.add_column("PID", style=palette.DIM, justify="right")
    pt.add_column("PROCESS", style=palette.WHITE)
    pt.add_column("CPU", style=palette.CYAN, justify="right")
    pt.add_column("USER", style=palette.DIM)
    for pid, name, cpu, user in procs:
        pt.add_row(str(pid), name, f"{cpu:.1f}%", user)
    panels.append(Panel(pt, title="[bright_cyan]ACTIVE DAEMONS[/]", border_style=palette.CYAN))
    return Group(*panels)


def render(console) -> None:
    console.print(build())
