"""NETRUNNER//OS command line.

`netrunner` with no args launches the TUI on a TTY, else prints status.
"""

from __future__ import annotations

import argparse
import os
import sys

from rich.console import Console
from rich.panel import Panel

from . import __version__, banner, netinfo, palette
from .config import load, save


def _refuse_root(console: Console) -> None:
    """NETRUNNER//OS is a per-user deck — refuse to run under sudo.

    Running the whole suite as root sends your profile and shard vault to
    /root, breaks the Wayland TUI, and is never necessary: the handful of
    probes that need privileges (ufw/nft/firewalld status) escalate
    themselves per-command via `sudo -n`. Escape hatch: NETRUNNER_ALLOW_ROOT=1.
    """
    try:
        is_root = os.geteuid() == 0
    except AttributeError:
        is_root = False
    if not is_root or os.environ.get("NETRUNNER_ALLOW_ROOT") == "1":
        return
    console.print(Panel(
        f"[{palette.RED}]NETRUNNER//OS must not be jacked in as root.[/]\n\n"
        f"[{palette.DIM}]Run it as your own operator — [/]"
        f"[{palette.WHITE}]netrunner[/][{palette.DIM}], not [/]"
        f"[{palette.WHITE}]sudo netrunner[/][{palette.DIM}].[/]\n"
        f"[{palette.DIM}]Privileged probes (firewall status) escalate themselves "
        f"via [/][{palette.WHITE}]sudo -n[/][{palette.DIM}] when needed.[/]\n\n"
        f"[{palette.DIM}]Override (not recommended): [/]"
        f"[{palette.WHITE}]NETRUNNER_ALLOW_ROOT=1[/]",
        title=f"[{palette.RED}]ACCESS DENIED[/]", border_style=palette.RED))
    raise SystemExit(1)


def _status(console: Console) -> None:
    from . import sysinfo
    console.print(banner.render_banner())
    sysinfo.render(console)
    netinfo.render_interfaces(console)


def _scan(console: Console, subnet: str | None, sweep: bool) -> None:
    from rich.table import Table

    netinfo.render_interfaces(console)
    netinfo.render_arp(console)
    if sweep:
        console.print("[bright_cyan]▸ ping sweep in progress...[/]")
        src = netinfo.default_route().get("src", "")
        subnet = subnet or (".".join(src.split(".")[:3]) + ".0/24" if src else None)
        if not subnet:
            console.print("[red]no routable address — cannot sweep[/]")
            return
        base = subnet.rsplit(".", 1)[0]
        alive = netinfo.ping_sweep(base)
        t = Table(box=None, expand=True, title=None)
        t.add_column("ALIVE HOSTS", style=palette.GREEN)
        rows = [alive[i:i + 4] for i in range(0, len(alive), 4)]
        for row in rows:
            t.add_row(*[f"{ip:<16}" for ip in row] + [""] * (4 - len(row)))
        console.print(Panel(t, title=f"[bright_cyan]SWEEP — {subnet}[/]",
                            border_style=palette.CYAN))
    nm = netinfo.nmcli_summary()
    if nm:
        nt = Table(box=None, expand=True)
        nt.add_column("DEVICE", style=palette.CYAN)
        nt.add_column("TYPE", style=palette.DIM)
        nt.add_column("STATE")
        nt.add_column("CONNECTION", style=palette.WHITE)
        for r in nm:
            st = f"[green]{r['state']}[/]" if r["state"] == "connected" else f"[yellow]{r['state']}[/]"
            nt.add_row(r["device"], r["type"], st, r["connection"])
        console.print(Panel(nt, title="[bright_cyan]NETWORKMANAGER[/]", border_style=palette.CYAN))


def _hack(console: Console, kind: str, target: str, ports: str | None) -> None:
    from rich.table import Table

    if kind == "ping":
        r = netinfo.ping(target)
        body = (f"[{palette.DIM}]HOST[/]    {r['host']}\n"
                f"[{palette.DIM}]STATUS[/]  "
                + (f"[green]ALIVE[/]" if r["alive"] else "[red]UNREACHABLE[/]") + "\n")
        if r.get("loss") is not None:
            body += f"[{palette.DIM}]LOSS[/]    {r['loss']}%\n"
        if r.get("avg") is not None:
            body += (f"[{palette.DIM}]RTT[/]     min {r['min']:.1f} / "
                     f"[bright_cyan]avg {r['avg']:.1f}[/] / max {r['max']:.1f} ms\n")
        console.print(Panel(body, title=f"[magenta]QUICKHACK — PING[/]", border_style=palette.MAGENTA))
    elif kind == "trace":
        lines = netinfo.traceroute(target)
        body = "\n".join(f"[bright_cyan]{ln}[/]" for ln in lines) or "[red]no route[/]"
        console.print(Panel(body, title=f"[magenta]QUICKHACK — ROUTE TRACE[/]",
                            border_style=palette.MAGENTA))
    elif kind == "dns":
        r = netinfo.dns_lookup(target)
        body = "\n".join(f"[bright_cyan]{rec}[/]" for rec in r["records"]) or f"[red]{r.get('error', 'no records')}[/]"
        console.print(Panel(body, title=f"[magenta]QUICKHACK — DNS DECRYPT ({r['method']})[/]",
                            border_style=palette.MAGENTA))
    elif kind == "ports":
        try:
            plist = [int(p) for p in ports.split(",")] if ports else None
        except ValueError:
            console.print(f"[red]invalid --ports {ports!r}: expected a comma-separated "
                          f"list of port numbers (e.g. 22,80,443)[/]")
            raise SystemExit(2)
        if plist and any(not 1 <= p <= 65535 for p in plist):
            console.print("[red]ports must be in range 1..65535[/]")
            raise SystemExit(2)
        console.print(f"[bright_cyan]▸ port analysis on {target}...[/]")
        open_ports = netinfo.tcp_scan(target, plist)
        t = Table(box=None, expand=True)
        t.add_column("OPEN PORTS", style=palette.GREEN)
        rows = [[str(p) for p in open_ports[i:i + 8]] for i in range(0, len(open_ports), 8)]
        for row in rows or [["—"]]:
            t.add_row(*row + [""] * (8 - len(row)))
        console.print(Panel(t, title=f"[magenta]PORT ANALYSIS — {target}[/]",
                            border_style=palette.MAGENTA))
    elif kind == "http":
        r = netinfo.http_inspect(target)
        if "error" in r:
            body = f"[red]{r['error']}[/] ({r['ms']}ms)"
        else:
            body = (f"[{palette.DIM}]URL[/]     {r['url']}\n"
                    f"[{palette.DIM}]STATUS[/]  [green]{r['status']} {r['reason']}[/]\n"
                    f"[{palette.DIM}]SERVER[/]  {r['server']}\n"
                    f"[{palette.DIM}]TYPE[/]    {r['content_type']}\n"
                    f"[{palette.DIM}]SIZE[/]    {r['bytes']} bytes\n"
                    f"[{palette.DIM}]TIME[/]    {r['ms']} ms")
        console.print(Panel(body, title="[magenta]QUICKHACK — HTTP INSPECT[/]",
                            border_style=palette.MAGENTA))


def _execute(console: Console, name: str, fn) -> None:
    """Run an armory action; render the outcome and exit non-zero on failure."""
    from rich.text import Text

    from . import armory
    try:
        result = fn()
    except armory.ActionError as exc:
        console.print(Panel(Text(str(exc), style=palette.RED),
                            title=f"[{palette.RED}]{name.upper()}[/]",
                            border_style=palette.RED))
        raise SystemExit(1)
    console.print(Panel(Text(result, style=palette.GREEN),
                        title=f"[{palette.GREEN}]{name.upper()}[/]",
                        border_style=palette.GREEN))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="netrunner",
        description="NETRUNNER//OS — a Cyberpunk 2077-style netrunner suite for Omarchy",
    )
    parser.add_argument("--version", action="version", version=f"NETRUNNER//OS {__version__}")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("tui", help="launch the interactive TUI")
    bp = sub.add_parser("boot", help="play the boot sequence")
    bp.add_argument("--fast", action="store_true")
    sub.add_parser("status", help="one-shot cyberdeck status readout")

    sp = sub.add_parser("scan", help="netscan: interfaces, ARP, live ping sweep")
    sp.add_argument("--subnet", help="e.g. 10.0.1 (default: the deck's own /24)")
    sp.add_argument("--no-sweep", action="store_true", help="skip the live ping sweep")

    sub.add_parser("ice", help="ICE analysis: firewall, sockets, threat tier")
    dp = sub.add_parser("daemons", help="systemd daemon roster")
    dp.add_argument("--all", action="store_true", help="include inactive units")
    shp = sub.add_parser("shards", help="recent journal entries as data shards")
    shp.add_argument("-n", type=int, default=25)

    sh2 = sub.add_parser("shard", help="store a custom data shard in the vault")
    sh2.add_argument("title")
    sh2.add_argument("body", nargs="?", default="")

    cfgp = sub.add_parser("config", help="set operator/corp/deck identity + fixer")
    cfgp.add_argument("--operator")
    cfgp.add_argument("--corp")
    cfgp.add_argument("--deck")
    cfgp.add_argument("--fixer", dest="edgerunner_name",
                      help="name your AI fixer (default: EDGERUNNER)")
    cfgp.add_argument("--fixer-url", dest="edgerunner_url",
                      help="fixer endpoint (default: http://10.0.1.103:8731)")
    cfgp.add_argument("--fixer-model", dest="edgerunner_model",
                      help="pin a model id (default: auto-detect)")

    hp = sub.add_parser("hack", help="quickhacks: ping | trace | dns | ports | http")
    hp.add_argument("kind", choices=["ping", "trace", "dns", "ports", "http"])
    hp.add_argument("target")
    hp.add_argument("--ports", help="comma-separated port list for `ports`")

    # ARMORY — quickhack execution. Real damage; every action needs --yes
    # (or an interactive confirm) and lands in the action log.
    kl = sub.add_parser("kill", help="DOWNTIME — signal a process (pid or name)")
    kl.add_argument("target", help="pid or process name")
    kl.add_argument("-s", "--signal", default="TERM")
    kl.add_argument("-f", "--force", action="store_true", help="allow protected pids")
    kl.add_argument("-y", "--yes", action="store_true")
    ct = sub.add_parser("cut", help="SHORT CIRCUIT — kill TCP connections to a host")
    ct.add_argument("host")
    ct.add_argument("--port", type=int)
    ct.add_argument("-y", "--yes", action="store_true")
    wk = sub.add_parser("wake", help="WAKE-ON-LAN — UDP magic packet (no confirm needed)")
    wk.add_argument("mac")
    wk.add_argument("--via", default="255.255.255.255")
    sv = sub.add_parser("svc", help="DAEMON CONTROL — systemctl verb on a unit")
    sv.add_argument("action", choices=["start", "stop", "restart", "reload",
                                       "enable", "disable"])
    sv.add_argument("unit")
    sv.add_argument("--user", action="store_true", help="user-scope unit (no root)")
    sv.add_argument("-y", "--yes", action="store_true")
    ss = sub.add_parser("ssh", help="REMOTE EXEC — run a command on another deck")
    ss.add_argument("host")
    ss.add_argument("command", nargs="+")
    fl = sub.add_parser("flood", help="PING FLOOD — ICMP load on a host")
    fl.add_argument("host")
    fl.add_argument("-c", type=int, default=64)
    fl.add_argument("-y", "--yes", action="store_true")
    rb = sub.add_parser("reboot", help="REMOTE REBOOT — reboot the deck")
    rb.add_argument("-y", "--yes", action="store_true")
    spn = sub.add_parser("suspend", help="SLEEP PROTOCOL — suspend the deck")
    spn.add_argument("-y", "--yes", action="store_true")
    lgp = sub.add_parser("log", help="action log — every executed quickhack")
    lgp.add_argument("-n", type=int, default=15)

    br = sub.add_parser("breach", help="play Breach Protocol in the terminal")
    br.add_argument("--demo", action="store_true", help="auto-play the breach")
    br.add_argument("--seed", type=int, help="deterministic buffer")

    ep = sub.add_parser("edgerunner", aliases=["ask"],
                        help="consult EDGERUNNER, the deck's local AI fixer")
    ep.add_argument("prompt", nargs="*", help="your question (omit for interactive chat)")
    ep.add_argument("--no-context", action="store_true",
                    help="don't send the live deck snapshot with your question")

    args = parser.parse_args(argv)
    cmd = args.cmd or ("tui" if sys.stdout.isatty() else "status")
    console = Console()
    _refuse_root(console)

    if cmd == "tui":
        from .ui import run
        run()
    elif cmd == "boot":
        banner.boot(console, fast=args.fast)
    elif cmd == "status":
        _status(console)
    elif cmd == "scan":
        _scan(console, args.subnet, sweep=not args.no_sweep)
    elif cmd == "ice":
        from . import ice
        ice.render(console)
    elif cmd == "daemons":
        from . import daemons
        daemons.render(console, show_all=args.all)
    elif cmd == "shards":
        from . import shards
        shards.render(console, n=args.n)
    elif cmd == "shard":
        path = __import__("netrunner.shards", fromlist=["write_shard"]).write_shard(
            args.title, args.body or "no content")
        console.print(f"[green]shard stored:[/] {path}")
    elif cmd == "config":
        cfg = load()
        for key in ("operator", "corp", "deck",
                    "edgerunner_name", "edgerunner_url", "edgerunner_model"):
            val = getattr(args, key, None)
            if val:
                cfg[key] = val
        path = save(cfg)
        console.print(f"[green]config saved:[/] {path}")
    elif cmd == "hack":
        _hack(console, args.kind, args.target, args.ports)
    elif cmd == "kill":
        _execute(console, "kill",
                 lambda: __import__("netrunner.armory", fromlist=["kill"]).kill(
                     args.target, args.signal, args.force, args.yes))
    elif cmd == "cut":
        _execute(console, "cut",
                 lambda: __import__("netrunner.armory", fromlist=["cut"]).cut(
                     args.host, args.port, args.yes))
    elif cmd == "wake":
        _execute(console, "wake",
                 lambda: __import__("netrunner.armory", fromlist=["wake"]).wake(
                     args.mac, args.via))
    elif cmd == "svc":
        _execute(console, "svc",
                 lambda: __import__("netrunner.armory", fromlist=["service"]).service(
                     args.action, args.unit, args.user, args.yes))
    elif cmd == "ssh":
        _execute(console, "ssh",
                 lambda: __import__("netrunner.armory", fromlist=["remote_exec"]).remote_exec(
                     args.host, " ".join(args.command)))
    elif cmd == "flood":
        _execute(console, "flood",
                 lambda: __import__("netrunner.armory", fromlist=["flood"]).flood(
                     args.host, args.c, args.yes))
    elif cmd == "reboot":
        _execute(console, "reboot",
                 lambda: __import__("netrunner.armory", fromlist=["deck_reboot"]).deck_reboot(args.yes))
    elif cmd == "suspend":
        _execute(console, "suspend",
                 lambda: __import__("netrunner.armory", fromlist=["deck_suspend"]).deck_suspend(args.yes))
    elif cmd == "log":
        console.print(__import__("netrunner.armory", fromlist=["build_log"]).build_log(args.n))
    elif cmd == "breach":
        from . import breach
        if args.demo:
            breach.demo(console, seed=args.seed)
        else:
            breach.play(console, seed=args.seed)
    elif cmd in ("edgerunner", "ask"):
        from . import edgerunner
        prompt = " ".join(args.prompt).strip()
        if prompt:
            edgerunner.run_once(console, prompt, with_context=not args.no_context)
        else:
            edgerunner.repl(console, with_context=not args.no_context)


if __name__ == "__main__":
    main()
