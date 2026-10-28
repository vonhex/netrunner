"""EDGERUNNER — the deck's AI fixer.

A netrunning assistant backed by a local Halogen / OpenAI-compatible
inference server (default: the operator's own box at 10.0.1.103:8731). It
answers networking, Linux and Omarchy questions and helps the operator read
NETRUNNER//OS's own telemetry — never a cloud service, all on the LAN.

Transport is stdlib urllib only (no new dependencies), hitting
``/v1/chat/completions``. Every call degrades gracefully: if the fixer is
offline the UI shows a clear "EDGERUNNER offline" line instead of crashing.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from . import palette
from .config import load

SYSTEM_PROMPT = (
    "You are {name}, the AI fixer jacked into NETRUNNER//OS — a Cyberpunk "
    "2077-styled network and system console running on the operator's own "
    "Omarchy (Arch Linux + Hyprland) deck. You assist the operator with "
    "network diagnostics, Linux/Omarchy administration, and reading the deck's "
    "live telemetry (interfaces, routes, ARP, firewall/ICE, systemd daemons, "
    "logs, port scans). Be concise and practical: give the exact command or "
    "answer first, then at most a line or two of why. Stay in a light "
    "cyberpunk voice without letting it bury the facts. You only ever advise "
    "on the operator's own systems and networks. If you are unsure, say so "
    "rather than inventing output."
)


class EdgerunnerError(RuntimeError):
    """Raised when the fixer can't be reached or returns an error."""


def _base_url() -> str:
    cfg = load()
    return (os.environ.get("NETRUNNER_EDGERUNNER_URL")
            or cfg.get("edgerunner_url") or "http://10.0.1.103:8731").rstrip("/")


def fixer_name() -> str:
    """The operator's chosen name for the fixer (default EDGERUNNER)."""
    return (os.environ.get("NETRUNNER_EDGERUNNER_NAME")
            or load().get("edgerunner_name") or "EDGERUNNER")


def _request(path: str, payload: dict | None = None, timeout: int = 120) -> dict:
    url = f"{_base_url()}{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data, method="POST" if data else "GET",
        headers={"Content-Type": "application/json",
                 "User-Agent": "netrunner/1.0 (EDGERUNNER)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        raise EdgerunnerError(f"fixer returned HTTP {e.code}: {detail}") from e
    except (urllib.error.URLError, OSError) as e:
        raise EdgerunnerError(
            f"EDGERUNNER offline — no response from {_base_url()} ({e})") from e
    except json.JSONDecodeError as e:
        raise EdgerunnerError(f"fixer sent malformed data: {e}") from e


def resolve_model() -> str:
    """Config model if set, else the first id the server advertises."""
    cfg = load()
    if cfg.get("edgerunner_model"):
        return cfg["edgerunner_model"]
    data = _request("/v1/models", timeout=15)
    models = data.get("data") or []
    if not models:
        raise EdgerunnerError("fixer advertises no models")
    return models[0]["id"]


def deck_context() -> str:
    """A compact, best-effort snapshot of the deck for grounding answers."""
    from . import netinfo
    lines: list[str] = []
    try:
        cfg = load()
        lines.append(f"operator={cfg['operator']} deck={cfg['deck']} corp={cfg['corp']}")
    except Exception:  # noqa: BLE001 — context is optional, never fatal
        pass
    try:
        for i in netinfo.interfaces():
            if i["name"] == "lo":
                continue
            lines.append(f"iface {i['name']} {i['state']} {', '.join(i['addrs']) or '-'}")
        gw = netinfo.default_route()
        if gw.get("gateway"):
            lines.append(f"route default via {gw['gateway']} dev {gw.get('dev','?')} src {gw.get('src','?')}")
        dns = netinfo.dns_servers()
        if dns:
            lines.append(f"dns {', '.join(dns)}")
    except Exception:  # noqa: BLE001
        pass
    try:
        from . import ice
        name, state, _ = ice.firewall()
        lines.append(f"firewall {name} {state}")
    except Exception:  # noqa: BLE001
        pass
    return "DECK CONTEXT (live):\n" + "\n".join(lines) if lines else ""


def chat(messages: list[dict], *, model: str | None = None,
         temperature: float = 0.4, max_tokens: int = 1024,
         reasoning_effort: str = "low", timeout: int = 180) -> str:
    """Send an OpenAI-style message list; return the assistant's text."""
    model = model or resolve_model()
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "reasoning_effort": reasoning_effort,
        "stream": False,
    }
    data = _request("/v1/chat/completions", payload, timeout=timeout)
    try:
        return (data["choices"][0]["message"]["content"] or "").strip()
    except (KeyError, IndexError, TypeError) as e:
        raise EdgerunnerError(f"fixer sent an unexpected reply shape: {e}") from e


def build_messages(prompt: str, history: list[dict] | None = None,
                   with_context: bool = True) -> list[dict]:
    """Assemble the system + (optional live context) + history + prompt."""
    system = SYSTEM_PROMPT.format(name=fixer_name())
    if with_context:
        ctx = deck_context()
        if ctx:
            system = f"{system}\n\n{ctx}"
    msgs = [{"role": "system", "content": system}]
    msgs += history or []
    msgs.append({"role": "user", "content": prompt})
    return msgs


def ask(prompt: str, history: list[dict] | None = None,
        with_context: bool = True, **kw) -> str:
    """One-shot convenience: prompt in, assistant text out."""
    return chat(build_messages(prompt, history, with_context), **kw)


# --------------------------------------------------------------- front-ends

def _panel(body, title: str):
    from rich.panel import Panel
    return Panel(body, title=f"[{palette.MAGENTA}]{title}[/]",
                 border_style=palette.MAGENTA)


def run_once(console, prompt: str, with_context: bool = True) -> None:
    from rich.text import Text
    name = fixer_name()
    try:
        reply = ask(prompt, with_context=with_context)
    except EdgerunnerError as e:
        console.print(_panel(Text(str(e), style=palette.RED), name))
        return
    console.print(_panel(Text(reply), f"{name} // FIXER"))


def repl(console, with_context: bool = True) -> None:
    """Interactive CLI chat with the fixer; history kept for the session."""
    from rich.text import Text
    name = fixer_name()
    try:
        model = resolve_model()
    except EdgerunnerError as e:
        console.print(_panel(Text(str(e), style=palette.RED), name))
        return
    console.print(_panel(
        Text.from_markup(
            f"[{palette.DIM}]fixer online — [/][{palette.WHITE}]{model}[/]"
            f"[{palette.DIM}] @ {_base_url()}\nask your questions · 'q' to jack out[/]"),
        f"{name} // FIXER"))
    prompt_label = name.lower().split()[0][:12] or "fixer"
    history: list[dict] = []
    while True:
        try:
            prompt = input(f"\n{prompt_label}> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if prompt.lower() in ("q", "quit", "exit"):
            break
        if not prompt:
            continue
        try:
            # context only on the first turn; after that history carries it
            reply = ask(prompt, history=history, with_context=not history)
        except EdgerunnerError as e:
            console.print(f"[{palette.RED}]{e}[/]")
            continue
        history.append({"role": "user", "content": prompt})
        history.append({"role": "assistant", "content": reply})
        console.print(_panel(Text(reply), name))
