"""NETRUNNER//OS — interactive Textual TUI.

Eight tabs: DASHBOARD · NETSCAN · ICE · DAEMONS · SHARDS · BREACH · EDGERUNNER
· ARMORY. Keys: 1-8 switch tabs, arrows/WASD drive the Breach Protocol, n
starts a new protocol, q jacks out.
"""

from __future__ import annotations

from rich.console import Group
from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.widgets import Footer, Input, RichLog, Static, TabbedContent, TabPane

from . import armory, banner, daemons, edgerunner, ice, netinfo, palette, shards, sysinfo
from .breach import BreachProtocol


class AutoRefresh(Static):
    """Static widget that rebuilds its content on a timer — only while its tab is visible.

    Building runs in a worker thread (probes shell out to systemctl, journalctl, sudo -n…),
    so a slow probe never freezes the TUI, and hidden tabs cost nothing.
    """

    INTERVAL = 5.0

    def on_mount(self) -> None:
        self.update(Text("jacking in…", style=palette.DIM))
        self.refresh_view()
        self.set_interval(self.INTERVAL, self.refresh_view)

    def is_visible_tab(self) -> bool:
        pane = next((a for a in self.ancestors if isinstance(a, TabPane)), None)
        try:
            return pane is None or self.app.query_one(TabbedContent).active == pane.id
        except Exception:  # noqa: BLE001 — during startup/shutdown
            return False

    def refresh_view(self) -> None:
        if self.is_visible_tab():
            self._build_in_background()

    @work(thread=True, exclusive=True, group="refresh")
    def _build_in_background(self) -> None:
        try:
            view = self.build_view()
        except Exception as exc:  # keep the app alive on data glitches
            view = Text(f"render error: {exc}", style="red")
        self.app.call_from_thread(self.update, view)

    def build_view(self):
        raise NotImplementedError


class DashboardPane(AutoRefresh):
    INTERVAL = 2.0

    def build_view(self):
        return Group(banner.render_banner(), sysinfo.build())


class NetscanPane(AutoRefresh):
    INTERVAL = 5.0

    def build_view(self):
        return Group(netinfo.build_interfaces(), netinfo.build_arp())


class IcePane(AutoRefresh):
    INTERVAL = 5.0

    def build_view(self):
        return ice.build()


class DaemonsPane(AutoRefresh):
    INTERVAL = 10.0

    def build_view(self):
        return daemons.build()


class ShardsPane(AutoRefresh):
    INTERVAL = 10.0

    def build_view(self):
        return shards.build(30)


class ArmoryPane(AutoRefresh):
    INTERVAL = 5.0

    def build_view(self):
        return armory.build()


class BreachPane(Static):
    """Live Breach Protocol board — driven by app-level key bindings."""

    def __init__(self) -> None:
        super().__init__()
        self.game = BreachProtocol()

    def on_mount(self) -> None:
        self.update(self.game.render())

    def move(self, direction: str) -> None:
        self.game.move(direction)
        self.update(self.game.render())

    def new_protocol(self) -> None:
        self.game = BreachProtocol()
        self.update(self.game.render())


class EdgerunnerPane(Vertical):
    """EDGERUNNER — interactive chat with the deck's local AI fixer.

    Network calls run in worker threads so the TUI never freezes while the
    fixer is thinking; replies are written back on the UI thread.
    """

    def __init__(self) -> None:
        super().__init__()
        self.history: list[dict] = []
        self.fixer = edgerunner.fixer_name()
        self.feed = RichLog(wrap=True, markup=False, highlight=False, id="er-feed")
        self.box = Input(placeholder=f"ask {self.fixer}…  (Enter to send)", id="er-input")

    def compose(self) -> ComposeResult:
        yield self.feed
        yield self.box

    def on_mount(self) -> None:
        self.feed.write(Text(f"{self.fixer} // FIXER — local AI netrunning assist",
                             style=f"{palette.MAGENTA} bold"))
        self.feed.write(Text("connecting to fixer…", style=palette.DIM))
        self._greet()

    @work(thread=True, exclusive=True, group="edgerunner-greet")
    def _greet(self) -> None:
        try:
            msg = f"fixer online — {edgerunner.resolve_model()} @ {edgerunner._base_url()}"
            style = palette.GREEN
        except edgerunner.EdgerunnerError as exc:
            msg, style = str(exc), palette.RED
        self.app.call_from_thread(self.feed.write, Text(msg, style=style))

    def on_input_submitted(self, event: Input.Submitted) -> None:
        prompt = event.value.strip()
        if not prompt:
            return
        self.box.value = ""
        self.feed.write(Text(f"\n▸ {prompt}", style=f"{palette.CYAN} bold"))
        self.feed.write(Text(f"{self.fixer} is thinking…", style=palette.DIM))
        self._ask(prompt)

    @work(thread=True, group="edgerunner-ask")
    def _ask(self, prompt: str) -> None:
        try:
            reply = edgerunner.ask(prompt, history=list(self.history),
                                   with_context=not self.history)
            self.history.append({"role": "user", "content": prompt})
            self.history.append({"role": "assistant", "content": reply})
            out = Text(reply, style=palette.WHITE)
        except edgerunner.EdgerunnerError as exc:
            out = Text(str(exc), style=palette.RED)
        self.app.call_from_thread(self.feed.write, out)


class NetrunnerOS(App):
    """NETRUNNER//OS — the deck's operating system."""

    TITLE = "NETRUNNER//OS"

    CSS = """
    Screen {
        background: #0a0a12;
    }
    TabbedContent {
        height: 1fr;
    }
    TabPane {
        padding: 1 2;
    }
    Static {
        width: 1fr;
    }
    #er-feed {
        height: 1fr;
        border: round $panel;
        padding: 0 1;
    }
    #er-input {
        dock: bottom;
        border: round $panel;
    }
    """

    BINDINGS = [
        ("q", "quit", "Jack out"),
        ("1", "show_tab('dashboard')"),
        ("2", "show_tab('netscan')"),
        ("3", "show_tab('ice')"),
        ("4", "show_tab('daemons')"),
        ("5", "show_tab('shards')"),
        ("6", "show_tab('breach')"),
        ("7", "show_tab('edgerunner')"),
        ("8", "show_tab('armory')"),
        ("up", "move('up')"),
        ("down", "move('down')"),
        ("left", "move('left')"),
        ("right", "move('right')"),
        ("w", "move('up')"),
        ("s", "move('down')"),
        ("a", "move('left')"),
        ("d", "move('right')"),
        ("n", "new_protocol()"),
    ]

    def compose(self) -> ComposeResult:
        with TabbedContent(initial="dashboard"):
            with TabPane("Dashboard", id="dashboard"):
                yield DashboardPane()
            with TabPane("Netscan", id="netscan"):
                yield NetscanPane()
            with TabPane("ICE", id="ice"):
                yield IcePane()
            with TabPane("Daemons", id="daemons"):
                yield DaemonsPane()
            with TabPane("Shards", id="shards"):
                yield ShardsPane()
            with TabPane("Breach", id="breach"):
                yield BreachPane()
            with TabPane(edgerunner.fixer_name().title(), id="edgerunner"):
                yield EdgerunnerPane()
            with TabPane("Armory", id="armory"):
                yield ArmoryPane()
        yield Footer()

    def action_show_tab(self, tab_id: str) -> None:
        self.query_one(TabbedContent).active = tab_id

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        # hidden tabs don't refresh, so bring the newly shown one up to date straight away
        for pane in event.pane.query(AutoRefresh):
            pane.refresh_view()

    def action_move(self, direction: str) -> None:
        if self.query_one(TabbedContent).active == "breach":
            self.query_one(BreachPane).move(direction)

    def action_new_protocol(self) -> None:
        if self.query_one(TabbedContent).active == "breach":
            self.query_one(BreachPane).new_protocol()


def run() -> None:
    NetrunnerOS().run()
