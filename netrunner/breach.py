"""Breach Protocol — the Cyberpunk 2077 minigame, fully playable.

The buffer is a 6x8 grid of bytes. Each byte has a hex value and a color:
  C (cyan)    — data
  M (magenta) — malware    (downloads attach a malware subroutine)
  Y (yellow)  — data maelstrom (costs integrity when executed)

Row layout follows the game's protocol tables:
  row 0: one 2-byte + one 3-byte sequence
  row 1: one 3-byte sequence
  rows 2-3: one 3-byte + one 4-byte sequence
  rows 4-5: one 5-byte sequence

Junk bytes between sequences are mostly data, with the odd stray maelstrom byte
(yellow) that costs integrity when stepped on.

The netrunner moves the cursor one byte at a time (WASD / arrows). Stepping
onto an undownloaded sequence executes the whole sequence. Breach completes
when every sequence in the buffer has been downloaded.
"""

from __future__ import annotations

import random
import time

from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import palette
from .palette import BYTE_STYLES

WIDTH, HEIGHT = 8, 6
SPECS = {0: [2, 3], 1: [3], 2: [3, 4], 3: [3, 4], 4: [5], 5: [5]}

PROTOCOL_NAMES = [
    "ICEPICK", "MANTIS", "WINTERFROST", "BULLFROG", "COLD BLOOD",
    "MAELSTROM", "NIGHT WIND", "BLACK ICE", "SINGULARITY", "FLATLINE",
    "MAKO", "WHISPER", "THOR'S HAMMER", "DAEDALUS", "SILENT RIVER",
]

MOVES = {
    "w": (-1, 0), "up": (-1, 0),
    "s": (1, 0), "down": (1, 0),
    "a": (0, -1), "left": (0, -1),
    "d": (0, 1), "right": (0, 1),
}


class Cell:
    __slots__ = ("value", "color", "seq")

    def __init__(self, value: str, color: str, seq=None):
        self.value = value
        self.color = color
        self.seq = seq


class Sequence:
    __slots__ = ("cells", "value", "color", "size", "downloaded")

    def __init__(self, row: int, col: int, size: int, value: str, color: str):
        self.cells = [(row, col + i) for i in range(size)]
        self.value = value
        self.color = color
        self.size = size
        self.downloaded = False


class BreachProtocol:
    """Full game engine: generation, movement, execution, completion."""

    def __init__(self, seed: int | None = None):
        self.rng = random.Random(seed)
        self.name = self.rng.choice(PROTOCOL_NAMES)
        self.grid: list[list[Cell]] = []
        self.sequences: list[Sequence] = []
        self.cursor = [0, 0]
        self.data_kb = 0
        self.integrity = 100
        self.malware: list[str] = []
        self.log: list[str] = []
        self._generate()

    # ------------------------------------------------------------ generation

    def _unique_hex(self, used: set[str]) -> str:
        while True:
            v = f"{self.rng.randrange(256):02X}"
            if v not in used:
                used.add(v)
                return v

    def _spread(self, total: int, k: int) -> list[int]:
        """Distribute `total` empty slots across k gaps (stars and bars)."""
        if k == 1:
            return [total]
        cuts = sorted(self.rng.sample(range(total + k - 1), k - 1))
        parts, prev = [], -1
        for c in cuts:
            parts.append(c - prev - 1)
            prev = c
        parts.append(total + k - 2 - prev)
        return parts

    def _pick_seq_color(self) -> str:
        return self.rng.choices("CMY", weights=[72, 16, 12])[0]

    def _generate(self) -> None:
        used: set[str] = set()
        for row in range(HEIGHT):
            sizes = SPECS[row]
            gaps = WIDTH - sum(sizes)
            parts = self._spread(gaps, len(sizes) + 1)
            row_cells: list[Cell | None] = [None] * WIDTH
            col = 0
            for i, size in enumerate(sizes):
                col += parts[i]
                value = self._unique_hex(used)
                color = self._pick_seq_color()
                seq = Sequence(row, col, size, value, color)
                for c in range(col, col + size):
                    row_cells[c] = Cell(value, color, seq)
                self.sequences.append(seq)
                col += size
            # fill remaining cells with junk data (never matching a neighbor)
            for c in range(WIDTH):
                if row_cells[c] is not None:
                    continue
                forbidden = set()
                for nb in (row_cells[c - 1] if c > 0 else None,
                           row_cells[c + 1] if c + 1 < WIDTH else None):
                    if nb is not None:
                        forbidden.add(nb.value)
                v = f"{self.rng.randrange(256):02X}"
                while v in forbidden:
                    v = f"{self.rng.randrange(256):02X}"
                row_cells[c] = Cell(v, "Y" if self.rng.random() < 0.1 else "C")  # ~1 in 10 is maelstrom
            self.grid.append(row_cells)  # type: ignore[arg-type]

    # ------------------------------------------------------------- gameplay

    @property
    def complete(self) -> bool:
        return all(s.downloaded for s in self.sequences)

    def move(self, direction: str) -> str:
        """Move the cursor one byte; executing whatever it lands on."""
        if self.complete:
            return "protocol already complete — jack out"
        if direction not in MOVES:
            return f"invalid move: {direction}"
        dr, dc = MOVES[direction]
        r, c = self.cursor[0] + dr, self.cursor[1] + dc
        if not (0 <= r < HEIGHT and 0 <= c < WIDTH):
            return "buffer edge — no further movement"
        self.cursor = [r, c]
        cell = self.grid[r][c]
        if cell.seq is not None and not cell.seq.downloaded:
            seq = cell.seq
            seq.downloaded = True
            self.data_kb += seq.size * 4
            if seq.color == "M":
                self.malware.append(f"{seq.value} ({seq.size}B)")
                msg = (f"executed [magenta]{seq.value}[/] — {seq.size}-byte "
                       f"malware sequence downloaded, subroutine attached")
            elif seq.color == "Y":
                self.integrity = max(0, self.integrity - 10)
                msg = (f"executed [yellow]{seq.value}[/] — {seq.size}-byte maelstrom "
                       f"sequence, -10 integrity")
            else:
                msg = f"executed [bright_cyan]{seq.value}[/] — {seq.size}-byte sequence downloaded"
            self.log.append(f"r{r}c{c}: {seq.value} downloaded")
            if self.complete:
                msg += " — [bold green]PROTOCOL COMPLETE[/]"
            return msg
        if cell.color == "Y":
            self.integrity = max(0, self.integrity - 5)
            return f"executed [yellow]{cell.value}[/] — stray maelstrom byte, -5 integrity"
        return f"executed [bright_cyan]{cell.value}[/] — junk data"

    # -------------------------------------------------------------- render

    def render(self) -> Panel:
        from rich.console import Group

        t = Table(box=box.SIMPLE_HEAVY, expand=False, padding=(0, 0))
        for c in range(WIDTH):
            t.add_column(justify="center", width=4)
        for r in range(HEIGHT):
            cells = []
            for c in range(WIDTH):
                cell = self.grid[r][c]
                txt = Text(f" {cell.value} ", style=BYTE_STYLES[cell.color])
                if cell.seq is not None and cell.seq.downloaded:
                    txt.stylize("dim")
                if [r, c] == self.cursor:
                    txt.stylize("reverse")
                cells.append(txt)
            t.add_row(*cells)

        done = sum(1 for s in self.sequences if s.downloaded)
        status = Text.assemble(
            ("PROTOCOL: ", palette.DIM), (self.name, f"{palette.WHITE} bold"),
            ("   DATA: ", palette.DIM), (f"{self.data_kb}KB", palette.CYAN),
            ("   INTEGRITY: ", palette.DIM),
            (f"{self.integrity}%", palette.RED if self.integrity < 100 else palette.GREEN),
            ("   SEQUENCES: ", palette.DIM),
            (f"{done}/{len(self.sequences)}", palette.MAGENTA),
            ("   MALWARE: ", palette.DIM),
            (", ".join(self.malware) or "—", palette.MAGENTA),
        )
        body = Group(status, t, Text.from_markup(
            "[bold green]◆ PROTOCOL COMPLETE — BUFFER CLEARED ◆[/]" if self.complete
            else "[dim]WASD / arrow keys to move · q to jack out[/]"))
        title = "BREACH PROTOCOL" if not self.complete else "BREACH PROTOCOL — COMPLETE"
        border = palette.GREEN if self.complete else palette.MAGENTA
        return Panel(body, title=f"[{border}]{title}[/]", border_style=border)


# --------------------------------------------------------------- front-ends

def play(console, seed: int | None = None) -> None:
    """Interactive CLI game loop."""
    game = BreachProtocol(seed)
    while True:
        console.clear()
        console.print(game.render())
        try:
            key = input("move (w/a/s/d or arrows), q to jack out: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break
        if key in ("q", "quit", "exit"):
            break
        if not key:
            continue
        result = game.move(key)
        console.clear()
        console.print(game.render())
        console.print(f"\n> {result}")
        time.sleep(0.4)


def demo(console, seed: int | None = None, delay: float = 0.35, max_steps: int = 200) -> None:
    """Auto-play: the deck routes the cursor through every sequence."""
    game = BreachProtocol(seed)
    console.print(game.render())
    steps = 0
    while not game.complete and steps < max_steps:
        seq = next(s for s in game.sequences if not s.downloaded)
        target = seq.cells[0]
        # route vertically, then horizontally to the sequence start
        while not game.complete and game.cursor[0] != target[0]:
            game.move("s" if game.cursor[0] < target[0] else "w")
            steps += 1
        while not game.complete and game.cursor[1] != target[1]:
            game.move("d" if game.cursor[1] < target[1] else "a")
            steps += 1
        # walk the sequence itself
        for _ in range(seq.size - 1):
            if game.complete:
                break
            game.move("d")
            steps += 1
        console.print(game.render())
        if delay and __import__("sys").stdout.isatty():
            time.sleep(delay)
    console.print(f"\n[bold green]BREACH COMPLETE[/] — {game.data_kb}KB extracted, "
                  f"integrity {game.integrity}%, malware: {', '.join(game.malware) or 'none'}")
