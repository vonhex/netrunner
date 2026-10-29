"""NETRUNNER//OS — color system.

Cyberdeck palette: bodyware cyan, quickhack magenta, maelstrom yellow.
"""

CYAN = "bright_cyan"
MAGENTA = "magenta"
YELLOW = "yellow"
RED = "red"
GREEN = "green"
BLUE = "blue"
DIM = "grey37"
WHITE = "white"

# Cyberpunk ICE classification tiers (weakest -> strongest defense; see ice.score_ice)
ICE_TIERS = [
    ("White", "white"),
    ("Green", "green"),
    ("Blue", "blue"),
    ("Yellow", "yellow"),
    ("Cyan", "bright_cyan"),
    ("Magenta", "magenta"),
    ("Red", "red"),
    ("Black", "grey58"),
    ("Gold", "yellow"),
    ("Violet", "purple"),
]

# Byte colors used by the Breach Protocol buffer
BYTE_STYLES = {"C": CYAN, "M": MAGENTA, "Y": YELLOW}


def gauge_color(pct: int) -> str:
    """Pick a gauge color from a percentage."""
    if pct >= 90:
        return RED
    if pct >= 75:
        return YELLOW
    return CYAN


def bar(pct: float, width: int = 24, style: str | None = None) -> str:
    """Render a cyberdeck-style gauge bar, e.g. ███████░░░░░ 58%."""
    pct = max(0.0, min(100.0, float(pct)))
    n = round(pct / 100 * width)
    style = style or gauge_color(int(pct))
    return (
        f"[{style}]{'█' * n}[/]"
        f"[{DIM}]{'░' * (width - n)}[/]"
        f" [{style}]{pct:5.1f}%[/]"
    )


def kv(key: str, value: str, key_style: str = DIM, value_style: str = CYAN) -> str:
    """A dim label + bright value line."""
    return f"[{key_style}]{key:<14}[/][{value_style}]{value}[/]"
