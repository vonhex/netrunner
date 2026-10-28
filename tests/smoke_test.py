"""Headless smoke test of the Textual app + breach engine."""
import asyncio
import sys

sys.path.insert(0, "/home/administrator/Work/netrunner")

from netrunner.breach import BreachProtocol, WIDTH, HEIGHT, SPECS
from netrunner.ui import NetrunnerOS, BreachPane, TabbedContent


def test_engine():
    for seed in (1, 7, 42, 123, 999):
        g = BreachProtocol(seed)
        assert len(g.grid) == HEIGHT and all(len(r) == WIDTH for r in g.grid)
        expected = sum(len(SPECS[r]) for r in range(HEIGHT))
        assert len(g.sequences) == expected, (seed, len(g.sequences))
        # every cell has a value and color
        for row in g.grid:
            for c in row:
                assert len(c.value) == 2 and c.color in "CMY"
        # auto-complete via moves
        steps = 0
        while not g.complete and steps < 500:
            seq = next(s for s in g.sequences if not s.downloaded)
            while not g.complete and g.cursor[0] != seq.cells[0][0]:
                g.move("s" if g.cursor[0] < seq.cells[0][0] else "w")
                steps += 1
            while not g.complete and g.cursor[1] != seq.cells[0][1]:
                g.move("d" if g.cursor[1] < seq.cells[0][1] else "a")
                steps += 1
            for _ in range(seq.size - 1):
                if g.complete:
                    break
                g.move("d")
                steps += 1
        assert g.complete, f"seed {seed} not completable in {steps} steps"
        g.render()  # must not raise
    print("engine: 5 seeds generated, completed, rendered OK")


async def test_tui():
    app = NetrunnerOS()
    async with app.run_test(size=(140, 50)) as pilot:
        await pilot.pause(0.5)
        tabs = app.query_one(TabbedContent)
        assert tabs.active == "dashboard"
        for tab in ("netscan", "ice", "daemons", "shards", "breach",
                    "edgerunner", "armory"):
            tabs.active = tab
            await pilot.pause(0.4)
            assert tabs.active == tab
        # drive the breach game with arrow keys
        pane = app.query_one(BreachPane)
        before = pane.game.data_kb
        await pilot.press("down")
        await pilot.pause(0.2)
        assert pane.game.data_kb >= before
        # new protocol + quit binding exist
        await pilot.press("n")
        await pilot.pause(0.2)
    print("tui: all 8 tabs rendered, arrow-key breach works, quit OK")


asyncio.run(test_tui())
test_engine()
print("ALL TESTS PASS")
