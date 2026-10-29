"""Regression tests for bugs found in review. Pure logic: no root, no network needed.

Run: python -m unittest discover -s tests -p "test_*.py"
"""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["NETRUNNER_HOME"] = tempfile.mkdtemp(prefix="netrunner-test-")

from netrunner import armory, breach, config, ice, netinfo, sysinfo  # noqa: E402


class PingSweep(unittest.TestCase):
    def test_unanswered_ping_is_not_alive(self):
        # ping prints a header even when nothing answers; only the exit code says "alive"
        silent = subprocess.CompletedProcess([], 1, stdout=b"PING 10.0.0.9 56(84) bytes of data.\n", stderr=b"")
        with mock.patch.object(netinfo.subprocess, "run", return_value=silent):
            self.assertEqual(netinfo._ping_one("10.0.0.9"), ("10.0.0.9", False))

    def test_answered_ping_is_alive(self):
        ok = subprocess.CompletedProcess([], 0, stdout=b"64 bytes from 10.0.0.1", stderr=b"")
        with mock.patch.object(netinfo.subprocess, "run", return_value=ok):
            self.assertEqual(netinfo._ping_one("10.0.0.1"), ("10.0.0.1", True))


class Signals(unittest.TestCase):
    @unittest.skipIf(sys.platform == "win32", "POSIX signals")
    def test_numeric_and_named_signals(self):
        self.assertEqual(armory.parse_signal("9"), (9, "SIGKILL"))
        self.assertEqual(armory.parse_signal("kill"), (9, "SIGKILL"))
        self.assertEqual(armory.parse_signal("SIGTERM")[1], "SIGTERM")
        with self.assertRaises(armory.ActionError):
            armory.parse_signal("NOPE")


class Config(unittest.TestCase):
    def test_quotes_and_backslashes_survive_a_save(self):
        cfg = config.load()
        cfg["edgerunner_name"] = 'The "Fixer" \\ Johnny'
        config.save(cfg)
        self.assertEqual(config.load()["edgerunner_name"], 'The "Fixer" \\ Johnny')

    def test_damaged_config_falls_back_to_defaults(self):
        config.ensure_dirs()
        config.CONFIG_FILE.write_text('[netrunner]\noperator = "broken\n')
        self.assertEqual(config.load()["corp"], config.DEFAULTS["corp"])
        config.CONFIG_FILE.unlink()


class Dns(unittest.TestCase):
    def test_cname_lines_are_not_used_as_ips(self):
        self.assertEqual(netinfo.ip_records(["cdn.example.net.", "93.184.215.14", "2606:2800::1"]),
                         ["93.184.215.14", "2606:2800::1"])


class Gpu(unittest.TestCase):
    def test_several_gpus(self):
        out = "NVIDIA RTX 4090, 12, 2048, 24564\nNVIDIA RTX 4090, 3, 512, 24564\n"
        self.assertEqual(len(sysinfo.parse_gpus(out)), 2)

    def test_unavailable_memory_values(self):
        self.assertEqual(sysinfo.parse_gpus("Tesla T4, 0, [N/A], [N/A]"), ["Tesla T4 — 0%"])


class IceRating(unittest.TestCase):
    def test_more_open_ports_never_means_stronger_ice(self):
        for fw in ("ACTIVE", "UNKNOWN", "INACTIVE", "NO ICE"):
            scores = [ice.score_ice(fw, n) for n in (0, 2, 6, 20)]
            self.assertEqual(scores, sorted(scores, reverse=True), fw)

    def test_firewall_raises_the_rating(self):
        self.assertGreater(ice.score_ice("ACTIVE", 5), ice.score_ice("NO ICE", 5))

    def test_loopback_listeners_are_not_exposure(self):
        socks = [{"addr": "127.0.0.1:631"}, {"addr": "::1:631"}, {"addr": "0.0.0.0:22"}]
        self.assertEqual([s["addr"] for s in ice.exposed(socks)], ["0.0.0.0:22"])


class Armory(unittest.TestCase):
    def test_ssh_host_cannot_be_an_option(self):
        with mock.patch.object(armory.shutil, "which", return_value="/usr/bin/ssh"):
            with self.assertRaises(armory.ActionError):
                armory.remote_exec("-oProxyCommand=touch /tmp/pwned", "uptime", assume_yes=True)

    def test_partial_name_needs_force(self):
        fake = mock.Mock(pid=4242, info={"name": "sshd"})
        with mock.patch.object(armory.psutil, "process_iter", return_value=[fake]):
            with self.assertRaises(armory.ActionError) as e:
                armory.kill("ssh", assume_yes=True)
        self.assertIn("partial", str(e.exception))


class Breach(unittest.TestCase):
    def test_stray_maelstrom_bytes_exist(self):
        colors = {c.color for seed in range(20) for row in breach.BreachProtocol(seed).grid
                  for c in row if c.seq is None}
        self.assertIn("Y", colors)


if __name__ == "__main__":
    unittest.main()
