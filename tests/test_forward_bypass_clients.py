"""Regression tests for opt-in selective-client forwarding bypass."""
from pathlib import Path
import importlib.util
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "setup/root/antizapret/forward_bypass_clients.py"
spec = importlib.util.spec_from_file_location("forward_bypass_clients", MODULE)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class BypassRulesTest(unittest.TestCase):
    def parse(self, text, prefix="172"):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "allow.txt"
            file.write_text(text)
            return policy.commands(prefix, file)

    def test_default_empty_list_means_no_bypass(self):
        self.assertEqual(self.parse("# no bypass\n"), [])

    def test_deduplicate_and_serialize_exact_client_addresses(self):
        self.assertEqual(self.parse("# selective\n172.29.0.3/32\n172.29.0.2\n172.29.0.3 # repeated\n"), [
            "add antizapret-bypass 172.29.0.2 -exist",
            "add antizapret-bypass 172.29.0.3 -exist",
        ])

    def test_10_prefix(self):
        self.assertEqual(self.parse("10.29.0.3\n", "10"), [
            "add antizapret-bypass 10.29.0.3 -exist"
        ])

    def test_disallow_ranges_other_subnets_and_injection(self):
        for value in (
            "172.29.0.0/21", "172.29.0.3/24", "172.29.8.3",
            "192.168.0.3", "172.29.0.3;flush", "172.29.0.0", "172.29.7.255"
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.parse(value)

    def test_bad_config_rejected_without_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "allow.txt"
            file.write_text("172.29.0.3\n172.29.0.0/21\n")
            res = subprocess.run(
                [sys.executable, str(MODULE), "172", str(file)],
                capture_output=True, text=True,
            )
            self.assertEqual(res.returncode, 2)
            self.assertEqual(res.stdout, "")

    def test_missing_config_fails_closed(self):
        with self.assertRaises(ValueError):
            policy.commands("172", Path("/no/such/file"))

    def test_rules_are_reversible_and_do_not_accept_unconditionally(self):
        up = (ROOT / "setup/root/antizapret/up.sh").read_text()
        down = (ROOT / "setup/root/antizapret/down.sh").read_text()
        needle = "-m set ! --match-set antizapret-bypass src -j DROP"
        self.assertIn(needle, up)
        self.assertIn(needle, down)
        self.assertIn("python3 ./forward_bypass_clients.py", up)
        self.assertIn("flush antizapret-bypass", up)
        self.assertIn("pre-migration restrict rule", down)


if __name__ == "__main__":
    unittest.main()
