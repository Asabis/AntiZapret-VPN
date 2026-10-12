"""Regressions for the persistent AntiZapret RPZ allowlist."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "setup/root/antizapret/rpz_allowlist.py"

RPZ = """$TTL 10800
@ SOA . . (1 1 1 1 10800)
ipify.org CNAME .
*.ipify.org CNAME .
api.ipify.org CNAME .
whatismyipaddress.com CNAME .
*.whatismyipaddress.com CNAME .
whatismyipaddress.net CNAME .
*.whatismyipaddress.net CNAME .
example.net CNAME .
*.example.net CNAME .
notipify.org CNAME .
ipify.org.evil.test CNAME .
ipify.org CNAME rpz-passthru.
*.ipify.org CNAME rpz-passthru.
"""


class RPZAllowlistTest(unittest.TestCase):
    def invoke(self, exclusions, records=RPZ, output_text=None):
        with tempfile.TemporaryDirectory() as work:
            directory = Path(work)
            allow = directory / "allow.txt"
            source = directory / "input.rpz"
            target = directory / "output.rpz"
            allow.write_text(exclusions, encoding="utf-8")
            source.write_text(records, encoding="utf-8")
            if output_text is not None:
                target.write_text(output_text, encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(SCRIPT), "--allowlist", str(allow),
                 "--input", str(source), "--output", str(target)],
                capture_output=True, text=True, check=False,
            )
            output = target.read_text(encoding="utf-8") if target.exists() else None
            return proc, output

    def test_explicit_and_wildcards_filtered_without_weaken_other_denies(self):
        proc, output = self.invoke(
            "# DNS monitoring services\nipify.org\nwhatismyipaddress.com\n"
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for record in ("ipify.org CNAME", "*.ipify.org CNAME",
                       "api.ipify.org CNAME", "whatismyipaddress.com CNAME",
                       "*.whatismyipaddress.com CNAME"):
            self.assertNotIn(record, output)
        for record in ("example.net CNAME .", "*.example.net CNAME .",
                       "notipify.org CNAME .", "ipify.org.evil.test CNAME .",
                       "whatismyipaddress.net CNAME ."):
            self.assertIn(record, output)
        self.assertIn("removed 7 records", proc.stderr)

    def test_case_trailing_dot_and_duplicate_allowlist(self):
        proc, output = self.invoke(
            "IPIFY.ORG.\nipify.org\n", "ipify.org. CNAME .\n*.IPIFY.ORG. CNAME .\nexample.com CNAME .\n"
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(output, "example.com CNAME .\n")
        self.assertIn("1 domains", proc.stderr)

    def test_no_allowlist_keeps_input_byte_for_byte(self):
        proc, output = self.invoke("# empty\n\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(output, RPZ)

    def test_subdomain_only_does_not_disable_parent(self):
        proc, output = self.invoke("api.ipify.org\n")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("ipify.org CNAME .", output)
        self.assertNotIn("api.ipify.org CNAME .", output)

    def test_invalid_allowlist_fails_without_overwriting(self):
        for invalid in ("*.ipify.org\n", "com\n", "bad..example.com\n", "../danger\n"):
            with self.subTest(invalid=invalid):
                proc, output = self.invoke(invalid, output_text="untouched")
                self.assertNotEqual(proc.returncode, 0)
                self.assertEqual(output, "untouched")

    def test_parent_wildcard_fails_closed_without_overwriting(self):
        proc, output = self.invoke(
            "api.ipify.org\n", "*.ipify.org CNAME .\napi.ipify.org CNAME .\n",
            output_text="untouched",
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(output, "untouched")
        self.assertIn("covers allowed", proc.stderr)

    def test_repeat_build_is_deterministic(self):
        proc1, output1 = self.invoke("ipify.org\nwhatismyipaddress.com\n")
        proc2, output2 = self.invoke("ipify.org\nwhatismyipaddress.com\n", output1)
        self.assertEqual((proc1.returncode, proc2.returncode), (0, 0))
        self.assertEqual(output1, output2)


if __name__ == "__main__":
    unittest.main()
