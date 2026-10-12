"""Offline regression suite for DNS -> RPZ -> Fake IP -> NAT diagnosis."""
import importlib.util
import ipaddress
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
SCRIPT = HERE / "setup/root/antizapret/diagnose-domain.py"
spec = importlib.util.spec_from_file_location("diagnose_domain", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

DNAT = """-N ANTIZAPRET-MAPPING
-A ANTIZAPRET-MAPPING -d 198.18.133.123/32 -j DNAT --to-destination 172.64.149.12
-A ANTIZAPRET-MAPPING -s 172.29.0.0/16 -d 198.18.148.86/32 -j DNAT --to-destination 104.18.99.23
-A ANTIZAPRET-MAPPING -d 198.19.44.1/32 -j RETURN
-A OTHER -d 198.18.133.123/32 -j DNAT --to-destination 8.8.8.8
-A ANTIZAPRET-MAPPING -d 198.17.0.0/16 -j DNAT --to-destination 1.1.1.1
"""


class DomainDiagnosticsTest(unittest.TestCase):
    def test_domain_validation_and_normalization(self):
        self.assertEqual(mod.normalize_name(" API.IPIFY.ORG. "), "api.ipify.org")
        self.assertTrue(mod.normalize_name("пример.рф").startswith("xn--"))
        for invalid in ("", "foo", "-bad.example.com", "*.example.org",
                        "foo..bar.net", "example.org;touch /tmp/xxx"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    mod.normalize_name(invalid)

    def test_rpz_exact_wildcard_and_unrelated(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Path(directory) / "deny.rpz"
            f.write_text(
                "$TTL 10800\n@ SOA . . (1 1 1 1 10800)\n"
                "ipify.org CNAME .\n*.ipify.org CNAME .\n"
                "notipify.org CNAME .\n*.example.net CNAME .\n"
            )
            exact = mod.rpz_matches(f, "ipify.org")
            self.assertEqual([x["owner"] for x in exact["matches"]], ["ipify.org"])
            child = mod.rpz_matches(f, "api.ipify.org")
            self.assertEqual([x["owner"] for x in child["matches"]], ["*.ipify.org"])
            self.assertFalse(mod.rpz_matches(f, "xipify.org")["matches"])
            self.assertFalse(mod.rpz_matches(f, "ipify.org.evil")["matches"])
            self.assertEqual(
                [x["owner"] for x in mod.rpz_matches(f, "foo.example.net")["matches"]],
                ["*.example.net"],
            )
            self.assertFalse(mod.rpz_matches(f, "example.net")["matches"])

    def test_nat_matches_explicit_ip_and_ignores_other_chains(self):
        mapping = mod.parse_nat_rules(
            DNAT, ["198.18.133.123", "198.18.148.86", "198.19.44.1"]
        )
        self.assertEqual(mapping["198.18.133.123"][0]["destination"], "172.64.149.12")
        self.assertEqual(mapping["198.18.148.86"][0]["destination"], "104.18.99.23")
        self.assertEqual(mapping["198.19.44.1"], [])

    def test_default_routes_and_device_template(self):
        with tempfile.TemporaryDirectory() as directory:
            f = Path(directory) / "DEFAULT"
            f.write_text(
                'push "route 198.18.0.0 255.254.0.0"\n'
                'push "route 10.224.0.0 255.254.0.0"\n'
                'route 185.149.144.143 255.255.255.255 net_gateway\n'
            )
            report = mod.read_routes(f, ["198.18.133.123", "198.19.209.219"])
            self.assertEqual(report["coverage"], {
                "198.18.133.123": True, "198.19.209.219": True
            })
            self.assertEqual(report["routes"], 3)

    def test_fake_ip_success_and_dns_zero_denial(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "antizapret"
            rpz = Path(directory) / "knot"
            (root / "result").mkdir(parents=True)
            rpz.mkdir()
            (root / "result" / "DEFAULT").write_text(
                'push "route 198.18.0.0 255.254.0.0"\n'
            )
            for name in ("deny.rpz", "proxy.rpz", "warp.rpz"):
                (rpz / name).write_text("@ SOA . . (1 1 1 1 10800)\n")
            (root / "result" / "deny.rpz").write_text(
                "@ SOA . . (1 1 1 1 10800)\n"
            )
            network = ipaddress.ip_network("198.18.0.0/15")
            with patch.object(mod, "read_dns", return_value=(
                ["198.18.133.123"], [], None
            )), patch.object(mod, "read_nat", return_value=(
                {"198.18.133.123": [{"destination": "172.64.149.12",
                                    "match": "198.18.133.123/32"}]}, None
            )):
                report = mod.diagnose("github.com", "127.1.1.1", rpz, root, network, 8)
                self.assertEqual(report["status"], "ok", report)
                self.assertTrue(report["generated_routes"]["coverage"]["198.18.133.123"])
                self.assertTrue(report["rpz_in_sync"])
            with patch.object(mod, "read_dns", return_value=(
                ["198.18.133.123"], [], None
            )), patch.object(mod, "read_nat", return_value=(
                {"198.18.133.123": []}, None
            )):
                report = mod.diagnose("github.com", "127.1.1.1", rpz, root, network, 8)
                self.assertEqual(report["status"], "issue")
                self.assertIn("no matching DNAT", report["errors"][0])
            with patch.object(mod, "read_dns", return_value=(
                ["0.0.0.0"], [], None
            )):
                report = mod.diagnose("ipify.org", "127.1.1.1", rpz, root, network, 8)
                self.assertEqual(report["status"], "issue")
                self.assertIn("0.0.0.0", " ".join(report["errors"]))

    def test_inconclusive_nat_permissions_not_reported_as_missing_mapping(self):
        with tempfile.TemporaryDirectory() as d:
            root, rpz = Path(d) / "root", Path(d) / "knot"
            (root / "result").mkdir(parents=True)
            rpz.mkdir()
            with patch.object(mod, "read_dns", return_value=(
                ["198.19.209.219"], [], None
            )), patch.object(mod, "read_nat", return_value=({}, "permission denied")):
                report = mod.diagnose(
                    "whatismyipaddress.com", "127.1.1.1", rpz, root,
                    ipaddress.ip_network("198.18.0.0/15"), 8
                )
                self.assertEqual(report["status"], "review")
                self.assertEqual(report["errors"], [])
                self.assertTrue(any("Cannot inspect NAT" in w for w in report["warnings"]))


if __name__ == "__main__":
    unittest.main()
