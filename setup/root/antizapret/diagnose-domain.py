#!/usr/bin/env python3
"""Diagnose AntiZapret DNS -> RPZ -> Fake IP -> NAT -> generated routes.

Read-only for configuration/firewall. An ordinary DNS query can populate
resolver caches and allocate Fake IP mappings in the existing DNS sidecar.
No HTTPS probe is attempted: exit-local DNS/NAT evidence cannot prove the
route accepted by a remote OpenVPN client.
"""
import argparse
import datetime as dt
import filecmp
import ipaddress
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys

VALID_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def normalize_name(value):
    name = value.strip().rstrip(".").lower()
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("invalid domain name") from exc
    labels = name.split(".")
    if len(labels) < 2 or len(name) > 253 or any(
        not VALID_LABEL.fullmatch(label) for label in labels
    ):
        raise ValueError("expected a public domain such as example.org")
    return name


def owner_matches(domain, owner):
    owner = owner.lower().rstrip(".")
    if owner == "*":
        return True
    if owner.startswith("*."):
        suffix = owner[2:]
        return domain.endswith("." + suffix)
    return domain == owner


def rpz_matches(path, domain):
    """Return only matching RPZ owners; do not pretend to evaluate Knot policy order."""
    if not path.is_file():
        return {"present": False, "matches": []}
    matched = []
    with path.open(encoding="utf-8", errors="replace") as source:
        for number, raw in enumerate(source, 1):
            fields = raw.split()
            if (
                len(fields) < 3
                or fields[0].startswith((";", "#", "$"))
                or fields[0] == "@"
                or "CNAME" not in (field.upper() for field in fields[1:3])
            ):
                continue
            if owner_matches(domain, fields[0]):
                matched.append({
                    "line": number,
                    "owner": fields[0],
                    "value": fields[-1],
                })
                if len(matched) >= 30:
                    break
    return {"present": True, "matches": matched}


def read_dns(domain, resolver, timeout):
    try:
        result = subprocess.run(
            ["dig", "+short", "+tries=1", "+time=2", "@" + resolver,
             domain, "A"],
            text=True, capture_output=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], [], str(exc)
    if result.returncode:
        return [], [], result.stderr.strip() or "dig exited " + str(result.returncode)
    addresses, aliases = [], []
    for line in result.stdout.splitlines():
        value = line.strip()
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            if value:
                aliases.append(value)
            continue
        if isinstance(ip, ipaddress.IPv4Address) and value not in addresses:
            addresses.append(value)
    return addresses, aliases, None


def parse_nat_rules(text, addresses):
    """Find explicit DNAT rules for requested Fake IP addresses."""
    mapping = {ip: [] for ip in addresses}
    for raw in text.splitlines():
        try:
            pieces = shlex.split(raw)
            if len(pieces) < 6 or pieces[0:2] != ["-A", "ANTIZAPRET-MAPPING"]:
                continue
            if "-j" not in pieces or pieces[pieces.index("-j") + 1] != "DNAT":
                continue
            dest_flag = "-d" if "-d" in pieces else "--destination"
            if dest_flag not in pieces:
                continue
            cidr = ipaddress.ip_network(pieces[pieces.index(dest_flag) + 1], strict=False)
            if not isinstance(cidr, ipaddress.IPv4Network):
                continue
            target_flag = (
                "--to-destination" if "--to-destination" in pieces else "--to"
            )
            if target_flag not in pieces:
                continue
            target = pieces[pieces.index(target_flag) + 1]
            for ip in addresses:
                if ipaddress.IPv4Address(ip) in cidr:
                    entry = {"destination": target, "match": str(cidr)}
                    if entry not in mapping[ip]:
                        mapping[ip].append(entry)
        except (ValueError, IndexError):
            continue
    return mapping


def read_nat(addresses, timeout):
    if not addresses:
        return {}, None
    try:
        result = subprocess.run(
            ["iptables", "-t", "nat", "-S", "ANTIZAPRET-MAPPING"],
            text=True, capture_output=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {}, str(exc)
    if result.returncode:
        return {}, result.stderr.strip() or "iptables failed"
    return parse_nat_rules(result.stdout, addresses), None


def read_routes(path, addresses):
    if not path.is_file():
        return {"present": False, "path": str(path), "coverage": {}}
    networks = []
    with path.open(encoding="utf-8", errors="replace") as source:
        for line in source:
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", ";")):
                continue
            try:
                parts = shlex.split(stripped)
                if len(parts) == 2 and parts[0] == "push":
                    parts = shlex.split(parts[1])
                if len(parts) < 3 or parts[0] != "route":
                    continue
                net = ipaddress.ip_network(parts[1] + "/" + parts[2], strict=False)
                if isinstance(net, ipaddress.IPv4Network):
                    networks.append(net)
            except (ValueError, IndexError):
                continue
    return {
        "present": True,
        "path": str(path),
        "routes": len(networks),
        "coverage": {
            address: any(ipaddress.IPv4Address(address) in net for net in networks)
            for address in addresses
        },
    }


def compare_generated(active, generated):
    if not active.is_file() or not generated.is_file():
        return None
    return filecmp.cmp(active, generated, shallow=False)


def diagnose(domain, resolver, rpz_dir, root, fake_network, timeout):
    report = {
        "schema_version": 1,
        "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "domain": domain,
        "resolver": resolver,
        "dns": {},
        "rpz": {},
        "nat": {},
        "generated_routes": {},
        "rpz_in_sync": None,
        "errors": [],
        "warnings": [],
        "notes": [],
    }
    addresses, aliases, dns_error = read_dns(domain, resolver, timeout)
    fake = [ip for ip in addresses if ipaddress.ip_address(ip) in fake_network]
    real = [ip for ip in addresses if ip not in fake]
    report["dns"] = {
        "addresses": addresses, "aliases": aliases,
        "fake_ips": fake, "public_or_other_ips": real, "error": dns_error,
    }
    if dns_error:
        report["errors"].append("DNS query failed; inspect Knot listener/upstreams")
    if not addresses:
        report["errors"].append("DNS returned no IPv4 addresses")
    if "0.0.0.0" in addresses:
        report["errors"].append("DNS returned 0.0.0.0 (potential explicit deny)")

    for zone in ("deny.rpz", "proxy.rpz", "warp.rpz"):
        report["rpz"][zone] = rpz_matches(rpz_dir / zone, domain)

    report["rpz_in_sync"] = compare_generated(
        rpz_dir / "deny.rpz", root / "result" / "deny.rpz"
    )
    if report["rpz_in_sync"] is False:
        report["warnings"].append("Deployed deny.rpz differs from generated file")
    if not report["rpz"]["deny.rpz"]["present"]:
        report["warnings"].append("deny.rpz missing; static policy cannot be inspected")
    if report["rpz"]["deny.rpz"]["matches"]:
        report["warnings"].append(
            "Static deny.rpz matches domain; verify rule priority against DNS answer"
        )

    if fake:
        nat, nat_error = read_nat(fake, timeout)
        report["nat"] = {"mappings": nat, "error": nat_error}
        if nat_error:
            report["warnings"].append(
                "Cannot inspect NAT mappings (use sudo on exit): " + nat_error
            )
        else:
            for ip in fake:
                if not nat.get(ip):
                    report["errors"].append("Fake IP " + ip + " has no matching DNAT rule")
    else:
        report["nat"] = {"mappings": {}, "error": None}

    report["generated_routes"] = read_routes(root / "result" / "DEFAULT", fake)
    if fake:
        route_info = report["generated_routes"]
        if not route_info["present"]:
            report["warnings"].append("Generated OpenVPN CCD DEFAULT route file missing")
        elif any(not value for value in route_info["coverage"].values()):
            report["warnings"].append("Generated OpenVPN routes do not cover some Fake IPs")

    if real and not fake:
        report["notes"].append(
            "Public A address suggests direct routing, but client routing is NOT verified"
        )
    if fake:
        report["notes"].append(
            "Fake IP and DNAT evidence is exit-local; verify client routes and HTTPS separately"
        )
    report["status"] = (
        "issue" if report["errors"] else
        "review" if report["warnings"] else "ok"
    )
    return report


def format_human(report):
    lines = [f"DOMAIN: {report['domain']}", f"STATUS: {report['status']}"]
    dns = report["dns"]
    lines.append("DNS A: " + (", ".join(dns["addresses"]) or "(none)"))
    lines.append("DNS Fake IP: " + (", ".join(dns["fake_ips"]) or "(none)"))
    for zone, evidence in report["rpz"].items():
        matches = evidence["matches"]
        desc = "not found" if not evidence["present"] else (
            ", ".join(m["owner"] + "=" + m["value"] for m in matches) or "(no matches)"
        )
        lines.append(zone + ": " + desc)
    sync = report["rpz_in_sync"]
    lines.append("Generated vs deployed deny.rpz: " + (
        "same" if sync is True else "DIFFER" if sync is False else "unknown"
    ))
    for ip, mappings in report["nat"]["mappings"].items():
        lines.append("DNAT " + ip + ": " + (
            ", ".join(entry["destination"] for entry in mappings) or "MISSING"
        ))
    if report["nat"]["error"]:
        lines.append("NAT inspection: " + report["nat"]["error"])
    coverage = report["generated_routes"]["coverage"]
    for ip, present in coverage.items():
        lines.append(f"Generated OpenVPN route for {ip}: {'yes' if present else 'NO'}")
    for field in ("errors", "warnings", "notes"):
        for message in report[field]:
            lines.append(field[:-1].upper() + ": " + message)
    return "\n".join(lines)


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("domain", help="Domain to inspect, e.g. github.com")
    cli.add_argument("--resolver", default="127.1.1.1", help="Exit Knot listener")
    cli.add_argument("--rpz-dir", type=Path, default=Path("/etc/knot-resolver"))
    cli.add_argument("--root", type=Path, default=Path("/root/antizapret"))
    cli.add_argument("--fake-cidr", default="198.18.0.0/15")
    cli.add_argument("--timeout", type=float, default=8.0)
    cli.add_argument("--json", action="store_true")
    args = cli.parse_args()
    try:
        domain = normalize_name(args.domain)
        resolver = str(ipaddress.ip_address(args.resolver))
        network = ipaddress.ip_network(args.fake_cidr, strict=True)
        if not isinstance(network, ipaddress.IPv4Network) or args.timeout <= 0:
            raise ValueError("expected IPv4 Fake IP CIDR and positive timeout")
    except ValueError as exc:
        cli.error(str(exc))
    report = diagnose(
        domain, resolver, args.rpz_dir, args.root, network, args.timeout
    )
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(format_human(report))
    return 1 if report["status"] == "issue" else 0


if __name__ == "__main__":
    sys.exit(main())
