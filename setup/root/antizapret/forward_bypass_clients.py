#!/usr/bin/env python3
"""Validate opt-in AntiZapret clients and emit ipset restore ADD commands.

Only individual IPv4 addresses from the configured selective-client /21 are
accepted. Never place an entire VPN pool on the forwarding bypass list.
"""
import ipaddress
from pathlib import Path
import sys

SET_NAME = "antizapret-bypass"


def commands(prefix: str, source: Path) -> list[str]:
    if prefix not in ("10", "172"):
        raise ValueError("unsupported AntiZapret client prefix")
    subnet = ipaddress.IPv4Network(f"{prefix}.29.0.0/21")
    if not source.is_file():
        raise ValueError(f"missing allowlist: {source}")
    addresses = set()
    for number, raw in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
        value = raw.partition("#")[0].strip()
        if not value:
            continue
        try:
            address = ipaddress.IPv4Interface(value)
        except ValueError as exc:
            raise ValueError(f"{source}:{number}: invalid client IPv4 address") from exc
        if address.network.prefixlen != 32 or address.ip not in subnet:
            raise ValueError(
                f"{source}:{number}: only one client IPv4 address in {subnet} is allowed"
            )
        if address.ip in (subnet.network_address, subnet.broadcast_address):
            raise ValueError(f"{source}:{number}: reserved client address")
        addresses.add(address.ip)
    return [f"add {SET_NAME} {ip} -exist" for ip in sorted(addresses)]


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: forward_bypass_clients.py CLIENT_PREFIX ALLOWLIST", file=sys.stderr)
        return 2
    try:
        for command in commands(sys.argv[1], Path(sys.argv[2])):
            print(command)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"AntiZapret bypass allowlist rejected: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
