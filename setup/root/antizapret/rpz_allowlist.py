#!/usr/bin/env python3
"""Filter explicit RPZ denials using an operator-owned domain allowlist.

This is a pre-publication build step, not a DNS server or a passthrough policy.
Removing both DENY and rpz-passthru rules for selected domains allows the
subsequent AntiZapret proxy.rpz policy to install Fake IP routing.
"""
import argparse
import re
import sys
from pathlib import Path

LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def canonical(domain):
    return domain.lower().rstrip(".")


def read_allowlist(path):
    allowed = set()
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        value = canonical(line.split("#", 1)[0].strip())
        if not value:
            continue
        labels = value.split(".")
        if (
            len(labels) < 2
            or len(value) > 253
            or any(not LABEL.fullmatch(part) for part in labels)
        ):
            raise ValueError(f"{path}:{number}: invalid domain {value!r}; use ASCII/Punycode names without wildcards")
        allowed.add(value)
    return allowed


def matches(name, domain):
    return name == domain or name.endswith("." + domain)


def filter_rpz(content, allowed):
    result = []
    removed = 0
    for number, line in enumerate(content.splitlines(keepends=True), 1):
        fields = line.split()
        if len(fields) < 3 or fields[0].startswith((";", "#", "$")) or fields[0] == "@":
            result.append(line)
            continue

        owner = canonical(fields[0])
        wildcard = owner.startswith("*.")
        name = owner[2:] if wildcard else owner

        # A wildcard on a parent would still deny an allowed child. Do not
        # silently weaken the entire parent domain or claim an exception works.
        if wildcard:
            for domain in allowed:
                if domain != name and domain.endswith("." + name):
                    raise ValueError(
                        f"RPZ line {number}: {fields[0]!r} covers allowed {domain!r}; "
                        "narrow the parent wildcard manually"
                    )

        if any(matches(name, domain) for domain in allowed):
            removed += 1
            continue
        result.append(line)
    return "".join(result), removed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allowlist", type=Path, required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.input == args.output:
        parser.error("--input and --output must be different")

    try:
        allowed = read_allowlist(args.allowlist)
        content = args.input.read_text(encoding="utf-8")
        filtered, removed = filter_rpz(content, allowed)
        # No output is created on invalid config or unsupported parent wildcard.
        args.output.write_text(filtered, encoding="utf-8")
    except (OSError, UnicodeError, ValueError) as exc:
        parser.exit(2, f"RPZ allowlist error: {exc}\n")

    print(
        f"RPZ allowlist: {len(allowed)} domains, removed {removed} records",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
