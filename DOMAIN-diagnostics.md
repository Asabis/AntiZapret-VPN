# GP-03: Domain / Fake IP / NAT / route diagnostics

A **read-only configuration inspector** for AntiZapret exit servers.
Applicable to all standard OpenVPN clients, not only to TP-Link.

## Install only the new diagnostic script

GP-03 does not change OpenVPN, Knot, AZRelay, firewall rules or routing.

On a DE/US exit using a trusted clone/checkout of this private repository:

    install -m 0755 setup/root/antizapret/diagnose-domain.py \
      /root/antizapret/diagnose-domain.py

Do **not** blindly replace customized parse.sh or restart WARP. This tool
is independent of the GP-01 generator. Its dependencies are Python 3
standard library, dig, iptables and existing AntiZapret outputs.

## Examples (run on exit, with sudo)

    cd /root/antizapret
    sudo python3 diagnose-domain.py github.com
    sudo python3 diagnose-domain.py api.ipify.org --json
    sudo python3 diagnose-domain.py ya.ru
    sudo python3 diagnose-domain.py whatismyipaddress.com

Optional paths: --root, --rpz-dir, --resolver, --fake-cidr, --timeout,
--ccd-file (active OpenVPN route file path, default
/etc/openvpn/server/ccd/DEFAULT).
JSON output has schema_version=1 and stable top-level statuses:
ok | review | issue.

Run it **only on exit**. RU AZRelay forwards encrypted OpenVPN packets
and cannot inspect DNS or NAT inside those packets.

## What it checks

1. Domain validation and DNS A answers from the selected local Knot
   listener (default 127.1.1.1). IPv4 A records are classified as
   Fake IP (default 198.18.0.0/15) vs other.
2. Static matching records in /etc/knot-resolver/{deny,proxy,warp}.rpz.
   Wildcards and exact owners are matched against the queried name.
3. Byte-for-byte comparison of active deny.rpz and generated
   /root/antizapret/result/deny.rpz (when both exist).
4. Existing DNAT rules from iptables -t nat -S ANTIZAPRET-MAPPING for
   **each** returned Fake IP. Missing mappings are reported as issues.
5. Coverage of each returned Fake IP by the **active** OpenVPN CCD
   /etc/openvpn/server/ccd/DEFAULT and, when present, the temporary
   generated /root/antizapret/result/DEFAULT for drift comparison.
   The script checks the file content, not OpenVPN's in-memory route state.
   Check that your OpenVPN instance actually uses the configured CCD directory.

The tool prints only rules relevant to the requested domain/IPs.
It doesn't print private VPN configuration, certificates, client IPs
or the complete DNS blocklists.

## Interpret the output carefully

- **ok:** the checked DNS / route-template / NAT prerequisites look
  consistent, **not** proof of OpenVPN client routing or HTTPS success.
- **review:** incomplete evidence such as insufficient permissions to
  inspect iptables, missing active CCD (or absent Fake IP route in it), stale RPZ or
  conflicting static rules. Avoid assuming the site is unreachable.
- **issue:** zero A answer (0.0.0.0), a DNS query failure, or a returned
  Fake IP without corresponding DNAT rules.
- Public A without Fake IP may mean *intended* direct routing.
  This tool cannot prove a specific client's route priority or NAT egress.
- Static RPZ match is evidence, not effective policy precedence; Knot
  Lua modules and upstream resolver state can alter the result.
- DNS queries can fill caches and allocate fake mappings: no persistent
  configuration is changed, but this is not a packet-capture-only tool.
- DNAT *rule presence* doesn't prove traffic counters or TLS access.
- Running `./parse.sh hosts` deletes/rebuilds `result/` without creating
  `result/DEFAULT`. Its absence is expected after a DNS-only regeneration
  and is **not** a warning when the active CCD file is present and covers
  the Fake IP. The inspector uses the active CCD as primary evidence.
- An active CCD file is still **not proof** that a router/desktop accepted
  pushed routes. Routers such as TP-Link may require local `.ovpn` routes.
  Verify on the client; the tool cannot introspect its installed route table.
- If an installation uses a nonstandard CCD directory, pass `--ccd-file`
  explicitly after verifying the server configuration.

This script does not test connectivity to a website, doesn't bypass
the network restrictions and does not restart/reconfigure anything.

## Regression testing

    python3 -m unittest discover -s tests -v

Tests cover domain/wildcard matching, overlapping domains, IDN/invalid
inputs, IP mapping parsing, route-template coverage, stale RPZ, missing
DNAT and permission-denied results. CI runs the suite on every PR.

## Dependency: full end-to-end check

For RU AZRelay and client layer use:
https://github.com/Asabis/proxy-openvpn/blob/main/docs/E2E_RUNBOOK.md

The full test is: client route/DNS -> RU AZRelay -> exit OpenVPN
authenticated session -> exit DNS/Fake IP/NAT -> actual HTTPS egress.
