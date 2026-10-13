# Selective VPN: opt-in client egress bypass

## Why this exists

On DE, `RESTRICT_FORWARD=y` marks ordinary public destinations and drops
their packets if the destination is absent from `antizapret-forward`. When a
router mistakenly tunnels **all** traffic for an attached device, ordinary
sites (for example `ya.ru`) time out. A live test showed packets reaching
`antizapret-udp` but not leaving DE; a temporary per-client `ACCEPT`
restored HTTPS. This is a forwarding-policy mismatch, not a DuckDNS failure.

Do **not** disable `RESTRICT_FORWARD` globally or add `0.0.0.0/0` to
`config/forward-ips.txt`.

## Opt-in workaround

The new file `/root/antizapret/config/forward-bypass-clients.txt` is empty by
default. Add only the current OpenVPN IPv4 address of a client known to require
this compatibility mode:

```text
172.29.0.3/32
```

The helper validates exact IPv4 addresses within the selective OpenVPN
`172.29.0.0/21` pool (or `10.29.0.0/21` in the default installation).
The firewall uses the `antizapret-bypass` **source** ipset, excluding listed
clients from the destination restriction only. Unlike a blanket `ACCEPT`,
other `FORWARD` protections (INVALID, denied destinations, client isolation,
torrent guards) still execute. Unlisted clients are unaffected.

**This is not genuine selective routing.** Ordinary traffic that the router
tunnels is allowed to exit through DE and may have DE's public IP. Proper
selective routing requires the router/OpenVPN client to route only configured
destinations (including FakeIP `198.18.0.0/15`) through the tunnel.

## Applying on DE

First compare the live files with the repository: DE has local modifications.
Back them up. Copy the updated `up.sh`, `down.sh`,
`forward_bypass_clients.py` and default `forward-bypass-clients.txt`
into `/root/antizapret/`, **without overwriting an existing local allowlist**.
Edit only the installed allowlist to opt in the desired client IP. Do not put
local client details into this public repository.

`up.sh` runs `down.sh` and reconstructs multiple chains and WARP interfaces.
Apply it only during an explicit maintenance window with out-of-band access.
**Merely pulling this commit does not change live firewall rules.**

After restart/rebuild check:

```bash
sudo ipset test antizapret-bypass 172.29.0.3
sudo iptables -S FORWARD | grep 'antizapret-bypass'
curl -4 --max-time 10 -I https://ya.ru
```

Verify `FORWARD` does **not** retain the temporary per-client
`-j ACCEPT` inserted during diagnosis. Remove it after validating the
allowlist-aware restrict rule, otherwise it bypasses other protections.
Re-check the client address after reconnect; OpenVPN addresses can change.

## Rollback

Clear `config/forward-bypass-clients.txt` and apply the prior firewall config
during maintenance (or restore the backed-up `up.sh` and `down.sh`).
The default empty list preserves the original restrictive policy. This change
does not modify OpenVPN credentials, DNS, WARP settings or AZRelay binaries.
