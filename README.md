# nostrhost-control

The NostrHost **control plane**: a local, loopback-only Nostr relay that is
the internal event bus for the [nostrhost](../) Nostr-native YunoHost
derivative. Identity, policy, approval, execution, catalogue and audit state
flow through it as signed events.

The relay engine is **khatru** (the standard Nostr relay framework) — NIP-01
WebSocket handling, NIP-42 AUTH, NIP-77 negentropy and the NIP-86 management
dispatch are provided by the framework. NostrHost adds:

- **event-model validation** for the NostrHost custom kinds (`EVENT-PROTOCOL.md`)
- **local access policy** (allow/ban pubkeys, kind allow/deny, IP blocks, admins)
- **NIP-42 auth** for protected (control-plane) kinds
- **per-kind retention** (immutable audit chain, replaceable definitions,
  prunable request records)
- **NIP-86 relay management** backed by a durable policy store
- **NIP-77 negentropy** for state sync (enabled)

## Quick start

```
go build ./cmd/nostrhost-control
cp config.example.toml config.toml    # set operator_pubkey (hex)
./nostrhost-control -config config.toml
```

The relay listens on `ws://127.0.0.1:4848` by default.

## Layout

```
cmd/nostrhost-control/   entry point (the relay)
cmd/nostrhost-notify/    entry point (the notification service)
internal/relay/          khatru relay assembly + policies
internal/eventmodel/     NostrHost custom kinds + schema validation
internal/policy/         durable access/kind/admin policy store (bolt)
internal/config/         TOML configuration (relay)
internal/notify/         native notification service (roadmap §18.1)
EVENT-PROTOCOL.md        canonical event-model spec
config.example.toml      relay config
notify.example.toml      notification service config
```

## Notification service (`nostrhost-notify`)

A second, separate binary — a relay *client*, not part of the relay process.
It subscribes to the operation chain and system/service/backup/security
notices (`EVENT-PROTOCOL.md` §2.3) on the local relay and delivers
human-readable summaries to configured npubs as encrypted Nostr direct
messages (NIP-17/NIP-59), replacing local mail as NostrHost's notification
mechanism (roadmap §18.1; see `docs/NOTIFICATION-SERVICE.md` in the umbrella
repo for the full design).

```
go build ./cmd/nostrhost-notify
cp notify.example.toml notify.toml   # set notifier_private_key, outbound_relays
./nostrhost-notify -config notify.toml
```

It holds its own "notifier" key, deliberately separate from the relay's
`server_pubkey`/`operator_pubkey` — a compromised notifier key can read
notices and send DMs, but carries no control-plane authority. Recipients and
policy (which npubs, which event classes, severity threshold, immediate vs.
digest delivery) live in `state/notifications/{recipients,policy}.toml`
(roadmap §18.6); wiring that state directory to `nostrhost-state` is a
follow-up (currently loaded as plain local TOML files).

## NIP-86 example

```bash
# ban a pubkey (requires a NIP-98 header signed by an admin)
curl -X POST -H 'Content-Type: application/nostr+json+rpc' \
  -H 'Authorization: Nostr <base64 kind-27235 event>' \
  -d '{"method":"banpubkey","params":["<hex-pubkey>","abuse"]}' \
  http://127.0.0.1:4848/
```

## Development

```
go test ./...          # unit + relay integration tests (NIP-11/42/86)
```

Requires Go 1.25 (`go.mod` pins the toolchain).

## License

AGPL-3.0-or-later. The embedded relay framework is [khatru](https://github.com/fiatjaf/khatru) (MIT).