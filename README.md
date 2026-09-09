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
cmd/nostrhost-control/   entry point
internal/relay/          khatru relay assembly + policies
internal/eventmodel/     NostrHost custom kinds + schema validation
internal/policy/         durable access/kind/admin policy store (bolt)
internal/config/         TOML configuration
EVENT-PROTOCOL.md        canonical event-model spec
config.example.toml
```

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