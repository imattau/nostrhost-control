# NostrHost control-plane event protocol

Canonical specification for NostrHost's internal control-plane event model
(as implemented by `nostrhost-control`). This is the *minimal custom surface*
— standard Nostr primitives are used wherever possible, per the component →
NIP mapping (`docs/NIP-MAPPING.md` in the umbrella repo).

> Status: **draft.** Kind numbers are placeholders to be validated against
> the live NIP registry before the first release. They deliberately avoid the
> existing catalogue kinds (30063, 30267, 32267) and the bespoke 30078/30079/
> 30080 the catalogue is migrating away from.

## 1. Primitives used before custom kinds

| requirement | primitive |
|---|---|
| Public profile | kind 0 (NIP-01) |
| Agent signing delegation | NIP-26 |
| Relay client authentication | NIP-42 |
| Encrypted private payloads | NIP-44 |
| Lists (trusted publishers, relays, approved repos) | NIP-51 |
| Relay list metadata / discovery | NIP-65 / NIP-66 |
| State sync | NIP-77 (Negentropy) |
| App/user settings | NIP-78 (kinds 30078 / 78), NIP-42-gated |
| Relay management | NIP-86 (JSON-RPC, NIP-98-authenticated) |
| HTTP operation authentication | NIP-98 |

## 2. Custom kinds

### 2.1 Operation chain (regular, immutable — the audit trail)

| kind | name | required shape |
|---|---|---|
| `2200` | operation request | content `{"tool": "<string>", "args": {...}}`; optional `["p", target]` |
| `2201` | approval | `["e", <request id>]`; content optional JSON |
| `2202` | rejection | `["e", <request id>]`; content optional JSON |
| `2203` | execution started | `["e", <request id>]`; content JSON |
| `2204` | execution result | `["e", <request id>]`; content `{"ok": bool, ...}` |

Chain flow — every step references the request by its event id:

```text
REQUEST    npub-agent   kind 2200   app.upgrade  ditto
APPROVAL   npub-admin   kind 2201   e -> request-id
EXECUTION  npub-server  kind 2203   e -> request-id
RESULT     npub-server  kind 2204   e -> request-id   {"ok":true}
```

Each step is a unique, immutable, stored event; the chain is the authoritative
audit log (a projector may derive an index/read model for reporting).

### 2.2 Definitions (addressable, replaceable per `d`-tag)

| kind | name | `d` tag | content |
|---|---|---|---|
| `31100` | capability/role grant | subject pubkey (64-hex) | `{"type": "<role>", "scopes": ["app.install", ...]}` |
| `31101` | trust/policy declaration | subject | JSON (only if not expressible as NIP-51) |
| `31102` | identity definition | subject pubkey (64-hex) | `{"username": "<account>", "signer_type": "nip07|nip46|passkey|unknown", "label": "...", "enabled": true}` |
| `31300` | build/CI attestation | `"<repo>:<commit>"` | JSON (replaces bespoke catalogue kind 30080) |

Delegations use regular retained kind `27236` with tags `p` (delegate pubkey), `server`
(target server pubkey), `expiry` (Unix timestamp), and one or more `scope`
tags. A delegator may only delegate scopes it currently holds. Kind `27237`
revokes a delegation via an `e` tag and may be authored by the delegator or an
administrator.
| `30617` | NIP-34 repository announcement (state layer) | `"nostrhost-state"` | description; tags `i` = repo id, `n` = network, `r` = relative path |

`31102` is the authoritative pubkey ↔ YunoHost-account mapping. Authored by an
administrator (Phase 3 provisioning) or by the subject with proven account
control (Phase 4 portal self-link). Revocation = re-publish with
`enabled: false`. The identity projector materialises these into the
projection store and the LDAP compatibility account.

### 2.3 System notices (regular)

| kind | name | content |
|---|---|---|
| `2206` | auth/login notice | `{"username": ..., "at": ...}`; `["p", subject pubkey]` (roadmap §8) |
| `2210` | system event | JSON |
| `2211` | service event | JSON |
| `2212` | backup event | JSON |
| `2213` | security event | JSON |

## 3. Retention classes

| class | kinds | behaviour |
|---|---|---|
| `ephemeral` | 20000–29999 | not stored (khatru handles) |
| `replaceable` | 10000–19999, 30000–39999 | latest per address wins |
| `immutable` | regular kinds (chain, system notices) | stored forever |
| `prunable` | config-driven (e.g. `2200`) | stored, aged out after `keep_for` |

## 4. Validation

`nostrhost-control` enforces at write time (in policy order):

1. kind validity (NIP-16 treatment), timestamp bounds, content size
2. kind policy: denied kinds rejected; explicit allowlist enforced
3. writer policy: banned pubkeys rejected; allowlist mode default-denies
4. NIP-42 auth for protected kinds (control kinds + NIP-78/51 primitives)
5. schema validation of custom kinds (eventmodel)

Reads of protected kinds likewise require NIP-42 auth.

## 5. NIP-86 management surface

| method | backed by |
|---|---|
| `banpubkey` / `allowpubkey` / `listbannedpubkeys` / `listallowedpubkeys` | policy store |
| `allowkind` / `disallowkind` / `listallowedkinds` / `listdisallowedkinds` | policy store |
| `blockip` / `unblockip` / `listblockedips` | policy store |
| `grantadmin` / `revokeadmin` | policy store |
| `changerelayname` / `changerelaydescription` / `changerelayicon` | relay NIP-11 + policy store |
| `stats` | policy + event store counts |

All calls require a valid NIP-98 signature by a configured administrator.

## 6. Access model

- The relay binds **loopback only** — it is a local control plane, not a
  public relay.
- **NIP-42** answers "who are you"; **NIP-86** administers the relay;
  **Nostr events** administer NostrHost (authorisation is capability events
  evaluated by the policy engine).
- Sessions, CSRF and challenge state stay in the local HTTP/auth subsystem —
  never in the event stream.
## 7. Identity bootstrap

Three distinct roles (hardened bootstrap, Phase 3):

| role | key | signs |
|---|---|---|
| server | `server_sk` | execution `2203`/`2204` (the node's machine identity) |
| operator | `operator_sk` | approval `2201`/`2202`, capability `31100`, identity `31102` |
| admins | admin pubkeys | — (the set the projector/executor accept events from; always includes the operator) |

**Bootstrap vs post-bootstrap authority:**

- *Bootstrap* is the local, root-only, high-trust action (`nostrhost-bootstrap`):
  the machine owner generates/imports `server_sk` + `operator_sk` and
  designates admins into `/etc/nostrhost/operator.toml` (0600). Until then
  the daemons refuse to operate and the mutating CLI tools fail with a clear
  pointer to the bootstrap action.
- *Post-bootstrap*, authority flows through the configured admins via the
  signed event stream (approvals, grants, identity definitions); the relay
  allowlists both the operator (admin) and the server (writer only, via
  `server_pubkey`) so execution events are accepted without granting the
  server NIP-86 authority.

Legacy single-key configs (no `server_sk`) keep working: the server key falls
back to the operator key, and `nostrhost-bootstrap --force` upgrades them to
the distinct-key model.
