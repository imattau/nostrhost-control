// Package policy is the NostrHost local access/kind/admin policy store.
//
// It backs the NIP-86 relay-management surface: allow/ban pubkeys, allow/
// deny kinds, block IPs, grant admins. State is persisted in a bolt DB and
// seeded from the service config at first open.
package policy

import (
	"fmt"
	"sort"

	"github.com/nbd-wtf/go-nostr/nip86"
	bolt "go.etcd.io/bbolt"
)

var (
	bucketAdmins       = []byte("admins")        // pubkey -> "granted"
	bucketBanned       = []byte("banned")        // pubkey -> reason
	bucketAllowed      = []byte("allowed")       // pubkey -> reason
	bucketKindsAllowed = []byte("kinds_allowed") // strconv kind -> ""
	bucketKindsDenied  = []byte("kinds_denied")  // strconv kind -> ""
	bucketIPs          = []byte("ips")           // ip -> reason
	bucketInfo         = []byte("info")          // key -> value
)

// Store persists relay-management policy state.
type Store struct {
	db *bolt.DB
	// allowlistMode toggles default-deny for writes (every writer must be
	// in the allowed set). Operators/admins are auto-allowed.
	allowlistMode bool
}

// Open opens (or creates) the policy store at path and seeds it.
func Open(path string, adminPubkeys []string, allowedKinds []int, allowlistMode bool) (*Store, error) {
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		return nil, fmt.Errorf("policy: open %s: %w", path, err)
	}
	s := &Store{db: db, allowlistMode: allowlistMode}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketAdmins, bucketBanned, bucketAllowed,
			bucketKindsAllowed, bucketKindsDenied, bucketIPs, bucketInfo} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}
	for _, pk := range adminPubkeys {
		if pk != "" {
			_ = s.GrantAdmin(pk)
			_ = s.Allow(pk, "admin")
		}
	}
	for _, k := range allowedKinds {
		_ = s.AllowKind(k)
	}
	return s, nil
}

// Close closes the underlying database.
func (s *Store) Close() error { return s.db.Close() }

// AllowlistMode reports whether writes are default-deny.
func (s *Store) AllowlistMode() bool { return s.allowlistMode }

// --- admins ---

// IsAdmin reports whether pubkey is a relay administrator.
func (s *Store) IsAdmin(pubkey string) bool {
	var v []byte
	_ = s.db.View(func(tx *bolt.Tx) error {
		v = tx.Bucket(bucketAdmins).Get([]byte(pubkey))
		return nil
	})
	return v != nil
}

// GrantAdmin adds pubkey as an administrator.
func (s *Store) GrantAdmin(pubkey string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAdmins).Put([]byte(pubkey), []byte("granted"))
	})
}

// RevokeAdmin removes an administrator.
func (s *Store) RevokeAdmin(pubkey string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAdmins).Delete([]byte(pubkey))
	})
}

// --- pubkey allow / ban ---

// IsBanned reports whether pubkey is banned from publishing.
func (s *Store) IsBanned(pubkey string) bool {
	var v []byte
	_ = s.db.View(func(tx *bolt.Tx) error {
		v = tx.Bucket(bucketBanned).Get([]byte(pubkey))
		return nil
	})
	return v != nil
}

// IsAllowed reports whether pubkey is in the allow set.
func (s *Store) IsAllowed(pubkey string) bool {
	var v []byte
	_ = s.db.View(func(tx *bolt.Tx) error {
		v = tx.Bucket(bucketAllowed).Get([]byte(pubkey))
		return nil
	})
	return v != nil
}

// Ban bans a pubkey and removes it from the allow set.
func (s *Store) Ban(pubkey, reason string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketAllowed).Delete([]byte(pubkey)); err != nil {
			return err
		}
		return tx.Bucket(bucketBanned).Put([]byte(pubkey), []byte(reason))
	})
}

// Unban removes a ban.
func (s *Store) Unban(pubkey string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketBanned).Delete([]byte(pubkey))
	})
}

// Allow adds a pubkey to the allow set and removes any ban.
func (s *Store) Allow(pubkey, reason string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bucketBanned).Delete([]byte(pubkey)); err != nil {
			return err
		}
		return tx.Bucket(bucketAllowed).Put([]byte(pubkey), []byte(reason))
	})
}

func listKV(db *bolt.DB, bucket []byte) map[string]string {
	out := map[string]string{}
	_ = db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).ForEach(func(k, v []byte) error {
			out[string(k)] = string(v)
			return nil
		})
	})
	return out
}

// ListBanned returns banned pubkeys with reasons.
func (s *Store) ListBanned() []nip86.PubKeyReason {
	kv := listKV(s.db, bucketBanned)
	out := make([]nip86.PubKeyReason, 0, len(kv))
	for pk, reason := range kv {
		out = append(out, nip86.PubKeyReason{PubKey: pk, Reason: reason})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PubKey < out[j].PubKey })
	return out
}

// ListAllowed returns allowed pubkeys with reasons.
func (s *Store) ListAllowed() []nip86.PubKeyReason {
	kv := listKV(s.db, bucketAllowed)
	out := make([]nip86.PubKeyReason, 0, len(kv))
	for pk, reason := range kv {
		out = append(out, nip86.PubKeyReason{PubKey: pk, Reason: reason})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PubKey < out[j].PubKey })
	return out
}

// --- kinds ---

// KindAllowed reports whether an event of kind may be stored.
func (s *Store) KindAllowed(kind int) bool {
	key := itoa(kind)
	denied := s.has(bucketKindsDenied, key)
	if denied {
		return false
	}
	allowed := listKV(s.db, bucketKindsAllowed)
	if len(allowed) == 0 {
		return true // no explicit allowlist configured → allow except denied
	}
	return s.has(bucketKindsAllowed, key)
}

// AllowKind permits a kind (adds it to the explicit allowlist).
func (s *Store) AllowKind(kind int) error {
	return s.put(bucketKindsAllowed, itoa(kind), "")
}

// DenyKind forbids a kind.
func (s *Store) DenyKind(kind int) error {
	return s.put(bucketKindsDenied, itoa(kind), "")
}

// ListAllowedKinds returns the explicit kind allowlist.
func (s *Store) ListAllowedKinds() []int { return s.listInts(bucketKindsAllowed) }

// ListDeniedKinds returns the kind denylist.
func (s *Store) ListDeniedKinds() []int { return s.listInts(bucketKindsDenied) }

// --- IPs ---

// IsIPBlocked reports whether ip is blocked.
func (s *Store) IsIPBlocked(ip string) bool { return s.has(bucketIPs, ip) }

// BlockIP blocks an IP with a reason.
func (s *Store) BlockIP(ip, reason string) error { return s.put(bucketIPs, ip, reason) }

// UnblockIP removes an IP block.
func (s *Store) UnblockIP(ip string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketIPs).Delete([]byte(ip))
	})
}

// ListBlockedIPs returns blocked IPs with reasons.
func (s *Store) ListBlockedIPs() []nip86.IPReason {
	kv := listKV(s.db, bucketIPs)
	out := make([]nip86.IPReason, 0, len(kv))
	for ip, reason := range kv {
		out = append(out, nip86.IPReason{IP: ip, Reason: reason})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

// --- relay info ---

// GetRelayInfo returns a stored NIP-11 field value (name/description/icon).
func (s *Store) GetRelayInfo(key string) string {
	return string(s.get(bucketInfo, key))
}

// SetRelayInfo stores a NIP-11 field value.
func (s *Store) SetRelayInfo(key, value string) error {
	if value == "" {
		return s.db.Update(func(tx *bolt.Tx) error {
			return tx.Bucket(bucketInfo).Delete([]byte(key))
		})
	}
	return s.put(bucketInfo, key, value)
}

// --- helpers ---

func (s *Store) has(bucket []byte, key string) bool {
	var v []byte
	_ = s.db.View(func(tx *bolt.Tx) error {
		v = tx.Bucket(bucket).Get([]byte(key))
		return nil
	})
	return v != nil
}

func (s *Store) get(bucket []byte, key string) []byte {
	var v []byte
	_ = s.db.View(func(tx *bolt.Tx) error {
		v = tx.Bucket(bucket).Get([]byte(key))
		return nil
	})
	return v
}

func (s *Store) put(bucket []byte, key, value string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucket).Put([]byte(key), []byte(value))
	})
}

func (s *Store) listInts(bucket []byte) []int {
	kv := listKV(s.db, bucket)
	out := make([]int, 0, len(kv))
	for k := range kv {
		if n := atoi(k); n >= 0 {
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}

func atoi(s string) int {
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	if err != nil {
		return -1
	}
	return n
}
