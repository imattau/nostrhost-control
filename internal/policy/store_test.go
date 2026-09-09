package policy

import (
	"path/filepath"
	"testing"
)

func openTmp(t *testing.T, admin []string, allowedKinds []int, allowlist bool) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "policy.db"), admin, allowedKinds, allowlist)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestAdminSeeding(t *testing.T) {
	s := openTmp(t, []string{"aa", "bb"}, nil, false)
	if !s.IsAdmin("aa") || !s.IsAdmin("bb") || s.IsAdmin("cc") {
		t.Fatal("admin seeding wrong")
	}
	_ = s.RevokeAdmin("aa")
	if s.IsAdmin("aa") {
		t.Fatal("revoke admin failed")
	}
}

func TestAllowBan(t *testing.T) {
	s := openTmp(t, nil, nil, false)
	_ = s.Ban("aa", "spam")
	if !s.IsBanned("aa") {
		t.Fatal("ban not applied")
	}
	_ = s.Allow("aa", "trusted")
	if s.IsBanned("aa") || !s.IsAllowed("aa") {
		t.Fatal("allow should clear ban and add to allow set")
	}
	if got := s.ListBanned(); len(got) != 0 {
		t.Fatalf("unexpected banned list: %v", got)
	}
}

func TestKindPolicy(t *testing.T) {
	s := openTmp(t, nil, []int{1, 2200}, false)
	if !s.KindAllowed(2200) || s.KindAllowed(30078) {
		t.Fatal("explicit allowlist should deny unlisted kinds")
	}
	_ = s.AllowKind(30078)
	if !s.KindAllowed(30078) {
		t.Fatal("AllowKind should extend the allowlist")
	}
	_ = s.DenyKind(2200)
	if s.KindAllowed(2200) {
		t.Fatal("DenyKind should win over the allowlist")
	}
}

func TestKindPolicyOpenDefault(t *testing.T) {
	s := openTmp(t, nil, nil, false)
	if !s.KindAllowed(2200) || !s.KindAllowed(1) {
		t.Fatal("no explicit allowlist should allow everything except denied")
	}
	_ = s.DenyKind(2200)
	if s.KindAllowed(2200) {
		t.Fatal("denied kind should be rejected")
	}
}

func TestIPsAndRelayInfo(t *testing.T) {
	s := openTmp(t, nil, nil, false)
	_ = s.BlockIP("10.0.0.1", "abuse")
	if !s.IsIPBlocked("10.0.0.1") {
		t.Fatal("IP block not applied")
	}
	if got := s.ListBlockedIPs(); len(got) != 1 || got[0].Reason != "abuse" {
		t.Fatalf("unexpected blocked IPs: %v", got)
	}
	_ = s.UnblockIP("10.0.0.1")
	if s.IsIPBlocked("10.0.0.1") {
		t.Fatal("IP unblock failed")
	}

	_ = s.SetRelayInfo("name", "nostrhost")
	if s.GetRelayInfo("name") != "nostrhost" {
		t.Fatal("relay info round-trip failed")
	}
	_ = s.SetRelayInfo("name", "")
	if s.GetRelayInfo("name") != "" {
		t.Fatal("relay info delete failed")
	}
}

func TestAllowlistModeFlag(t *testing.T) {
	s := openTmp(t, []string{"admin"}, nil, true)
	if !s.AllowlistMode() {
		t.Fatal("allowlist mode flag not set")
	}
	// admins auto-allowed
	if !s.IsAllowed("admin") {
		t.Fatal("admin should be auto-allowed in allowlist mode")
	}
}
