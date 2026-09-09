// Package relay builds the NostrHost control-plane relay on khatru.
//
// The relay engine is khatru (the standard Nostr relay framework): NIP-01
// WebSocket handling, NIP-42 AUTH, NIP-77 negentropy and the NIP-86
// management dispatch are provided by the framework — NostrHost adds the
// event-model validation, the local access/kind/admin policy and per-kind
// retention on top.
package relay

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/fiatjaf/eventstore"
	"github.com/fiatjaf/eventstore/badger"
	"github.com/fiatjaf/khatru"
	"github.com/fiatjaf/khatru/policies"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip86"

	"github.com/imattau/nostrhost-control/internal/config"
	"github.com/imattau/nostrhost-control/internal/eventmodel"
	"github.com/imattau/nostrhost-control/internal/policy"
)

// Software and version advertised via NIP-11.
const (
	Software = "https://github.com/imattau/nostrhost-control"
	Version  = "0.1.0"
)

// ProtectedKinds are the kinds that require NIP-42 AUTH by default when
// config.RequireAuthKinds is empty: the control plane's own kinds plus the
// standard primitives that carry per-user data (NIP-78 app data, NIP-51
// lists).
var ProtectedKinds = []int{
	eventmodel.KindOperationRequest, eventmodel.KindOperationApproval,
	eventmodel.KindOperationRejection, eventmodel.KindExecutionStarted,
	eventmodel.KindExecutionResult, eventmodel.KindSystemEvent,
	eventmodel.KindServiceEvent, eventmodel.KindBackupEvent,
	eventmodel.KindSecurityEvent, eventmodel.KindCapability,
	eventmodel.KindTrustPolicy, eventmodel.KindIdentityDefinition,
	eventmodel.KindBuildAttestation,
	78, 30078, 10002, 30000, 30002, 30267, 10006,
}

// Server is the assembled control-plane relay.
type Server struct {
	Relay  *khatru.Relay
	Store  eventstore.Store
	Policy *policy.Store
	Cfg    config.Config

	mu      sync.Mutex
	pruners map[int]time.Duration
}

// New assembles the relay from cfg.
func New(cfg config.Config) (*Server, error) {
pol, err := policy.Open(cfg.PolicyDBPath, adminsFrom(cfg), cfg.AllowedKinds, cfg.AllowlistMode)
	if err != nil {
		return nil, fmt.Errorf("open policy store: %w", err)
	}
	// The server's own machine key writes execution events (2203/2204). It is
	// an allowlisted writer but NOT an admin (no NIP-86 authority).
	if nostr.IsValidPublicKey(cfg.ServerPubkey) {
		_ = pol.Allow(cfg.ServerPubkey, "server")
	}

	s := &Server{
		Relay:  khatru.NewRelay(),
		Policy: pol,
		Cfg:    cfg,
	}
	s.Store = &badger.BadgerBackend{Path: cfg.EventsDBPath, MaxLimit: 500}

	s.Relay.ServiceURL = fmt.Sprintf("ws://%s:%d", cfg.ListenHost, cfg.ListenPort)
	s.Relay.Negentropy = true

	// NIP-11
	s.Relay.Info.Name = cfg.Name
	s.Relay.Info.Description = cfg.Description
	s.Relay.Info.Icon = cfg.Icon
	s.Relay.Info.Software = Software
	s.Relay.Info.Version = Version
	s.Relay.Info.AddSupportedNIPs([]int{1, 9, 11, 42, 70, 77, 86, 98})
	if nostr.IsValidPublicKey(cfg.OperatorPubkey) {
		s.Relay.Info.PubKey = cfg.OperatorPubkey
	}
	if name := pol.GetRelayInfo("name"); name != "" {
		s.Relay.Info.Name = name
	}
	if desc := pol.GetRelayInfo("description"); desc != "" {
		s.Relay.Info.Description = desc
	}
	if icon := pol.GetRelayInfo("icon"); icon != "" {
		s.Relay.Info.Icon = icon
	}

	// storage hooks
	s.Relay.StoreEvent = []func(context.Context, *nostr.Event) error{s.Store.SaveEvent}
	s.Relay.ReplaceEvent = []func(context.Context, *nostr.Event) error{s.Store.ReplaceEvent}
	s.Relay.DeleteEvent = []func(context.Context, *nostr.Event) error{s.Store.DeleteEvent}
	s.Relay.QueryEvents = []func(context.Context, nostr.Filter) (chan *nostr.Event, error){s.Store.QueryEvents}
	s.Relay.CountEvents = []func(context.Context, nostr.Filter) (int64, error){s.countEvents}

	// write policies
	s.Relay.RejectEvent = []func(context.Context, *nostr.Event) (bool, string){
		policies.ValidateKind,
		policies.PreventTimestampsInTheFuture(time.Minute * 10),
		s.rejectOversizedContent,
		s.rejectKindDenied,
		s.rejectWriterPolicy,
		s.requireAuthPolicy,
		s.validateEventModelPolicy,
	}

	// read policies: protected kinds require NIP-42 auth
	s.Relay.RejectFilter = []func(context.Context, nostr.Filter) (bool, string){
		s.requireAuthForRead,
		policies.NoEmptyFilters,
		policies.NoComplexFilters,
	}

	// connection-level IP blocking
	s.Relay.RejectConnection = []func(*http.Request) bool{s.rejectBlockedIP}

	// NIP-86 management surface
	s.wireManagementAPI()

	// retention pruners
	s.pruners = map[int]time.Duration{}
	if pd, err := cfg.PruneDurations(); err == nil {
		s.pruners = pd
	}

	return s, nil
}

func adminsFrom(cfg config.Config) []string {
	out := append([]string{}, cfg.AdminPubkeys...)
	if cfg.OperatorPubkey != "" {
		out = append(out, cfg.OperatorPubkey)
	}
	return out
}

// protectedKinds returns the kinds that require NIP-42 auth.
//
// Config semantics: `require_auth_kinds` unset (nil) → the default protected
// set is used; explicitly set to an empty list → NIP-42 is not required at
// all (the loopback control-plane posture: write allowlist + loopback
// binding carry the access control, since nostr-sdk clients can't yet do
// NIP-42 client auth cleanly). Non-empty list → exactly those kinds.
func (s *Server) protectedKinds() []int {
	if s.Cfg.RequireAuthKinds != nil {
		return s.Cfg.RequireAuthKinds
	}
	return ProtectedKinds
}

func kindIn(list []int, kind int) bool {
	for _, k := range list {
		if k == kind {
			return true
		}
	}
	return false
}

func (s *Server) countEvents(ctx context.Context, filter nostr.Filter) (int64, error) {
	if c, ok := s.Store.(interface {
		CountEvents(context.Context, nostr.Filter) (int64, error)
	}); ok {
		return c.CountEvents(ctx, filter)
	}
	return 0, nil
}

func (s *Server) rejectOversizedContent(_ context.Context, event *nostr.Event) (bool, string) {
	if len(event.Content) > s.Cfg.MaxContentLength {
		return true, "content too large"
	}
	return false, ""
}

// --- write policies ---

func (s *Server) rejectKindDenied(_ context.Context, event *nostr.Event) (bool, string) {
	if !s.Policy.KindAllowed(event.Kind) {
		return true, "kind not allowed"
	}
	return false, ""
}

func (s *Server) rejectWriterPolicy(_ context.Context, event *nostr.Event) (bool, string) {
	if s.Policy.IsBanned(event.PubKey) {
		return true, "pubkey is banned"
	}
	if s.Policy.AllowlistMode() && !s.Policy.IsAllowed(event.PubKey) {
		return true, "pubkey not in allowlist"
	}
	return false, ""
}

func (s *Server) requireAuthPolicy(ctx context.Context, event *nostr.Event) (bool, string) {
	if kindIn(s.protectedKinds(), event.Kind) {
		if authed := khatru.GetAuthed(ctx); authed == "" {
			khatru.RequestAuth(ctx)
			return true, "authentication required"
		}
	}
	return false, ""
}

func (s *Server) validateEventModelPolicy(_ context.Context, event *nostr.Event) (bool, string) {
	if err := eventmodel.Validate(event); err != nil {
		return true, err.Error()
	}
	return false, ""
}

// --- read policies ---

func (s *Server) requireAuthForRead(ctx context.Context, filter nostr.Filter) (bool, string) {
	for _, kind := range filter.Kinds {
		if kindIn(s.protectedKinds(), kind) {
			if authed := khatru.GetAuthed(ctx); authed == "" {
				khatru.RequestAuth(ctx)
				return true, "authentication required"
			}
		}
	}
	return false, ""
}

// --- connection policy ---

func (s *Server) rejectBlockedIP(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	return s.Policy.IsIPBlocked(host)
}

// --- NIP-86 ---

func (s *Server) wireManagementAPI() {
	api := &s.Relay.ManagementAPI

	// Only relay administrators may call any method. khatru's HandleNIP86
	// already verified the NIP-98 signature and set the caller in context.
	api.RejectAPICall = []func(context.Context, nip86.MethodParams) (bool, string){
		func(ctx context.Context, _ nip86.MethodParams) (bool, string) {
			if !s.Policy.IsAdmin(khatru.GetAuthed(ctx)) {
				return true, "not authorized"
			}
			return false, ""
		},
	}

	api.BanPubKey = func(_ context.Context, pubkey, reason string) error {
		return s.Policy.Ban(pubkey, reason)
	}
	api.AllowPubKey = func(_ context.Context, pubkey, reason string) error {
		return s.Policy.Allow(pubkey, reason)
	}
	api.ListBannedPubKeys = func(_ context.Context) ([]nip86.PubKeyReason, error) {
		return s.Policy.ListBanned(), nil
	}
	api.ListAllowedPubKeys = func(_ context.Context) ([]nip86.PubKeyReason, error) {
		return s.Policy.ListAllowed(), nil
	}

	api.AllowKind = func(_ context.Context, kind int) error { return s.Policy.AllowKind(kind) }
	api.DisallowKind = func(_ context.Context, kind int) error { return s.Policy.DenyKind(kind) }
	api.ListAllowedKinds = func(_ context.Context) ([]int, error) { return s.Policy.ListAllowedKinds(), nil }
	api.ListDisAllowedKinds = func(_ context.Context) ([]int, error) { return s.Policy.ListDeniedKinds(), nil }

	api.BlockIP = func(_ context.Context, ip net.IP, reason string) error { return s.Policy.BlockIP(ip.String(), reason) }
	api.UnblockIP = func(_ context.Context, ip net.IP, _ string) error { return s.Policy.UnblockIP(ip.String()) }
	api.ListBlockedIPs = func(_ context.Context) ([]nip86.IPReason, error) { return s.Policy.ListBlockedIPs(), nil }

	api.GrantAdmin = func(_ context.Context, pubkey string, _ []string) error { return s.Policy.GrantAdmin(pubkey) }
	api.RevokeAdmin = func(_ context.Context, pubkey string, _ []string) error { return s.Policy.RevokeAdmin(pubkey) }

	api.ChangeRelayName = func(_ context.Context, name string) error {
		s.Relay.Info.Name = name
		return s.Policy.SetRelayInfo("name", name)
	}
	api.ChangeRelayDescription = func(_ context.Context, desc string) error {
		s.Relay.Info.Description = desc
		return s.Policy.SetRelayInfo("description", desc)
	}
	api.ChangeRelayIcon = func(_ context.Context, icon string) error {
		s.Relay.Info.Icon = icon
		return s.Policy.SetRelayInfo("icon", icon)
	}

	api.Stats = func(ctx context.Context) (nip86.Response, error) {
		banned, _ := api.ListBannedPubKeys(ctx)
		allowed, _ := api.ListAllowedPubKeys(ctx)
		var events int64
		if s.Store != nil {
			if c, ok := s.Store.(interface {
				CountEvents(context.Context, nostr.Filter) (int64, error)
			}); ok {
				events, _ = c.CountEvents(ctx, nostr.Filter{})
			}
		}
		return nip86.Response{
			Result: map[string]any{
				"banned_pubkeys":  len(banned),
				"allowed_pubkeys": len(allowed),
				"stored_events":   events,
			},
		}, nil
	}
}

// --- lifecycle ---

// Start initialises storage and begins serving. It also starts the retention
// pruner; run until the returned context is cancelled or the server shuts
// down. Optional `started` channels are closed once the relay is listening.
func (s *Server) Start(started ...chan bool) error {
	if err := s.Store.Init(); err != nil {
		return fmt.Errorf("relay: init store: %w", err)
	}
	go s.runPruner()
	log.Printf("nostrhost-control: relay listening on ws://%s:%d (nip86 + nip42 + nip77)", s.Cfg.ListenHost, s.Cfg.ListenPort)
	return s.Relay.Start(s.Cfg.ListenHost, s.Cfg.ListenPort, started...)
}

// Shutdown closes the relay and stores.
func (s *Server) Shutdown(ctx context.Context) {
	s.Relay.Shutdown(ctx)
	s.Store.Close()
	_ = s.Policy.Close()
}

// runPruner ages out prunable kinds past their TTL (e.g. old operation
// requests). It re-enumerates every hour.
func (s *Server) runPruner() {
	if len(s.pruners) == 0 {
		return
	}
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		for kind, ttl := range s.pruners {
			s.pruneKind(kind, ttl)
		}
	}
}

func (s *Server) pruneKind(kind int, ttl time.Duration) {
	cutoff := time.Now().Add(-ttl).Unix()
	ch, err := s.Store.QueryEvents(context.Background(), nostr.Filter{Kinds: []int{kind}})
	if err != nil {
		return
	}
	for evt := range ch {
		if evt.CreatedAt < nostr.Timestamp(cutoff) {
			_ = s.Store.DeleteEvent(context.Background(), evt)
		}
	}
}
