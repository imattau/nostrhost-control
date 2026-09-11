package notify

import (
	"fmt"
	"os"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Config is the nostrhost-notify service configuration. It is a distinct
// binary/config from nostrhost-control's relay (see cmd/nostrhost-notify):
// the notification service is a relay *client*, holding its own key
// ("notifier"), separate from the server/operator keys that sign the
// control-plane's own events (EVENT-PROTOCOL.md §7).
type Config struct {
	// RelayURL is the local control-plane relay this service subscribes to
	// (ws://127.0.0.1:4848 by default — see nostrhost-control's own config).
	RelayURL string `toml:"relay_url"`

	// NotifierPrivateKey is the hex secret key used to sign and NIP-44
	// encrypt outbound notification DMs. Never derived from server_sk or
	// operator_sk — a compromised notifier key should not carry any
	// control-plane authority.
	NotifierPrivateKey string `toml:"notifier_private_key"`

	// RecipientsPath / PolicyPath point at state/notifications/*.toml
	// (roadmap §18.6); see docs/NOTIFICATION-SERVICE.md in the umbrella repo.
	RecipientsPath string `toml:"recipients_path"`
	PolicyPath     string `toml:"policy_path"`

	// StatePath is where the service persists its last-seen event cursor
	// (JSON, 0600), so restarts resume without re-delivering history.
	StatePath string `toml:"state_path"`

	// DigestInterval is how often DeliverySummary rules flush their queue.
	DigestInterval string `toml:"digest_interval"`

	// OutboundRelays are additional relays used for ScopeExternal delivery
	// (beyond RelayURL, which is always used for ScopeLocalOnly and as the
	// service's own inbox).
	OutboundRelays []string `toml:"outbound_relays"`
}

// Default returns sane local-only defaults.
func Default() Config {
	return Config{
		RelayURL:       "ws://127.0.0.1:4848",
		RecipientsPath: "./state/notifications/recipients.toml",
		PolicyPath:     "./state/notifications/policy.toml",
		StatePath:      "./state/notifications/state.json",
		DigestInterval: "1h",
	}
}

// LoadConfig reads path and applies defaults for unset fields.
func LoadConfig(path string) (Config, error) {
	cfg := Default()
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("notify: read config %s: %w", path, err)
	}
	if err := toml.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("notify: parse config %s: %w", path, err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	d := Default()
	if c.RelayURL == "" {
		c.RelayURL = d.RelayURL
	}
	if c.RecipientsPath == "" {
		c.RecipientsPath = d.RecipientsPath
	}
	if c.PolicyPath == "" {
		c.PolicyPath = d.PolicyPath
	}
	if c.DigestInterval == "" {
		c.DigestInterval = d.DigestInterval
	}
	if c.StatePath == "" {
		c.StatePath = d.StatePath
	}
}

// Validate checks the config, including that DigestInterval parses.
func (c Config) Validate() error {
	if c.NotifierPrivateKey == "" {
		return fmt.Errorf("notify: notifier_private_key is required")
	}
	if _, err := c.digestInterval(); err != nil {
		return fmt.Errorf("notify: digest_interval %q: %w", c.DigestInterval, err)
	}
	return nil
}

func (c Config) digestInterval() (time.Duration, error) {
	return time.ParseDuration(c.DigestInterval)
}
