// Package config loads nostrhost-control's TOML configuration.
package config

import (
	"fmt"
	"os"
	"time"

	"github.com/pelletier/go-toml/v2"
)

// Defaults (bound to loopback only — this is a local control plane).
const (
	DefaultListenHost       = "127.0.0.1"
	DefaultListenPort       = 4848
	DefaultMaxContentLength = 100000
)

// Prunable is a kind that is stored but aged out after KeepFor.
type Prunable struct {
	Kind    int    `toml:"kind"`
	KeepFor string `toml:"keep_for"`
}

// Config is the nostrhost-control service configuration.
type Config struct {
	ListenHost       string     `toml:"listen_host"`
	ListenPort       int        `toml:"listen_port"`
	Name             string     `toml:"name"`
	Description      string     `toml:"description"`
	Icon             string     `toml:"icon"`
	OperatorPubkey   string     `toml:"operator_pubkey"`
	AdminPubkeys     []string   `toml:"admin_pubkeys"`
	AllowlistMode    bool       `toml:"allowlist_mode"`
	RequireAuthKinds []int      `toml:"require_auth_kinds"`
	AllowedKinds     []int      `toml:"allowed_kinds"`
	DeniedKinds      []int      `toml:"denied_kinds"`
	MaxContentLength int        `toml:"max_content_length"`
	EventsDBPath     string     `toml:"events_db_path"`
	PolicyDBPath     string     `toml:"policy_db_path"`
	Prunable         []Prunable `toml:"prunable"`
}

// Default returns a config with sane local-only defaults.
func Default() Config {
	return Config{
		ListenHost:       DefaultListenHost,
		ListenPort:       DefaultListenPort,
		MaxContentLength: DefaultMaxContentLength,
		EventsDBPath:     "./data/events.db",
		PolicyDBPath:     "./data/policy.db",
	}
}

// Load reads the config file at path and applies defaults for unset fields.
func Load(path string) (Config, error) {
	cfg := Default()
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("config: read %s: %w", path, err)
	}
	if err := toml.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("config: parse %s: %w", path, err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *Config) applyDefaults() {
	if c.ListenHost == "" {
		c.ListenHost = DefaultListenHost
	}
	if c.ListenPort == 0 {
		c.ListenPort = DefaultListenPort
	}
	if c.MaxContentLength == 0 {
		c.MaxContentLength = DefaultMaxContentLength
	}
	if c.EventsDBPath == "" {
		c.EventsDBPath = "./data/events.db"
	}
	if c.PolicyDBPath == "" {
		c.PolicyDBPath = "./data/policy.db"
	}
}

// Validate checks the config.
func (c *Config) Validate() error {
	if c.OperatorPubkey == "" {
		return fmt.Errorf("config: operator_pubkey is required")
	}
	if c.ListenPort < 1 || c.ListenPort > 65535 {
		return fmt.Errorf("config: listen_port out of range: %d", c.ListenPort)
	}
	for _, p := range c.Prunable {
		if _, err := time.ParseDuration(p.KeepFor); err != nil {
			return fmt.Errorf("config: prunable kind %d keep_for %q: %w", p.Kind, p.KeepFor, err)
		}
	}
	return nil
}

// PruneDurations returns the prunable kinds with parsed durations.
func (c Config) PruneDurations() (map[int]time.Duration, error) {
	out := map[int]time.Duration{}
	for _, p := range c.Prunable {
		d, err := time.ParseDuration(p.KeepFor)
		if err != nil {
			return nil, err
		}
		out[p.Kind] = d
	}
	return out, nil
}
