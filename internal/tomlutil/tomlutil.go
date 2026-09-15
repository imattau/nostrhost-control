// Package tomlutil provides a shared "read file → toml.Unmarshal → wrap
// error" helper used by every TOML-backed config/policy loader in this
// module, so each caller only supplies the target type and an error prefix.
package tomlutil

import (
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"
)

// Load reads the TOML file at path and unmarshals it into a zero value of T.
// Read and parse errors are wrapped as "<errPrefix>: read/parse <path>: ..."
// so callers only need to supply a short subject, e.g. "config",
// "notify: recipients".
func Load[T any](path, errPrefix string) (T, error) {
	var v T
	raw, err := os.ReadFile(path)
	if err != nil {
		return v, fmt.Errorf("%s: read %s: %w", errPrefix, path, err)
	}
	if err := toml.Unmarshal(raw, &v); err != nil {
		return v, fmt.Errorf("%s: parse %s: %w", errPrefix, path, err)
	}
	return v, nil
}
