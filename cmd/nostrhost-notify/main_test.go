package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCursorRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cursor.json")

	c, has, err := loadCursor(path)
	if err != nil {
		t.Fatal(err)
	}
	if has {
		t.Fatal("expected no pre-existing state")
	}
	c.LastSeen = 1234
	if err := c.save(); err != nil {
		t.Fatal(err)
	}

	c2, has, err := loadCursor(path)
	if err != nil {
		t.Fatal(err)
	}
	if !has {
		t.Fatal("expected persisted state to be found")
	}
	if c2.LastSeen != 1234 {
		t.Fatalf("last_seen = %d, want 1234", c2.LastSeen)
	}
}

func TestCursorPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cursor.json")
	c := &cursor{LastSeen: 1, path: path}
	if err := c.save(); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("state file mode = %v, want 0600", st.Mode().Perm())
	}
}