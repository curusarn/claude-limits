package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestKeychainSvcFor(t *testing.T) {
	if got := keychainSvcFor(""); got != "Claude Code-credentials" {
		t.Fatalf("default = %q", got)
	}
	// sha256("/Users/me/.claude-accounts/a@example.com")[:8], as Claude Code computes it
	if got := keychainSvcFor("/Users/me/.claude-accounts/a@example.com"); got != "Claude Code-credentials-23de0674" {
		t.Fatalf("dir = %q", got)
	}
}

func TestCheckPlaceDir(t *testing.T) {
	home, _ := os.UserHomeDir()
	for _, bad := range []string{"rel/dir", "/x/y/", "/x/../y", "/x/ž", filepath.Join(home, ".claude")} {
		if checkPlaceDir(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if err := checkPlaceDir("/Users/me/.claude-accounts/a@example.com"); err != nil {
		t.Error(err)
	}
}

func TestWriteDirOauthAccountCreatesFile(t *testing.T) {
	dir := t.TempDir()
	if err := writeDirOauthAccount(dir, oauthProfile{Email: "a@x", AccountUUID: "acc", OrgUUID: "org"}); err != nil {
		t.Fatal(err)
	}
	var m map[string]map[string]string
	b, _ := os.ReadFile(filepath.Join(dir, ".claude.json"))
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["oauthAccount"]["emailAddress"] != "a@x" || m["oauthAccount"]["organizationUuid"] != "org" {
		t.Fatalf("got %v", m)
	}
}

// A placed account never reaches the stored-token (self-refreshing) path.
func TestPlacedAccountIsLive(t *testing.T) {
	t.Setenv("CLAUDE_LIMITS_CONFIG_DIR", t.TempDir())
	dir := t.TempDir() // no keychain item, no .credentials.json: a logged-out dir
	_, live, err := getCreds(Account{Email: "a@x", Source: "stored", Dir: dir}, localLogin{})
	if !live || err == nil {
		t.Fatalf("live=%v err=%v, want live with a no-login error", live, err)
	}
	if _, serr := os.Stat(credsPath("a@x")); !os.IsNotExist(serr) {
		t.Fatal("a stored copy appeared")
	}
}

func TestClaudeRunningIn(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "sessions"), 0o700)
	os.WriteFile(filepath.Join(dir, "sessions", strconv.Itoa(os.Getpid())+".json"), []byte(`{}`), 0o600)
	os.WriteFile(filepath.Join(dir, "sessions", "999999.json"), []byte(`{}`), 0o600) // gone
	os.WriteFile(filepath.Join(dir, "sessions", strconv.Itoa(os.Getpid())+".abc.key"), nil, 0o600)
	os.WriteFile(filepath.Join(dir, "sessions", "999998.abc.key"), nil, 0o600) // gone
	os.WriteFile(filepath.Join(dir, "sessions", "notes.txt"), nil, 0o600)
	got := claudeRunningIn(dir)
	if len(got) != 1 || got[0] != strconv.Itoa(os.Getpid()) {
		t.Fatalf("got %v", got)
	}
}
