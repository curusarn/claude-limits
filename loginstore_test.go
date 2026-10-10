package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A fake helper: a shell script that keeps the "agents' file" in a temp dir.
func fakeHelper(t *testing.T) (dir string) {
	dir = t.TempDir()
	script := filepath.Join(dir, "helper")
	body := `#!/bin/sh
f="` + dir + `/creds.json"; a="` + dir + `/account.json"
case "$1" in
read) [ -f "$f" ] && cat "$f" || exit 1 ;;
write) cat > "$f" ;;
account) cat > "$a" ;;
esac
`
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_LIMITS_LOGIN_HELPER", script)
	return dir
}

func TestLoginHelperReadWriteKeepsOtherKeys(t *testing.T) {
	dir := fakeHelper(t)
	if usesKeychain() {
		t.Fatal("a login helper must replace the keychain")
	}
	if readClaudeCodeCandidates() != nil {
		t.Fatal("no login yet")
	}
	os.WriteFile(filepath.Join(dir, "creds.json"), []byte(`{"claudeAiOauth":{"accessToken":"old","refreshToken":"r0"},"mcpOAuth":{"x":1}}`), 0o600)
	if c := readClaudeCodeCandidates(); len(c) != 1 || c[0].AccessToken != "old" {
		t.Fatalf("got %+v", c)
	}
	if err := writeLoginFile(&Creds{AccessToken: "new", RefreshToken: "r1"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "creds.json"))
	if parseClaudeCodeBlob(b).AccessToken != "new" || !strings.Contains(string(b), "mcpOAuth") {
		t.Fatalf("got %s", b)
	}
	if err := setLoginAccount(oauthProfile{Email: "a@x", AccountUUID: "u", OrgUUID: "o"}); err != nil {
		t.Fatal(err)
	}
	if a, _ := os.ReadFile(filepath.Join(dir, "account.json")); !strings.Contains(string(a), `"emailAddress":"a@x"`) {
		t.Fatalf("account: %s", a)
	}
}
