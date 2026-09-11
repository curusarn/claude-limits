package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestKeychainBlobRoundTripsScopes(t *testing.T) {
	c := &Creds{
		AccessToken: "sk-ant-oat01-x", RefreshToken: "sk-ant-ort01-y",
		ExpiresAt: 1, RefreshTokenExpiresAt: 2,
		Scopes:           []string{"user:inference", "user:profile"},
		SubscriptionType: "max", RateLimitTier: "default_claude_max_20x",
	}
	blob := keychainBlobJSON(c)
	// Claude Code's exact key set - nothing extra (it rejects nothing, but we
	// keep the shape identical to what it writes itself).
	var m map[string]map[string]any
	if err := json.Unmarshal(blob, &m); err != nil {
		t.Fatal(err)
	}
	want := []string{"accessToken", "expiresAt", "rateLimitTier", "refreshToken", "refreshTokenExpiresAt", "scopes", "subscriptionType"}
	var got []string
	for k := range m["claudeAiOauth"] {
		got = append(got, k)
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("keys = %v, want %v", got, want)
	}
	back := parseClaudeCodeBlob(blob)
	if !reflect.DeepEqual(back, c) {
		t.Fatalf("round trip lost data:\n got %+v\nwant %+v", back, c)
	}
}

func TestRefreshResponseScopeIsSplit(t *testing.T) {
	c := &Creds{Scopes: []string{"old"}}
	applyRefresh(c, refreshResponse{AccessToken: "a", RefreshToken: "r", ExpiresIn: 10, Scope: "user:inference user:profile"})
	if !reflect.DeepEqual(c.Scopes, []string{"user:inference", "user:profile"}) {
		t.Fatalf("scopes = %v", c.Scopes)
	}
	// a response without scope keeps the ones we had
	applyRefresh(c, refreshResponse{AccessToken: "b", RefreshToken: "r2", ExpiresIn: 10})
	if len(c.Scopes) != 2 {
		t.Fatalf("scopes lost: %v", c.Scopes)
	}
}

func TestUpdateOauthAccountRewritesIdentityOnly(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, ".claude.json")
	os.WriteFile(p, []byte(`{"hasCompletedOnboarding":true,"oauthAccount":{"accountUuid":"old","emailAddress":"old@x","organizationUuid":"oldorg","displayName":"Old","profileFetchedAt":123,"seatTier":null},"projects":{"/a":{"x":1}}}`), 0o644)
	if err := updateOauthAccount(p, oauthProfile{Email: "new@x", AccountUUID: "acc", OrgUUID: "org"}); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	b, _ := os.ReadFile(p)
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	oa := m["oauthAccount"].(map[string]any)
	if oa["emailAddress"] != "new@x" || oa["accountUuid"] != "acc" || oa["organizationUuid"] != "org" {
		t.Fatalf("identity not rewritten: %v", oa)
	}
	if _, ok := oa["profileFetchedAt"]; ok {
		t.Fatal("profileFetchedAt must be dropped so Claude Code refetches the profile")
	}
	if _, ok := oa["displayName"]; ok {
		t.Fatal("stale per-account fields (displayName) must be dropped")
	}
	if m["hasCompletedOnboarding"] != true || m["projects"].(map[string]any)["/a"] == nil {
		t.Fatal("unrelated keys lost")
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode changed: %v", fi.Mode())
	}
}

// Live: writes the CURRENT keychain blob back to the keychain unchanged and
// reads it again. Opt-in only (touches the real login keychain).
func TestLiveKeychainWriteRoundTrip(t *testing.T) {
	if os.Getenv("CLAUDE_LIMITS_LIVE_KEYCHAIN") != "1" {
		t.Skip("set CLAUDE_LIMITS_LIVE_KEYCHAIN=1")
	}
	before := readKeychainItem(keychainAccountName())
	if before == nil {
		t.Skip("no keychain item")
	}
	if err := writeKeychainCreds(before); err != nil {
		t.Fatal(err)
	}
	after := readKeychainItem(keychainAccountName())
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("round trip changed the item:\n%+v\n%+v", before, after)
	}
}

// Live: refreshes ONE dormant stored account through the normal path and checks
// the token response carries scopes. Opt-in: CLAUDE_LIMITS_LIVE_REFRESH=<email>.
// (Rotation is persisted, exactly as a normal run would.)
func TestLiveRefreshCarriesScopes(t *testing.T) {
	email := os.Getenv("CLAUDE_LIMITS_LIVE_REFRESH")
	if email == "" {
		t.Skip("set CLAUDE_LIMITS_LIVE_REFRESH=<dormant email>")
	}
	if cur := currentLogin(); cur.email == email {
		t.Fatal("refusing to refresh the ACTIVE login (Claude Code owns its rotation)")
	}
	c, err := readStoredCreds(email)
	if err != nil {
		t.Fatal(err)
	}
	if err := refreshCreds(c); err != nil {
		t.Fatal(err)
	}
	if err := writeStoredCreds(email, c); err != nil {
		t.Fatalf("CRITICAL: rotated but not saved: %v", err)
	}
	if len(c.Scopes) == 0 {
		t.Fatal("refresh response carried no scope")
	}
	t.Logf("scopes: %v", c.Scopes)
}
