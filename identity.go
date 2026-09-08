package main

// Account identity comes from the API, never from local labels.
//
// The bug this design fixes (2026-09-08): the keychain account was labeled from
// ~/.claude.json's oauthAccount.emailAddress - a file that can lag the actual
// credentials by a whole login. Claude Code held one account's tokens while
// ~/.claude.json still named a different account, so that account's at-limit
// usage rendered under the wrong email. Identity is therefore resolved
// from the token itself:
//
//	GET https://api.anthropic.com/api/oauth/profile  -> account.email
//
// and memoized per exact access token (sha256 -> email) so rotation re-resolves
// but a cached identity can never mislabel. Fallback order when the API is
// unreachable: JWT claims in the token (rare - Claude tokens are opaque), then
// "unresolved" - never a guessed or stale label.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const profileURL = "https://api.anthropic.com/api/oauth/profile"

func fetchProfileEmail(accessToken string) (string, error) {
	req, _ := http.NewRequest("GET", profileURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", "claude-code/"+claudeVersion())
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return "", &httpError{resp.StatusCode, fmt.Sprintf("profile API: HTTP %d: %s", resp.StatusCode, truncate(string(raw), 200))}
	}
	var p struct {
		Account struct {
			Email        string `json:"email"`
			EmailAddress string `json:"email_address"`
		} `json:"account"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return "", fmt.Errorf("profile API: bad response: %w", err)
	}
	if p.Account.Email != "" {
		return p.Account.Email, nil
	}
	return p.Account.EmailAddress, nil
}

// jwtEmail best-effort extracts an email claim if the token is a JWT.
// Claude OAuth tokens are opaque (sk-ant-oat...), so this usually returns "".
func jwtEmail(tok string) string {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Email string `json:"email"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.Email
}

// ---- per-token identity memo (sha256(token) -> email) ----
//
// Keyed by the exact token, so it can never cross accounts: a rotated token is
// a cache miss and re-resolves against the API.

var identityMu sync.Mutex

func identityPath() string { return filepath.Join(cacheDir(), "identities.json") }

func tokenKey(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func readIdentityMemo() map[string]string {
	m := map[string]string{}
	if b, err := os.ReadFile(identityPath()); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func memoEmail(tok string) string {
	identityMu.Lock()
	defer identityMu.Unlock()
	return readIdentityMemo()[tokenKey(tok)]
}

func memoizeEmail(tok, email string) {
	if tok == "" || email == "" {
		return
	}
	identityMu.Lock()
	defer identityMu.Unlock()
	m := readIdentityMemo()
	m[tokenKey(tok)] = email
	if err := os.MkdirAll(cacheDir(), 0o700); err != nil {
		return
	}
	b, _ := json.Marshal(m)
	_ = atomicWrite(identityPath(), b, 0o600)
}

// resolveEmail returns the verified account email for an access token:
// memo (exact-token) -> profile API -> JWT claims -> error. Never a local label.
func resolveEmail(accessToken string) (string, error) {
	if accessToken == "" {
		return "", errors.New("no access token")
	}
	if e := memoEmail(accessToken); e != "" {
		return e, nil
	}
	e, err := fetchProfileEmail(accessToken)
	if err == nil && e != "" {
		memoizeEmail(accessToken, e)
		return e, nil
	}
	if err == nil {
		err = errors.New("profile API returned no email")
	}
	if e := jwtEmail(accessToken); e != "" {
		return e, nil
	}
	return "", err
}
