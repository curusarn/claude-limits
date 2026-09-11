package main

// Credential sources and the OAuth refresh loop.
//
// Verified against the real endpoints (2026-09-08):
//   - refresh: POST https://platform.claude.com/v1/oauth/token (JSON body)
//     -> 200 {access_token, refresh_token, expires_in, refresh_token_expires_in, account{email_address}, ...}
//     The refresh token ROTATES on every use: the old one is invalidated, so
//     whoever refreshes MUST persist the new pair or the account is lost.
//   - Claude Code stores its creds in the macOS Keychain, service
//     "Claude Code-credentials", as {"claudeAiOauth":{accessToken,refreshToken,expiresAt,...}}.
//     ~/.claude/.credentials.json is a plaintext FALLBACK written only when the
//     keychain write fails (verified in Claude Code 2.1.267) - it can be stale.
//
// Because refresh rotates, the account you're CURRENTLY logged into (its email
// matches this machine's keychain) is read LIVE and never refreshed by the tool
// - Claude Code owns that rotation, and two writers would race each other out
// of the token family. Every OTHER (dormant) account is owned by the tool: it
// self-refreshes the stored pair as needed, rewriting the rotated pair each
// time, so a switched-away account stays alive. The active/dormant decision is
// made per run in getCreds; every account is stored + email-keyed.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	oauthTokenURL = "https://platform.claude.com/v1/oauth/token"
	oauthClientID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e" // Claude Code's public OAuth client id
	keychainSvc   = "Claude Code-credentials"
)

// Account is one entry in accounts.json. Identity is the account EMAIL as
// verified against the API (see identity.go) - there is no human-typed alias.
type Account struct {
	Email  string `json:"email,omitempty"` // verified identity = the key (from the API, never guessed)
	Source string `json:"source"`          // "stored" (added via `add`/paste) | "op" (seeded from 1Password)
	OpRef  string `json:"ref,omitempty"`   // op://vault/item/field for source "op" (seeds the stored file once)

	// LegacyName is a pre-email-identity typed alias, kept only until migration
	// re-derives the real email from the token (or flags the entry for re-import).
	LegacyName string `json:"name,omitempty"`

	// Unadded marks a display-only entry for the current login that has not been
	// `add`ed yet (never persisted; suppresses the stored-copy sync in getCreds).
	Unadded bool `json:"-"`
}

// key names this account's on-disk creds file: the verified email, or the
// legacy alias until migration resolves it.
func (a Account) key() string {
	if a.Email != "" {
		return a.Email
	}
	return a.LegacyName
}

// Creds is the on-disk per-account credential store (creds/<name>.json, 0600).
type Creds struct {
	AccessToken           string   `json:"accessToken"`
	RefreshToken          string   `json:"refreshToken"`
	ExpiresAt             int64    `json:"expiresAt"`                       // unix ms
	RefreshTokenExpiresAt int64    `json:"refreshTokenExpiresAt,omitempty"` // unix ms
	Email                 string   `json:"email,omitempty"`
	Scopes                []string `json:"scopes,omitempty"` // kept verbatim so `switch` can write the blob back
	RateLimitTier         string   `json:"rateLimitTier,omitempty"`
	SubscriptionType      string   `json:"subscriptionType,omitempty"`
}

func configDir() string {
	if d := os.Getenv("CLAUDE_LIMITS_CONFIG_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "claude-limits")
}

func accountsPath() string { return filepath.Join(configDir(), "accounts.json") }
func credsPath(name string) string {
	return filepath.Join(configDir(), "creds", name+".json")
}

// loadAccounts reads accounts.json (the accounts you've `add`ed). With no
// config it returns nothing configured - cmdShow still shows the current login
// live (labeled "not added yet"), so a fresh run is never blank.
func loadAccounts() ([]Account, error) {
	b, err := os.ReadFile(accountsPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var accs []Account
	if err := json.Unmarshal(b, &accs); err != nil {
		return nil, fmt.Errorf("%s: %w", accountsPath(), err)
	}
	return accs, nil
}

// localLogin is the account Claude Code is logged into on this machine right now.
type localLogin struct {
	email string // API-verified; "" if not logged in / unresolvable
	creds *Creds // freshest VALID keychain copy; nil if none
}

// currentLogin resolves this machine's live Claude Code account. It picks the
// credential copy whose identity the API confirms (the keychain and
// .credentials.json copies drift a rotation apart; the stale one 401s), so the
// returned creds are display-ready and the email is verified - never guessed.
func currentLogin() localLogin {
	for _, c := range readClaudeCodeCandidates() {
		if e, err := resolveEmail(c.AccessToken); err == nil && e != "" {
			c.Email = e
			return localLogin{email: e, creds: c}
		}
	}
	return localLogin{}
}

func containsEmail(accs []Account, email string) bool {
	for _, a := range accs {
		if a.Email == email {
			return true
		}
	}
	return false
}

// migrateAccounts brings older configs to the current model: every tracked
// account is email-keyed and stored. It (1) drops legacy "keychain" placeholder
// entries - the current login is now shown live by cmdShow, not via a config
// entry; (2) converts a legacy typed-alias ("name") stored/op entry to its
// API-verified email, re-keying its creds+cache files. A dead-token legacy
// entry stays flagged for re-add; a stale alias is never promoted to identity.
func migrateAccounts(accs []Account, cur localLogin) []Account {
	changed := false
	out := accs[:0]
	for i := range accs {
		a := accs[i]
		// drop the old keychain placeholder (no stored token to keep)
		if (a.Source == "keychain" || a.Source == "") && a.Email == "" {
			if a.LegacyName != "" {
				os.Remove(filepath.Join(cacheDir(), a.LegacyName+".json"))
			}
			changed = true
			continue
		}
		if a.Email != "" {
			if a.LegacyName != "" {
				a.LegacyName = ""
				changed = true
			}
			// a legacy keychain entry that somehow carries an email -> stored
			if a.Source == "keychain" || a.Source == "" {
				a.Source = "stored"
				changed = true
			}
			out = append(out, a)
			continue
		}
		// stored/op with only a typed alias: re-derive the real email
		c, _, err := getCreds(a, cur)
		if err != nil {
			fmt.Fprintf(os.Stderr, "note: account %q could not be verified (%v) - re-add with `claude-limits add`\n", a.LegacyName, err)
			out = append(out, a)
			continue
		}
		email, err := resolveEmail(c.AccessToken)
		if err != nil || email == "" {
			fmt.Fprintf(os.Stderr, "note: account %q has a dead or unverifiable token (%v) - re-add with `claude-limits add`\n", a.LegacyName, err)
			out = append(out, a)
			continue
		}
		os.Rename(credsPath(a.LegacyName), credsPath(email))
		os.Rename(filepath.Join(cacheDir(), a.LegacyName+".json"), filepath.Join(cacheDir(), email+".json"))
		fmt.Fprintf(os.Stderr, "migrated account %q -> %s (identity verified against the API)\n", a.LegacyName, email)
		a.Email, a.LegacyName, a.Source = email, "", "stored"
		changed = true
		out = append(out, a)
	}
	if changed {
		if err := saveAccounts(out); err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not save migrated accounts.json:", err)
		}
	}
	return out
}

func saveAccounts(accs []Account) error {
	if err := os.MkdirAll(configDir(), 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(accs, "", "  ")
	return atomicWrite(accountsPath(), append(b, '\n'), 0o644)
}

// atomicWrite writes via temp file + rename so a crash never truncates a cred store.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ---- keychain source (primary account, read-only, never refreshed) ----

type keychainBlob struct {
	ClaudeAiOauth struct {
		AccessToken           string   `json:"accessToken"`
		RefreshToken          string   `json:"refreshToken"`
		ExpiresAt             int64    `json:"expiresAt"`
		RefreshTokenExpiresAt int64    `json:"refreshTokenExpiresAt"`
		Scopes                []string `json:"scopes"`
		SubscriptionType      string   `json:"subscriptionType"`
		RateLimitTier         string   `json:"rateLimitTier"`
		Email                 string   `json:"email"` // informational only (added by `claude-limits extract`); identity always re-verified via the API
	} `json:"claudeAiOauth"`
}

// readClaudeCodeCandidates returns every place Claude Code's credentials might
// live, in the deterministic order the current login is most likely FIRST, so
// currentLogin() (which returns the first that resolves to an email) matches
// what `claude` itself shows.
//
// Why enumeration, not a single read (bug fixed 2026-09-08): the macOS keychain
// can hold MULTIPLE generic-password items under service "Claude Code-credentials"
// - here acct="simon" (the live login, written when Claude Code last switched
// accounts) AND a stale acct=<NULL> orphan whose token is revoked. A plain
// `security find-generic-password -s <svc> -w` (no -a) returns just ONE of them,
// and it returned the revoked NULL orphan; the code then fell through to
// ~/.claude/.credentials.json, which lagged a full login. Result: the tool
// showed the wrong account as "(logged in here)". So we read EACH keychain item
// and rank them.
//
// Order: the keychain item whose acct == the OS username first (Claude Code
// writes the active login there), then other keychain items by write-recency
// (mdat), then the plain no-account read (reaches an unnamed/NULL-acct item),
// and ~/.claude/.credentials.json LAST - the file never drives current-login
// when a keychain entry exists (it lagged here). Identity is still resolved from
// each token via the API (identity.go), so a revoked orphan simply fails to
// resolve and is skipped, never guessed and never surfaced as an error account.
func readClaudeCodeCandidates() []*Creds {
	var out []*Creds
	seen := map[string]bool{}
	add := func(c *Creds) {
		if c == nil || c.AccessToken == "" || seen[c.AccessToken] {
			return
		}
		seen[c.AccessToken] = true
		out = append(out, c)
	}
	readAcct := func(acct string) *Creds {
		args := []string{"find-generic-password", "-s", keychainSvc}
		if acct != "" {
			args = append(args, "-a", acct)
		}
		args = append(args, "-w")
		if b, err := exec.Command("security", args...).Output(); err == nil {
			return parseClaudeCodeBlob(bytes.TrimSpace(b))
		}
		return nil
	}

	osUser := os.Getenv("USER")
	// 1. the OS-username item = the active login Claude Code writes.
	if osUser != "" {
		add(readAcct(osUser))
	}
	// 2. every other keychain item under the service, most-recently-written first.
	for _, acct := range keychainAccounts(keychainSvc) {
		if acct == osUser {
			continue
		}
		if acct == "" {
			add(readAcct("")) // NULL-acct item isn't addressable by -a; the plain read reaches it
			continue
		}
		add(readAcct(acct))
	}
	// 3. plain no-account read as a catch-all (also reaches a NULL-acct item).
	add(readAcct(""))
	// 4. the on-disk copy LAST - it can lag the keychain by a whole login.
	home, _ := os.UserHomeDir()
	if raw, err := os.ReadFile(filepath.Join(home, ".claude", ".credentials.json")); err == nil {
		add(parseClaudeCodeBlob(raw))
	}
	return out
}

// keychainAccounts lists the acct names of every generic-password item under a
// service, newest-written (mdat) first. Best-effort: it parses
// `security dump-keychain` (attributes only, no secrets, no prompt); if that is
// unavailable the caller still has the username + no-account reads to fall back
// on. A NULL/absent acct is reported as "".
func keychainAccounts(service string) []string {
	out, err := exec.Command("security", "dump-keychain").Output()
	if err != nil {
		return nil
	}
	type item struct {
		acct string
		mdat string
	}
	var items []item
	var cur item
	var svce string
	haveItem := false
	flush := func() {
		if haveItem && svce == service {
			items = append(items, cur)
		}
	}
	for _, line := range strings.Split(string(out), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "keychain:") { // start of a new item block
			flush()
			cur, svce, haveItem = item{}, "", true
			continue
		}
		switch {
		case strings.HasPrefix(t, `"acct"`):
			cur.acct = keychainBlobValue(t)
		case strings.HasPrefix(t, `"svce"`):
			svce = keychainBlobValue(t)
		case strings.HasPrefix(t, `"mdat"`):
			cur.mdat = keychainQuotedTail(t) // ISO "20260908185816Z"; lexical order == chronological
		}
	}
	flush()
	sort.SliceStable(items, func(i, j int) bool { return items[i].mdat > items[j].mdat })
	names := make([]string, len(items))
	for i, it := range items {
		names[i] = it.acct
	}
	return names
}

// keychainBlobValue extracts the value from `"acct"<blob>="simon"` (or "" for
// `=<NULL>`).
func keychainBlobValue(line string) string {
	i := strings.Index(line, `="`)
	if i < 0 {
		return "" // <NULL> or unset
	}
	rest := line[i+2:]
	if j := strings.LastIndex(rest, `"`); j >= 0 {
		return rest[:j]
	}
	return ""
}

// keychainQuotedTail extracts the trailing quoted string from an mdat line like
// `"mdat"<timedate>=0x...  "20260908185816Z\000"`.
func keychainQuotedTail(line string) string {
	j := strings.LastIndex(line, `"`)
	if j <= 0 {
		return ""
	}
	i := strings.LastIndex(line[:j], `"`)
	if i < 0 {
		return ""
	}
	s := line[i+1 : j]
	return strings.TrimSuffix(s, `\000`)
}

// readKeychainCreds returns this machine's live Claude Code login (the
// highest-priority candidate).
func readKeychainCreds() (*Creds, error) {
	cands := readClaudeCodeCandidates()
	if len(cands) == 0 {
		return nil, fmt.Errorf("no Claude Code credentials found (keychain %q or ~/.claude/.credentials.json): log in with `claude` first", keychainSvc)
	}
	return cands[0], nil
}

func parseClaudeCodeBlob(raw []byte) *Creds {
	var kb keychainBlob
	if json.Unmarshal(raw, &kb) != nil || kb.ClaudeAiOauth.AccessToken == "" {
		return nil
	}
	o := kb.ClaudeAiOauth
	return &Creds{
		AccessToken: o.AccessToken, RefreshToken: o.RefreshToken,
		ExpiresAt: o.ExpiresAt, RefreshTokenExpiresAt: o.RefreshTokenExpiresAt,
		RateLimitTier: o.RateLimitTier, SubscriptionType: o.SubscriptionType,
		Email: o.Email, Scopes: o.Scopes,
	}
}

// ---- stored source (tool-owned, refresh + rotate) ----

func readStoredCreds(name string) (*Creds, error) {
	b, err := os.ReadFile(credsPath(name))
	if err != nil {
		return nil, err
	}
	var c Creds
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", credsPath(name), err)
	}
	return &c, nil
}

func writeStoredCreds(name string, c *Creds) error {
	dir := filepath.Dir(credsPath(name))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return atomicWrite(credsPath(name), append(b, '\n'), 0o600)
}

type refreshResponse struct {
	AccessToken           string `json:"access_token"`
	RefreshToken          string `json:"refresh_token"`
	ExpiresIn             int64  `json:"expires_in"`
	RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in"`
	Scope                 string `json:"scope"` // space-separated
	Account               struct {
		EmailAddress string `json:"email_address"`
	} `json:"account"`
}

// refreshCreds exchanges the refresh token for a new pair. The old refresh
// token is invalidated by this call - the caller MUST persist the result.
func refreshCreds(c *Creds) error {
	body, _ := json.Marshal(map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     oauthClientID,
		"refresh_token": c.RefreshToken,
	})
	req, _ := http.NewRequest("POST", oauthTokenURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// Cloudflare in front of platform.claude.com fingerprints the UA:
	// generic script UAs get 403/1010 or instant 429; the CLI UA passes.
	req.Header.Set("User-Agent", "claude-cli/"+claudeVersion()+" (external, cli)")
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("token refresh: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return fmt.Errorf("token refresh: HTTP %d: %s", resp.StatusCode, truncate(string(data), 200))
	}
	var rr refreshResponse
	if err := json.Unmarshal(data, &rr); err != nil {
		return fmt.Errorf("token refresh: bad response: %w", err)
	}
	applyRefresh(c, rr)
	return nil
}

// applyRefresh folds a token response into the stored pair.
func applyRefresh(c *Creds, rr refreshResponse) {
	now := time.Now().UnixMilli()
	c.AccessToken = rr.AccessToken
	if rr.RefreshToken != "" {
		c.RefreshToken = rr.RefreshToken // rotated - old one is dead
	}
	c.ExpiresAt = now + rr.ExpiresIn*1000
	if rr.RefreshTokenExpiresIn > 0 {
		c.RefreshTokenExpiresAt = now + rr.RefreshTokenExpiresIn*1000
	}
	if rr.Scope != "" {
		c.Scopes = strings.Fields(rr.Scope)
	}
	if rr.Account.EmailAddress != "" {
		c.Email = rr.Account.EmailAddress
		memoizeEmail(c.AccessToken, c.Email) // refresh response IS the API's identity answer
	}
}

// getCreds resolves an account to a usable access token and reports whether the
// account is ACTIVE (the login this machine holds right now) or DORMANT.
//
//   - ACTIVE (acc.Email == cur.email): read Claude Code's LIVE creds and sync
//     the stored copy from them. Claude Code owns rotation while you're on it,
//     so the tool never refreshes here - no two-owner race. The sync keeps the
//     stored pair fresh as of this run, so it still works once you switch away.
//   - DORMANT: use the stored token and SELF-REFRESH it (persisting each rotated
//     pair) so a switched-away account stays alive. Past its ~10-day refresh
//     window it lapses with a clear "switch to it and run add" message.
func getCreds(acc Account, cur localLogin) (*Creds, bool, error) {
	if acc.Email != "" && acc.Email == cur.email && cur.creds != nil {
		if !acc.Unadded { // persist the fresh pair for when this login goes dormant
			_ = writeStoredCreds(acc.Email, cur.creds)
		}
		return cur.creds, true, nil
	}

	c, err := readStoredCreds(acc.key())
	if errors.Is(err, os.ErrNotExist) && acc.Source == "op" && acc.OpRef != "" {
		c, err = seedFromOp(acc) // first use: seed from 1Password, then own it locally
	}
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, fmt.Errorf("no stored token - switch Claude Code to this account and run `claude-limits add`")
		}
		return nil, false, err
	}
	if expired(c.ExpiresAt) {
		if c.RefreshTokenExpiresAt > 0 && time.Now().UnixMilli() > c.RefreshTokenExpiresAt {
			return nil, false, fmt.Errorf("dormant token lapsed (refresh window ended %s ago) - switch Claude Code to this account and run `claude-limits add`", ago(c.RefreshTokenExpiresAt))
		}
		if err := refreshCreds(c); err != nil {
			return nil, false, fmt.Errorf("%w - dormant token could not be refreshed; switch Claude Code to this account and run `claude-limits add`", err)
		}
		if err := writeStoredCreds(acc.key(), c); err != nil {
			return nil, false, fmt.Errorf("CRITICAL: token rotated but could not be saved: %w", err)
		}
	}
	return c, false, nil
}

// pbcopy pipes data into the macOS clipboard.
func pbcopy(data []byte) error {
	cmd := exec.Command("pbcopy")
	cmd.Stdin = bytes.NewReader(data)
	return cmd.Run()
}

// fetchOpCreds reads a credential JSON blob from 1Password via the op CLI
// without persisting anything.
func fetchOpCreds(acc Account) (*Creds, error) {
	out, err := exec.Command("op", "read", acc.OpRef).Output()
	if err != nil {
		return nil, fmt.Errorf("op read %s: %w", acc.OpRef, err)
	}
	c, err := parseCredsInput(bytes.TrimSpace(out))
	if err != nil {
		return nil, fmt.Errorf("op read %s: %w", acc.OpRef, err)
	}
	return c, nil
}

// seedFromOp fetches from 1Password and imports into the local stored file.
// After this, the local file owns the token family (rotation rewrites it
// locally; 1Password is not updated).
func seedFromOp(acc Account) (*Creds, error) {
	c, err := fetchOpCreds(acc)
	if err != nil {
		return nil, err
	}
	if err := writeStoredCreds(acc.key(), c); err != nil {
		return nil, err
	}
	return c, nil
}

// parseCredsInput accepts either the full Claude Code keychain blob
// ({"claudeAiOauth":{...}}) or a bare {accessToken, refreshToken, ...} object.
func parseCredsInput(raw []byte) (*Creds, error) {
	if c := parseClaudeCodeBlob(raw); c != nil && c.RefreshToken != "" {
		return c, nil
	}
	var c Creds
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("expected the keychain JSON blob or {accessToken, refreshToken}: %w", err)
	}
	if c.RefreshToken == "" {
		return nil, errors.New("no refreshToken in input - without it the token cannot outlive its ~8h access window")
	}
	return &c, nil
}

func expired(expiresAtMs int64) bool {
	// 2-minute safety margin so we never hand out a token that dies mid-request
	return time.Now().UnixMilli() > expiresAtMs-2*60*1000
}

func ago(unixMs int64) string {
	return time.Since(time.UnixMilli(unixMs)).Round(time.Minute).String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// claudeVersion returns the newest locally installed Claude Code version
// (for User-Agent headers), falling back to a known-good pin.
func claudeVersion() string {
	if v := os.Getenv("CLAUDE_LIMITS_UA_VERSION"); v != "" {
		return v
	}
	home, _ := os.UserHomeDir()
	entries, err := os.ReadDir(filepath.Join(home, ".local", "share", "claude", "versions"))
	best := ""
	if err == nil {
		for _, e := range entries {
			if n := e.Name(); strings.Count(n, ".") == 2 && semverLess(best, n) {
				best = n
			}
		}
	}
	if best != "" {
		return best
	}
	return "2.1.263"
}

func semverLess(a, b string) bool {
	if a == "" {
		return true
	}
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3 && i < len(pa) && i < len(pb); i++ {
		var x, y int
		fmt.Sscanf(pa[i], "%d", &x)
		fmt.Sscanf(pb[i], "%d", &y)
		if x != y {
			return x < y
		}
	}
	return false
}

var httpClient = &http.Client{Timeout: 30 * time.Second}
