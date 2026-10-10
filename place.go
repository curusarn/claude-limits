package main

// `claude-limits place EMAIL DIR`: give an added account its own Claude Code
// config dir, so `CLAUDE_CONFIG_DIR=DIR claude` runs on that account while the
// default login (and every other dir) stays on its own.
//
// Verified against Claude Code 2.1.296 (2026-10-10) by reading its bundled
// source and running `claude auth status` against a throwaway dir:
//   - with CLAUDE_CONFIG_DIR set, the keychain service becomes
//     "Claude Code-credentials-" + the first 8 hex of sha256(dir), where dir
//     is the variable's value exactly as given (only NFC-normalized; no
//     ~ expansion, no trailing-slash trimming). The docs say the same
//     ("keys the macOS Keychain entry to that directory").
//   - the dir has its own .claude.json (oauthAccount lives there) and its own
//     .credentials.json fallback.
//
// Ownership: an access token pair belongs to exactly one writer, because a
// refresh rotates it and kills every other copy. A placed account's pair is
// MOVED into the dir's keychain item - its stored copy is deleted - and from
// then on Claude Code sessions in that dir own it. claude-limits reads it live
// and never refreshes it, like the default login. With no stored copy, even an
// older claude-limits that doesn't know about placement can't refresh it.
// `unplace` moves it back.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// keychainSvcFor is the keychain service Claude Code uses for a config dir
// ("" = the default dir, no suffix).
func keychainSvcFor(dir string) string {
	if dir == "" {
		return keychainSvc
	}
	sum := sha256.Sum256([]byte(dir))
	return keychainSvc + "-" + hex.EncodeToString(sum[:])[:8]
}

// checkPlaceDir accepts only a spelling of DIR that Claude Code will hash the
// same way every time: absolute, clean (no trailing slash, no ..), ASCII (we
// don't NFC-normalize), and not the default ~/.claude.
func checkPlaceDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%q is not an absolute path", dir)
	}
	if filepath.Clean(dir) != dir {
		return fmt.Errorf("%q is not in clean form - use %q (CLAUDE_CONFIG_DIR must be spelled exactly the same)", dir, filepath.Clean(dir))
	}
	for _, r := range dir {
		if r > 127 {
			return fmt.Errorf("%q has non-ASCII characters - use an ASCII path", dir)
		}
	}
	home, _ := os.UserHomeDir()
	if dir == filepath.Join(home, ".claude") {
		return fmt.Errorf("%q is the default config dir - use `claude-limits switch` for it", dir)
	}
	return nil
}

// readPlacedCreds reads a placed account's live pair from its dir's keychain
// item (or that dir's .credentials.json fallback) and checks it still is that
// account. It never refreshes: Claude Code in that dir owns the rotation.
func readPlacedCreds(acc Account) (*Creds, error) {
	c := readKeychainItemSvc(keychainSvcFor(acc.Dir), keychainAccountName())
	if c == nil {
		if raw, err := os.ReadFile(filepath.Join(acc.Dir, ".credentials.json")); err == nil {
			c = parseClaudeCodeBlob(raw)
		}
	}
	if c == nil || c.AccessToken == "" {
		return nil, fmt.Errorf("placed in %s, but there is no login there (logged out?) - run `CLAUDE_CONFIG_DIR=%s claude` and /login", acc.Dir, acc.Dir)
	}
	email, err := resolveEmail(c.AccessToken)
	if err != nil {
		if isHTTPStatus(err, 401) {
			return nil, fmt.Errorf("the login in %s has an expired access token - any `claude` session there refreshes it (claude-limits never does)", acc.Dir)
		}
		return nil, err
	}
	if email != acc.Email {
		return nil, fmt.Errorf("%s is logged into %s, not %s", acc.Dir, email, acc.Email)
	}
	c.Email = email
	return c, nil
}

// claudeRunningIn reports pids of Claude Code sessions alive in dir: each
// session registers itself in DIR/sessions as <pid>.<hash>.key from start and
// <pid>.json once past onboarding (verified in Claude Code 2.1.296). A file
// whose pid is gone is a leftover.
func claudeRunningIn(dir string) []string {
	entries, _ := os.ReadDir(filepath.Join(dir, "sessions"))
	seen := map[int]bool{}
	var pids []string
	for _, e := range entries {
		head, _, _ := strings.Cut(e.Name(), ".")
		pid, err := strconv.Atoi(head)
		if err != nil || pid <= 0 || seen[pid] {
			continue
		}
		seen[pid] = true
		if err := syscall.Kill(pid, 0); err == nil || errors.Is(err, syscall.EPERM) {
			pids = append(pids, strconv.Itoa(pid))
		}
	}
	return pids
}

// writeDirOauthAccount makes DIR/.claude.json name the placed account (the
// profile Claude Code shows in /status and sends as the org), creating the
// file when the dir is new.
func writeDirOauthAccount(dir string, p oauthProfile) error {
	path := filepath.Join(dir, ".claude.json")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		b, _ := json.MarshalIndent(map[string]any{"oauthAccount": map[string]any{
			"accountUuid":      p.AccountUUID,
			"emailAddress":     p.Email,
			"organizationUuid": p.OrgUUID,
		}}, "", "  ")
		return atomicWrite(path, append(b, '\n'), 0o600)
	}
	return updateOauthAccount(path, p)
}

func cmdPlace(args []string) int {
	if !usesKeychain() {
		fmt.Fprintln(os.Stderr, "error: place/unplace need the macOS keychain (one config dir per account); not available here")
		return 1
	}
	fs := flag.NewFlagSet("place", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: claude-limits place EMAIL DIR   (then run: CLAUDE_CONFIG_DIR=DIR claude)")
	}
	fs.Parse(args)
	if fs.NArg() != 2 {
		fs.Usage()
		return 2
	}
	email, dir := fs.Arg(0), fs.Arg(1)
	if err := checkPlaceDir(dir); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	accs, err := loadAccounts()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	idx := -1
	for i, a := range accs {
		if a.Email == email {
			idx = i
		}
		if a.Dir == dir && a.Email != email {
			fmt.Fprintf(os.Stderr, "error: %s already holds %s - unplace it first\n", dir, a.Email)
			return 1
		}
	}
	if idx < 0 {
		fmt.Fprintf(os.Stderr, "error: %q is not an added account (see `claude-limits accounts`)\n", email)
		return 1
	}
	acc := accs[idx]
	if acc.Dir == dir {
		fmt.Printf("%s is already placed in %s\n", email, dir)
		return 0
	}
	if acc.Dir != "" {
		fmt.Fprintf(os.Stderr, "error: %s is placed in %s - unplace it first (one account, one owner)\n", email, acc.Dir)
		return 1
	}
	cur := currentLogin()
	if cur.email == email {
		fmt.Fprintf(os.Stderr, "error: %s is Claude Code's default login - switch the default to another account first (one account, one owner)\n", email)
		return 1
	}
	svc := keychainSvcFor(dir)
	if there := readKeychainItemSvc(svc, keychainAccountName()); there != nil {
		e, _ := resolveEmail(there.AccessToken)
		if e != email {
			fmt.Fprintf(os.Stderr, "error: %s already has a login (%s) - pick another dir\n", dir, orUnknown(e))
			return 1
		}
		// already logged in there by hand: adopt it, drop our stale copy
		return finishPlace(accs, idx, dir)
	}

	creds, _, err := getCreds(acc, cur) // dormant: refreshes + persists if expired
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s: %v\n", email, err)
		return 1
	}
	prof, err := liveProfile(email, creds, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: NOT placed -", err)
		return 1
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if err := writeKeychainCredsSvc(svc, creds); err != nil {
		fmt.Fprintln(os.Stderr, "error: NOT placed -", err)
		return 1
	}
	if err := writeDirOauthAccount(dir, prof); err != nil {
		fmt.Fprintf(os.Stderr, "warning: %s/.claude.json not written (%v) - /status there may name no account until it refetches\n", dir, err)
	}
	return finishPlace(accs, idx, dir)
}

// finishPlace records the placement and deletes the stored copy, so only the
// dir's keychain item holds the pair.
func finishPlace(accs []Account, idx int, dir string) int {
	email := accs[idx].Email
	accs[idx].Dir = dir
	if err := saveAccounts(accs); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if err := os.Remove(credsPath(email)); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "warning: could not delete the stored copy (%v) - delete %s by hand\n", err, credsPath(email))
	}
	fmt.Printf("placed %s in %s\n", email, dir)
	fmt.Fprintf(os.Stderr, "Start sessions on it with:  CLAUDE_CONFIG_DIR=%s claude\n", dir)
	return 0
}

func cmdUnplace(args []string) int {
	if !usesKeychain() {
		fmt.Fprintln(os.Stderr, "error: place/unplace need the macOS keychain (one config dir per account); not available here")
		return 1
	}
	fs := flag.NewFlagSet("unplace", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: claude-limits unplace EMAIL   (logs its dir out; stop the sessions there first)")
	}
	fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	email := fs.Arg(0)
	accs, err := loadAccounts()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	idx := -1
	for i, a := range accs {
		if a.Email == email {
			idx = i
		}
	}
	if idx < 0 || accs[idx].Dir == "" {
		fmt.Fprintf(os.Stderr, "error: %q is not placed in a config dir\n", email)
		return 1
	}
	acc := accs[idx]
	// A session still running there would refresh its in-memory pair after we
	// take it, and kill our copy.
	if pids := claudeRunningIn(acc.Dir); len(pids) > 0 {
		fmt.Fprintf(os.Stderr, "error: Claude Code sessions still run in %s (pids %s) - stop them first\n", acc.Dir, strings.Join(pids, " "))
		return 1
	}
	creds, err := readPlacedCreds(acc)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: NOT unplaced -", err)
		return 1
	}
	if err := writeStoredCreds(email, creds); err != nil {
		fmt.Fprintln(os.Stderr, "error: NOT unplaced -", err)
		return 1
	}
	svc := keychainSvcFor(acc.Dir)
	if out, err := exec.Command("security", "delete-generic-password", "-s", svc, "-a", keychainAccountName()).CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "error: stored the pair, but could not delete keychain item %q: %v: %s - delete it by hand, then run unplace again\n", svc, err, strings.TrimSpace(string(out)))
		return 1
	}
	os.Remove(filepath.Join(acc.Dir, ".credentials.json"))
	accs[idx].Dir = ""
	if err := saveAccounts(accs); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("unplaced %s from %s (that dir is logged out; claude-limits keeps the account alive again)\n", email, acc.Dir)
	return 0
}

// liveProfile proves a pair is alive and is this account (refreshing once on
// a 401) and returns its profile. Shared by switch and place: never write an
// unverified token into a Claude Code login. fallbackScopes fill in when even
// a refresh returns none (the outgoing login's: same client, same grant).
func liveProfile(email string, creds *Creds, fallbackScopes []string) (oauthProfile, error) {
	prof, err := fetchProfile(creds.AccessToken)
	if err != nil && isHTTPStatus(err, 401) && creds.RefreshToken != "" {
		if rerr := refreshCreds(creds); rerr == nil {
			if werr := writeStoredCreds(email, creds); werr != nil {
				return prof, fmt.Errorf("CRITICAL: token rotated but could not be saved: %v", werr)
			}
			prof, err = fetchProfile(creds.AccessToken)
		}
	}
	if err != nil {
		return prof, fmt.Errorf("%s's stored token does not work (%v). Log into it once with `claude` and run `claude-limits add`", email, err)
	}
	if prof.Email != email {
		return prof, fmt.Errorf("stored token for %s belongs to %q", email, prof.Email)
	}
	// Claude Code gates refresh, profile fetch and org resolution on the
	// scopes list, so never hand it an empty one. A pair stored before scopes
	// were kept gets them from a refresh (the token response carries `scope`).
	if len(creds.Scopes) == 0 {
		if err := refreshCreds(creds); err != nil {
			return prof, err
		}
		if err := writeStoredCreds(email, creds); err != nil {
			return prof, fmt.Errorf("CRITICAL: token rotated but could not be saved: %v", err)
		}
		if len(creds.Scopes) == 0 {
			creds.Scopes = fallbackScopes
		}
		if len(creds.Scopes) == 0 {
			return prof, fmt.Errorf("no OAuth scopes known for %s; log into it once with `claude` and run `claude-limits add`", email)
		}
	}
	return prof, nil
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown account"
	}
	return s
}
