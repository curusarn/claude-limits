package main

// `claude-limits switch`: make Claude Code use another added account without a
// browser login, by writing that account's stored token pair into the keychain
// item Claude Code reads.
//
// Verified against Claude Code 2.1.267 (2026-09-10) by reading its bundled
// source:
//   - it reads   `security find-generic-password -a $USER -w -s "Claude Code-credentials"`
//     (account = process.env.USER || os.userInfo().username), caching the result
//     in memory for 30s;
//   - it writes  `add-generic-password -U -a $USER -s <svc> -X <hex JSON>` via
//     `security -i` on stdin - exactly what writeKeychainCreds does, so the item
//     keeps the same ACL and there is no prompt;
//   - before refreshing it takes ~/.claude/.oauth_refresh.lock, re-reads the
//     keychain and, if the access token there differs from the one in memory,
//     ADOPTS it instead of refreshing ("refresh race resolved"). On a 401 it
//     re-reads the keychain the same way. So a running session never rotates
//     the old account's refresh token over the swapped-in pair; it simply
//     moves to the new account at its next token check.
//   - ~/.claude.json's oauthAccount {accountUuid, emailAddress, organizationUuid}
//     is refetched from the profile API only when profileFetchedAt is older
//     than 24h; until then /status shows it and a few features send it as
//     x-organization-uuid. We rewrite those three fields and drop
//     profileFetchedAt so it refetches on next start.
//   - ~/.claude/.credentials.json is a plaintext FALLBACK, written only when the
//     keychain write fails; it is not a mirror. Not touched here.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
)

// keychainAccountName mirrors Claude Code's account-name rule for the item.
func keychainAccountName() string {
	n := os.Getenv("USER")
	if n == "" {
		if u, err := user.Current(); err == nil {
			n = u.Username
		}
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9._-]+$`).MatchString(n) {
		return "claude-code-user"
	}
	return n
}

// keychainBlobJSON renders the pair in the exact shape Claude Code writes.
func keychainBlobJSON(c *Creds) []byte {
	scopes := c.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	b, _ := json.Marshal(map[string]any{"claudeAiOauth": map[string]any{
		"accessToken":           c.AccessToken,
		"refreshToken":          c.RefreshToken,
		"expiresAt":             c.ExpiresAt,
		"refreshTokenExpiresAt": c.RefreshTokenExpiresAt,
		"scopes":                scopes,
		"subscriptionType":      c.SubscriptionType,
		"rateLimitTier":         c.RateLimitTier,
	}})
	return b
}

// readKeychainItem reads one keychain item by account name (nil if absent).
func readKeychainItem(acct string) *Creds {
	out, err := exec.Command("security", "find-generic-password", "-s", keychainSvc, "-a", acct, "-w").Output()
	if err != nil {
		return nil
	}
	return parseClaudeCodeBlob([]byte(strings.TrimSpace(string(out))))
}

// writeKeychainCreds updates (-U) Claude Code's keychain item in place, the
// same way Claude Code does it: the command on `security -i` stdin, payload as
// hex (-X) so quoting can't bite.
func writeKeychainCreds(c *Creds) error {
	blob := keychainBlobJSON(c)
	cmdLine := fmt.Sprintf("add-generic-password -U -a %q -s %q -X %q\n",
		keychainAccountName(), keychainSvc, hex.EncodeToString(blob))
	cmd := exec.Command("security", "-i")
	cmd.Stdin = strings.NewReader(cmdLine)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("security add-generic-password: %v: %s", err, strings.TrimSpace(string(out)))
	}
	// read back: the write must be what Claude Code will see
	got := readKeychainItem(keychainAccountName())
	if got == nil || got.AccessToken != c.AccessToken {
		return errors.New("keychain write did not stick (read-back mismatch)")
	}
	return nil
}

func claudeJSONPath() string {
	if d := os.Getenv("CLAUDE_CONFIG_DIR"); d != "" {
		return filepath.Join(d, ".claude.json")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude.json")
}

// updateOauthAccount rewrites the identity part of ~/.claude.json's
// oauthAccount and drops the rest of that block (per-account fields like
// displayName / billingType / profileFetchedAt), so Claude Code refetches the
// profile for the new account on its next start. Everything else in the file is
// preserved byte-for-byte in value (key order may change).
func updateOauthAccount(path string, p oauthProfile) error {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // nothing to fix up
	}
	if err != nil {
		return err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	oa, _ := json.Marshal(map[string]any{
		"accountUuid":      p.AccountUUID,
		"emailAddress":     p.Email,
		"organizationUuid": p.OrgUUID,
	})
	m["oauthAccount"] = oa
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	return atomicWrite(path, append(out, '\n'), mode)
}

// cmdSwitch swaps Claude Code's login to another added account.
func cmdSwitch(args []string) int {
	fs := flag.NewFlagSet("switch", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: claude-limits switch [EMAIL]   (no EMAIL = pick interactively)")
	}
	fresh := fs.Bool("fresh", false, "bypass the on-disk cache")
	fs.Parse(args)
	target := fs.Arg(0)

	// Show the usual limits first: that's what you pick by.
	accs, cur, code := showUsage(false, *fresh, "")
	if accs == nil {
		return code
	}
	var emails []string
	for _, a := range accs {
		if a.Email != "" && !a.Unadded {
			emails = append(emails, a.Email)
		}
	}
	if len(emails) == 0 {
		fmt.Fprintln(os.Stderr, "error: no added accounts to switch to - run `claude-limits add` on each account first")
		return 1
	}

	// Keep the outgoing login alive as a dormant account: sync its fresh pair
	// to the store before it is overwritten in the keychain.
	if cur.email != "" && cur.creds != nil && containsEmail(accs, cur.email) {
		if err := writeStoredCreds(cur.email, cur.creds); err != nil {
			fmt.Fprintf(os.Stderr, "error: could not save the current login (%s) before switching: %v\n", cur.email, err)
			return 1
		}
	}

	if target == "" {
		var err error
		target, err = pickAccount(emails, cur.email)
		if errors.Is(err, errCancelled) {
			if cur.email != "" {
				fmt.Fprintln(os.Stderr, "cancelled - Claude Code is still logged in as", cur.email)
			} else {
				fmt.Fprintln(os.Stderr, "cancelled - nothing changed")
			}
			return 0
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	}
	if !containsEmail(accs, target) {
		fmt.Fprintf(os.Stderr, "error: %q is not an added account (see `claude-limits accounts`)\n", target)
		return 1
	}
	if target == cur.email {
		fmt.Printf("Claude Code is already logged in as %s\n", target)
		return 0
	}
	if cur.email == "" {
		fmt.Fprintln(os.Stderr, "note: could not verify the current login; the outgoing account is not synced (its stored copy may lag)")
	}

	var acc Account
	for _, a := range accs {
		if a.Email == target {
			acc = a
		}
	}
	creds, _, err := getCreds(acc, cur) // dormant path: refreshes + persists if expired
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s: %v\n", target, err)
		return 1
	}
	// Never write an unverified token into Claude Code's login: prove the pair
	// is alive and really is this account, and pick up its ids for ~/.claude.json.
	prof, err := fetchProfile(creds.AccessToken)
	if err != nil && isHTTPStatus(err, 401) && creds.RefreshToken != "" {
		if rerr := refreshCreds(creds); rerr == nil {
			if werr := writeStoredCreds(target, creds); werr != nil {
				fmt.Fprintf(os.Stderr, "error: CRITICAL: token rotated but could not be saved: %v\n", werr)
				return 1
			}
			prof, err = fetchProfile(creds.AccessToken)
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: NOT switched - %s's stored token does not work (%v). Log into it once with `claude` and run `claude-limits add`.\n", target, err)
		return 1
	}
	if prof.Email != target {
		fmt.Fprintf(os.Stderr, "error: NOT switched - stored token for %s belongs to %q\n", target, prof.Email)
		return 1
	}
	// Claude Code gates refresh, profile fetch and org resolution on the scopes
	// list, so never hand it an empty one. A pair stored before scopes were
	// kept gets them from a refresh (the token response carries `scope`);
	// failing that, the outgoing login's scopes (same client, same grant).
	if len(creds.Scopes) == 0 {
		if err := refreshCreds(creds); err != nil {
			fmt.Fprintf(os.Stderr, "error: NOT switched - %s: %v\n", target, err)
			return 1
		}
		if err := writeStoredCreds(target, creds); err != nil {
			fmt.Fprintf(os.Stderr, "error: CRITICAL: token rotated but could not be saved: %v\n", err)
			return 1
		}
		if len(creds.Scopes) == 0 && cur.creds != nil {
			creds.Scopes = cur.creds.Scopes
		}
		if len(creds.Scopes) == 0 {
			fmt.Fprintf(os.Stderr, "error: NOT switched - no OAuth scopes known for %s; log into it once with `claude` and run `claude-limits add`\n", target)
			return 1
		}
	}

	if err := writeKeychainCreds(creds); err != nil {
		fmt.Fprintln(os.Stderr, "error: NOT switched -", err)
		return 1
	}
	if err := updateOauthAccount(claudeJSONPath(), prof); err != nil {
		fmt.Fprintf(os.Stderr, "warning: keychain switched but ~/.claude.json not updated (%v) - /status may show the old email for up to 24h\n", err)
	}
	fmt.Printf("switched Claude Code to %s\n", target)
	fmt.Fprintln(os.Stderr, "New `claude` sessions use it right away. Sessions already running move over")
	fmt.Fprintln(os.Stderr, "at their next token check (at the latest when their access token expires).")
	return 0
}

// errCancelled means the user backed out of the interactive pick (esc/q/ctrl-c
// or no selection) - a normal choice, not a failure.
var errCancelled = errors.New("cancelled")

// pickAccount is an arrow-key menu on /dev/tty (so it works with stdout
// piped). Raw mode via stty - no terminal dependency. Enter selects; Esc, q or
// Ctrl-C cancel; j/k also move.
func pickAccount(emails []string, current string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("no terminal for an interactive pick - pass the email: claude-limits switch EMAIL")
	}
	defer tty.Close()
	saved, err := stty(tty, "-g")
	if err != nil {
		return "", fmt.Errorf("stty: %v - pass the email: claude-limits switch EMAIL", err)
	}
	if _, err := stty(tty, "raw", "-echo"); err != nil {
		return "", fmt.Errorf("stty raw: %v", err)
	}
	defer stty(tty, strings.TrimSpace(saved))

	p := colors()
	sel := 0
	for i, e := range emails {
		if e == current {
			sel = (i + 1) % len(emails) // default to the next one: you switch AWAY
		}
	}
	// raw mode: \n no longer implies \r, so every line ends in \r\n
	w := func(f string, a ...any) { fmt.Fprintf(tty, f, a...) }
	draw := func(first bool) {
		if !first {
			w("\x1b[%dA", len(emails)) // back to the first row
		}
		for i, e := range emails {
			tag := ""
			if e == current {
				tag = p.dim + "  (logged in)" + p.reset
			}
			w("\x1b[2K") // clear the row
			if i == sel {
				w("  %s❯ %s%s%s%s\r\n", p.crail, p.bold, e, p.reset, tag)
			} else {
				w("    %s%s%s%s\r\n", p.dim, e, p.reset, tag)
			}
		}
	}
	w("\r\n%sSwitch Claude Code to%s  %s↑/↓ move · enter select · esc cancel%s\r\n", p.bold, p.reset, p.dim, p.reset)
	w("\x1b[?25l") // hide cursor
	defer w("\x1b[?25h")
	draw(true)

	buf := make([]byte, 8)
	for {
		n, err := tty.Read(buf)
		if err != nil || n == 0 {
			return "", errCancelled
		}
		switch {
		case n >= 3 && buf[0] == 0x1b && buf[1] == '[' && buf[2] == 'A', n == 1 && buf[0] == 'k':
			sel = (sel + len(emails) - 1) % len(emails)
		case n >= 3 && buf[0] == 0x1b && buf[1] == '[' && buf[2] == 'B', n == 1 && buf[0] == 'j':
			sel = (sel + 1) % len(emails)
		case n == 1 && (buf[0] == '\r' || buf[0] == '\n'):
			w("\r\n")
			return emails[sel], nil
		case n == 1 && (buf[0] == 0x1b || buf[0] == 'q' || buf[0] == 3):
			w("\r\n")
			return "", errCancelled
		default:
			continue
		}
		draw(false)
	}
}

// stty runs stty against the given terminal and returns its output.
func stty(tty *os.File, args ...string) (string, error) {
	cmd := exec.Command("stty", args...)
	cmd.Stdin = tty
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}
