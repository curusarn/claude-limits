package main

// claude-limits: Claude usage limits for multiple accounts, side by side.
//
// The model (see `claude-limits help`):
//   - `claude-limits`     shows every account you've added, plus the one this
//                         machine is logged into right now.
//   - `claude-limits add` adds whatever account this machine is CURRENTLY logged
//                         into. Do it, switch Claude Code to your next account,
//                         do it again - they accumulate and each stays forever.
//
// Identity is the account EMAIL as verified against the API from its own token
// (identity.go); there are no human-typed names, so data can never render under
// the wrong account.
//
// Token handling is automatic and never fights Claude Code: the account you're
// logged into is read LIVE from Claude Code's keychain (Claude Code owns its
// rotation); an account you've switched away from is kept alive by the tool
// self-refreshing its stored token. See getCreds in creds.go.

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sync"
)

// injected at release time via -ldflags -X main.version=...; "dev" for local builds
var version = "dev"

func main() {
	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "add", "add-account":
			os.Exit(cmdAdd(args[1:]))
		case "remove-account", "remove":
			os.Exit(cmdRemoveAccount(args[1:]))
		case "accounts":
			os.Exit(cmdAccounts())
		case "extract": // secondary: emit this login's blob for another machine
			os.Exit(cmdExtract(args[1:]))
		case "help", "--help", "-h":
			printHelp()
			return
		case "version", "--version", "-v":
			fmt.Println("claude-limits", version)
			return
		}
	}
	os.Exit(cmdShow(args))
}

func printHelp() {
	fmt.Print(`claude-limits - Claude usage limits for multiple accounts, side by side.

  claude-limits            show usage for every account you've added, plus the
                           account this machine is logged into right now
  claude-limits add        add the account this machine is CURRENTLY logged into

Add your accounts one at a time: run 'add', switch Claude Code to the next
account, run 'add' again. They accumulate and each stays tracked forever - the
tool refreshes a switched-away account's token on its own, and reads the one
you're currently on live from Claude Code (so it never fights it).

  claude-limits --json         machine-readable output
  claude-limits --fresh        bypass the on-disk cache
  claude-limits --account E    show only one account (by email)
  claude-limits accounts       list added accounts
  claude-limits remove-account EMAIL   forget an account

Advanced (adding an account from a DIFFERENT machine, no login switch):
  on that machine:  claude-limits extract --copy
  on this machine:  claude-limits add --token      (paste the blob, or pipe it)
`)
}

func cmdShow(args []string) int {
	fs := flag.NewFlagSet("claude-limits", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "machine-readable JSON output")
	fresh := fs.Bool("fresh", false, "bypass the on-disk cache")
	only := fs.String("account", "", "show only this account (email)")
	fs.Parse(args)

	accs, err := loadAccounts()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	cur := currentLogin()
	accs = migrateAccounts(accs, cur) // one-time: legacy shapes -> email-keyed stored
	// Always surface the current login: if it isn't added yet, show it live with
	// a nudge (display-only, never persisted) so a fresh run is never blank.
	if cur.email != "" && !containsEmail(accs, cur.email) {
		accs = append(accs, Account{Source: "stored", Email: cur.email, Unadded: true})
	}
	if *only != "" {
		var filtered []Account
		for _, a := range accs {
			if a.Email == *only || a.LegacyName == *only {
				filtered = append(filtered, a)
			}
		}
		if len(filtered) == 0 {
			fmt.Fprintf(os.Stderr, "error: no account named %q (see `claude-limits accounts`)\n", *only)
			return 1
		}
		accs = filtered
	}
	if len(accs) == 0 {
		fmt.Fprintln(os.Stderr, "No accounts. Log into Claude Code, then run `claude-limits add`.")
		return 1
	}

	// fetch accounts concurrently - each is one HTTP GET (or a cache read)
	results := make([]AccountResult, len(accs))
	var wg sync.WaitGroup
	for i, acc := range accs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = collect(acc, cur, *fresh)
		}()
	}
	wg.Wait()

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(results)
	} else {
		render(results)
	}
	for _, r := range results {
		if r.Err != "" && r.Limits == nil {
			return 1
		}
	}
	return 0
}

func cmdAccounts() int {
	accs, err := loadAccounts()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if len(accs) == 0 {
		fmt.Println("(none added yet - run `claude-limits add`)")
		return 0
	}
	for _, a := range accs {
		name := a.Email
		if name == "" && a.LegacyName != "" {
			name = a.LegacyName + " (unverified - re-add)"
		}
		if name == "" {
			name = "(unresolved)"
		}
		extra := ""
		if a.OpRef != "" {
			extra = "  " + a.OpRef
		}
		fmt.Printf("%-40s %s%s\n", name, a.Source, extra)
	}
	return 0
}

// cmdAdd adds the account this machine is CURRENTLY logged into (the primary
// path). With --token / a piped blob it instead imports an account from another
// machine. Adding is idempotent and accumulative: re-adding the current login
// just refreshes its stored token from Claude Code.
func cmdAdd(args []string) int {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	token := fs.Bool("token", false, "add an account from ANOTHER machine by pasting its `extract` blob on stdin")
	fromOp := fs.String("from-op", "", "add a stored account seeded from a 1Password field (op://vault/item/field)")
	fs.Parse(args)
	if rest := fs.Args(); len(rest) > 0 {
		fmt.Fprintf(os.Stderr, "note: ignoring %q - accounts are identified by their API-verified email, not a typed name\n", rest[0])
		fs.Parse(rest[1:])
	}

	accs, err := loadAccounts()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	// Secondary path: import a token blob (cross-machine). Triggered explicitly
	// by --token/--from-op, or implicitly when a blob is piped in.
	if *token || *fromOp != "" || !stdinIsTTY() {
		return addFromToken(accs, *fromOp)
	}

	// Primary path: capture this machine's current login.
	cur := currentLogin()
	if cur.email == "" || cur.creds == nil {
		fmt.Fprintln(os.Stderr, "error: could not read/verify this machine's Claude Code login - log in with `claude` first")
		return 1
	}
	creds := cur.creds
	creds.Email = cur.email

	if containsEmail(accs, cur.email) {
		// idempotent re-add: sync the stored token from Claude Code's fresh one
		if err := writeStoredCreds(cur.email, creds); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Printf("%s is already added - synced its token from this machine's current login\n", cur.email)
		return 0
	}

	raw, err := validateImport(creds) // proves the pair is live before we save
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: NOT saved - %v\n", err)
		return 1
	}
	if err := writeStoredCreds(cur.email, creds); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	accs = append(accs, Account{Source: "stored", Email: cur.email})
	if err := saveAccounts(accs); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	writeCache(cur.email, raw)
	fmt.Printf("added %s\n", cur.email)
	fmt.Fprintln(os.Stderr, "It now stays tracked. Switch Claude Code to another account and run `add` again to stack it.")
	return 0
}

// addFromToken imports an account from another machine: a blob from
// `claude-limits extract` over there, read on stdin (or a 1Password field).
func addFromToken(accs []Account, opRef string) int {
	var creds *Creds
	var err error
	source := "stored"
	if opRef != "" {
		source = "op"
		creds, err = fetchOpCreds(Account{Source: "op", OpRef: opRef})
	} else {
		if stdinIsTTY() {
			fmt.Fprintln(os.Stderr, "Paste the blob from `claude-limits extract` on the OTHER machine, then Ctrl-D.")
			fmt.Fprintln(os.Stderr, "Do it within a minute: the token is single-use and rotation kills the copy.")
		}
		var raw []byte
		raw, err = io.ReadAll(os.Stdin)
		if err == nil {
			creds, err = parseCredsInput(raw)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	rawUsage, verr := validateImport(creds)
	if verr != nil {
		fmt.Fprintf(os.Stderr, "error: NOT saved - %v\n", verr)
		return 1
	}
	email, ierr := resolveEmail(creds.AccessToken)
	if email == "" && creds.Email != "" {
		email = creds.Email
	}
	if email == "" {
		fmt.Fprintf(os.Stderr, "error: NOT saved - could not verify the account's identity (%v)\n", ierr)
		return 1
	}
	if containsEmail(accs, email) {
		fmt.Fprintf(os.Stderr, "error: %s is already added\n", email)
		return 1
	}
	if err := writeStoredCreds(email, creds); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	accs = append(accs, Account{Source: source, Email: email, OpRef: opRef})
	if err := saveAccounts(accs); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	writeCache(email, rawUsage)
	fmt.Printf("added %s (imported)\n", email)
	return 0
}

// validateImport proves a candidate pair is alive before it is ever saved: hit
// the usage API, and on 401 try one in-memory refresh (which also fills in the
// account email). Nothing is persisted here.
func validateImport(creds *Creds) ([]byte, error) {
	_, raw, err := fetchUsage(creds.AccessToken)
	if err == nil {
		return raw, nil
	}
	if !isHTTPStatus(err, 401) || creds.RefreshToken == "" {
		return nil, err
	}
	if rerr := refreshCreds(creds); rerr != nil {
		return nil, fmt.Errorf("these credentials are already revoked - Claude Code rotates them on every login/refresh, so an extracted pair goes stale as soon as the source rotates. Re-extract on the source machine and import within a minute. (usage: %v; refresh: %v)", err, rerr)
	}
	_, raw, err = fetchUsage(creds.AccessToken)
	return raw, err
}

// extractLocalCreds picks the freshest of Claude Code's credential copies that
// actually VALIDATES against the usage API (the copies drift a rotation apart,
// and the stale one is revoked).
func extractLocalCreds() (*Creds, error) {
	cands := readClaudeCodeCandidates()
	if len(cands) == 0 {
		return nil, fmt.Errorf("no Claude Code credentials found on this machine: log in with `claude` first")
	}
	for _, c := range cands {
		_, _, err := fetchUsage(c.AccessToken)
		if err == nil {
			return c, nil
		}
		if !isHTTPStatus(err, 401) {
			return nil, fmt.Errorf("could not validate the local credentials: %v (the usage API rate-limits per account - wait a minute and retry)", err)
		}
	}
	return nil, fmt.Errorf("every local Claude Code credential copy is revoked - run any `claude` command (or /login) to freshen them, then re-run immediately")
}

// cmdExtract (advanced) emits this machine's login as a validated blob to carry
// to another machine. On this machine you never need it - the account already
// shows via `claude-limits`.
func cmdExtract(args []string) int {
	fs := flag.NewFlagSet("extract", flag.ExitOnError)
	copyFlag := fs.Bool("copy", false, "copy the blob to the clipboard (pbcopy) instead of printing it")
	fs.Parse(args)

	c, err := extractLocalCreds()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if e, _ := resolveEmail(c.AccessToken); e != "" {
		c.Email = e
	}
	blob, _ := json.Marshal(map[string]any{"claudeAiOauth": map[string]any{
		"accessToken":           c.AccessToken,
		"refreshToken":          c.RefreshToken,
		"expiresAt":             c.ExpiresAt,
		"refreshTokenExpiresAt": c.RefreshTokenExpiresAt,
		"subscriptionType":      c.SubscriptionType,
		"rateLimitTier":         c.RateLimitTier,
		"email":                 c.Email,
	}})
	who := c.Email
	if who == "" {
		who = "unknown email"
	}
	if *copyFlag {
		if err := pbcopy(blob); err != nil {
			fmt.Fprintln(os.Stderr, "error: pbcopy:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "validated credential blob for %s copied to clipboard.\n", who)
	} else {
		os.Stdout.Write(append(blob, '\n'))
		fmt.Fprintf(os.Stderr, "validated credential blob for %s.\n", who)
	}
	fmt.Fprintln(os.Stderr, "On THIS machine you don't need this - the account already shows via `claude-limits`.")
	fmt.Fprintln(os.Stderr, "Use it only to track this account from ANOTHER machine: run `claude-limits add --token`")
	fmt.Fprintln(os.Stderr, "there within a minute (single-use token - rotation kills the copy).")
	return 0
}

func cmdRemoveAccount(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: claude-limits remove-account <email>")
		return 2
	}
	name := args[0]
	accs, err := loadAccounts()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	kept := accs[:0]
	found := false
	for _, a := range accs {
		if a.Email == name || (a.Email == "" && a.LegacyName == name) {
			found = true
			os.Remove(credsPath(a.key()))
			os.Remove(cacheDir() + "/" + a.key() + ".json")
			continue
		}
		kept = append(kept, a)
	}
	if !found {
		fmt.Fprintf(os.Stderr, "error: no account %q\n", name)
		return 1
	}
	if err := saveAccounts(kept); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("removed %q\n", name)
	return 0
}

func stdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
