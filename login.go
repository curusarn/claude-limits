package main

// `claude-limits login`: add an account by logging into Claude in the browser,
// instead of `add` (which captures the account this machine is CURRENTLY logged
// into via Claude Code's keychain). `login` needs no prior Claude Code login for
// the account, so you can stack an account you've never switched to here.
//
// It runs Claude Code's own OAuth flow, with values read out of the installed
// Claude Code bundle (2.1.269, 2026-09-12) so they stay identical to what
// `claude` itself sends:
//   - authorize:  GET  <authorize base>
//       ?code=true&client_id=<CLIENT_ID>&response_type=code
//       &redirect_uri=<loopback|manual>&scope=<claudeCodeScopes>
//       &code_challenge=<S256>&code_challenge_method=S256&state=<rand>
//     The authorize base is the Claude subscription login by default
//     (https://claude.com/cai/oauth/authorize), or the Anthropic Console login
//     (https://platform.claude.com/oauth/authorize) with `--console`. Since this
//     tool tracks subscription limits, subscription is the sensible default.
//   - exchange:   POST https://platform.claude.com/v1/oauth/token  (oauthTokenURL)
//       {grant_type:"authorization_code", code, redirect_uri, client_id,
//        code_verifier, state}
//
// PKCE: code_verifier = base64url(32 random bytes); challenge = base64url(sha256).
// state is a second 32-byte base64url value, verified on the callback (CSRF).
//
// Two redirect modes, exactly as Claude Code offers:
//   - loopback (default): a local http server on 127.0.0.1:<ephemeral> catches
//     the redirect to http://localhost:<port>/callback - no copy/paste.
//   - --manual: redirect to the hosted MANUAL_REDIRECT_URL, which shows a
//     "<code>#<state>" string the user pastes back (for headless/SSH).
//
// The tokens minted here are a SEPARATE family from Claude Code's, so this never
// touches or races Claude Code's login: the account is stored + tool-owned and
// self-refreshed, just like one added via `add` and then switched away from.

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const (
	// Claude Code offers two authorize endpoints (read from its bundle): the
	// Claude.ai subscription login (Pro/Max) and the Anthropic Console login
	// (API/billing accounts). This tool is about SUBSCRIPTION usage limits, so
	// the subscription flow is the default; `--console` selects the other.
	oauthAuthorizeClaudeAI = "https://claude.com/cai/oauth/authorize"      // subscription (loginWithClaudeAi)
	oauthAuthorizeConsole  = "https://platform.claude.com/oauth/authorize" // Anthropic Console
	oauthManualRedirect    = "https://platform.claude.com/oauth/code/callback"
	loginTimeout           = 5 * time.Minute
)

// claudeCodeScopes are exactly the scopes Claude Code requests, in its order
// (deduped) - read from the bundle. Wrong/short scopes get the authorize call
// rejected, so this must track Claude Code.
var claudeCodeScopes = []string{
	"org:create_api_key",
	"user:profile",
	"user:inference",
	"user:sessions:claude_code",
	"user:mcp_servers",
	"user:file_upload",
}

func cmdLogin(args []string) int {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	manual := fs.Bool("manual", false, "paste the code by hand instead of catching it on a local callback server (for headless/SSH)")
	console := fs.Bool("console", false, "log into an Anthropic Console (API/billing) account instead of a Claude subscription")
	fs.Parse(args)

	accs, err := loadAccounts()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	authBase := oauthAuthorizeClaudeAI
	if *console {
		authBase = oauthAuthorizeConsole
	}

	var creds *Creds
	if *manual {
		creds, err = oauthLoginManual(authBase)
	} else {
		creds, err = oauthLoginLoopback(authBase)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	// Prove the freshly minted pair really works before we save it, and settle
	// the identity from the token (never a guessed label).
	raw, err := validateImport(creds)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: NOT saved - %v\n", err)
		return 1
	}

	// The token response carries no subscription/tier, so fetch the profile (the
	// same call Claude Code makes after login) to fill them - that's what shows
	// the "(max 20x)" label. Best-effort for the tier; authoritative for email.
	email := creds.Email
	if prof, perr := fetchProfile(creds.AccessToken); perr == nil {
		if prof.Email != "" {
			email = prof.Email
		}
		creds.RateLimitTier = prof.RateLimitTier
		creds.SubscriptionType = prof.SubscriptionType
	}
	if email == "" {
		email, _ = resolveEmail(creds.AccessToken)
	}
	if email == "" {
		fmt.Fprintln(os.Stderr, "error: NOT saved - could not verify the account's identity")
		return 1
	}

	if containsEmail(accs, email) {
		// idempotent: refresh the stored token from this new login.
		if err := writeStoredCreds(email, creds); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		writeCache(email, raw)
		fmt.Printf("%s is already added - refreshed its token from this login\n", email)
		return 0
	}

	if err := writeStoredCreds(email, creds); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	accs = append(accs, Account{Source: "stored", Email: email})
	if err := saveAccounts(accs); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	writeCache(email, raw)
	fmt.Printf("added %s\n", email)
	fmt.Fprintln(os.Stderr, "Tracked from now on - the tool refreshes its token on its own, and never touches your Claude Code login.")
	return 0
}

// oauthLoginLoopback runs the browser flow with a local callback server, so the
// authorization code is caught automatically (no copy/paste).
func oauthLoginLoopback(authBase string) (*Creds, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("could not start the local callback server: %w (try `claude-limits login --manual`)", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://localhost:%d/callback", port)

	verifier, err := randomB64(32)
	if err != nil {
		return nil, err
	}
	state, err := randomB64(32)
	if err != nil {
		return nil, err
	}
	authURL := authorizeURL(authBase, redirectURI, pkceChallenge(verifier), state)

	type result struct {
		code string
		err  error
	}
	ch := make(chan result, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			writePlain(w, 200, "Sign-in was canceled or failed. You can close this window.")
			ch <- result{err: fmt.Errorf("authorization failed: %s %s", e, q.Get("error_description"))}
			return
		}
		code, gotState := q.Get("code"), q.Get("state")
		if code == "" {
			writePlain(w, 400, "Authorization code not found.")
			ch <- result{err: errors.New("no authorization code in the callback")}
			return
		}
		if gotState != state {
			writePlain(w, 400, "Invalid state parameter.")
			ch <- result{err: errors.New("state mismatch on the callback - aborted (possible CSRF)")}
			return
		}
		writePlain(w, 200, "Logged in to Claude. You can close this window and return to the terminal.")
		ch <- result{code: code}
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	promptOpen(authURL)

	select {
	case res := <-ch:
		if res.err != nil {
			return nil, res.err
		}
		return exchangeCode(res.code, verifier, state, redirectURI)
	case <-time.After(loginTimeout):
		return nil, fmt.Errorf("timed out after %s waiting for the browser login", loginTimeout)
	}
}

// oauthLoginManual runs the flow with the hosted redirect that shows a
// "<code>#<state>" string to paste back - for hosts with no browser/loopback.
func oauthLoginManual(authBase string) (*Creds, error) {
	verifier, err := randomB64(32)
	if err != nil {
		return nil, err
	}
	state, err := randomB64(32)
	if err != nil {
		return nil, err
	}
	authURL := authorizeURL(authBase, oauthManualRedirect, pkceChallenge(verifier), state)
	promptOpen(authURL)
	fmt.Fprint(os.Stderr, "\nAfter logging in, paste the code shown (looks like <code>#<state>): ")

	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return nil, fmt.Errorf("could not read the pasted code: %w", err)
	}
	code, gotState, ok := strings.Cut(strings.TrimSpace(line), "#")
	if !ok || code == "" || gotState == "" {
		return nil, errors.New("invalid code - copy the FULL value shown, including the part after '#'")
	}
	if gotState != state {
		return nil, errors.New("the pasted code is from a different login attempt (state mismatch) - run `login` again")
	}
	return exchangeCode(code, verifier, state, oauthManualRedirect)
}

// authorizeURL builds Claude Code's authorize URL. Query-param order is
// irrelevant to the server, so url.Values (sorted) is fine.
func authorizeURL(base, redirectURI, challenge, state string) string {
	q := url.Values{}
	q.Set("code", "true")
	q.Set("client_id", oauthClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(claudeCodeScopes, " "))
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	return base + "?" + q.Encode()
}

// exchangeCode swaps the authorization code for a token pair. Same endpoint,
// body shape and UA that Claude Code uses; applyRefresh folds the response into
// Creds (and memoizes the verified email from account.email_address).
func exchangeCode(code, verifier, state, redirectURI string) (*Creds, error) {
	body, _ := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  redirectURI,
		"client_id":     oauthClientID,
		"code_verifier": verifier,
		"state":         state,
	})
	req, _ := http.NewRequest("POST", oauthTokenURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "claude-cli/"+claudeVersion()+" (external, cli)")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("token exchange: HTTP %d: %s", resp.StatusCode, truncate(string(data), 200))
	}
	var rr refreshResponse
	if err := json.Unmarshal(data, &rr); err != nil {
		return nil, fmt.Errorf("token exchange: bad response: %w", err)
	}
	if rr.AccessToken == "" || rr.RefreshToken == "" {
		return nil, errors.New("token exchange: response had no token pair")
	}
	c := &Creds{}
	applyRefresh(c, rr)
	return c, nil
}

// ---- PKCE / helpers ----

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func randomB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("could not generate random bytes: %w", err)
	}
	return b64url(b), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return b64url(sum[:])
}

func writePlain(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	io.WriteString(w, msg+"\n")
}

// promptOpen prints the URL and tries to open it in the default browser.
func promptOpen(u string) {
	fmt.Fprintln(os.Stderr, "Opening your browser to log in to Claude. If it doesn't open, visit:")
	fmt.Fprintln(os.Stderr, "  "+u)
	openBrowser(u)
}

// openBrowser best-effort opens a URL in the default browser (never fatal - the
// URL is always printed too).
func openBrowser(u string) {
	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name, args = "open", []string{u}
	case "windows":
		name, args = "rundll32", []string{"url.dll,FileProtocolHandler", u}
	default:
		name, args = "xdg-open", []string{u}
	}
	_ = exec.Command(name, args...).Start()
}
