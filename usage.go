package main

// The usage endpoint and the on-disk last-good cache.
//
// GET https://api.anthropic.com/api/oauth/usage
//   Authorization: Bearer <oauth access token>
//   User-Agent: claude-code/<version>     (wrong UA -> instant 429)
//   anthropic-beta: oauth-2025-04-20
//
// Response shape (verified 2026-09-08): legacy top-level buckets
// (five_hour, seven_day, seven_day_opus, seven_day_sonnet, ...) plus a
// normalized `limits` array - kind session|weekly_all|weekly_scoped, percent,
// severity, resets_at, scope{model{display_name}}, is_active - plus
// extra_usage (usage credits) and spend. We render from `limits` and fall
// back to the legacy buckets if it's ever absent.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const usageURL = "https://api.anthropic.com/api/oauth/usage"

// httpError carries the status code so callers can react to 401 (refresh) vs
// 429 (serve stale cache) differently.
type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string { return e.msg }

func isHTTPStatus(err error, status int) bool {
	var he *httpError
	return errors.As(err, &he) && he.status == status
}

// The API is polled by Claude Code every ~3 min; a CLI must not hammer it.
// Rapid re-runs are served from the cache instead.
const defaultCacheTTL = 60 * time.Second

type UsageLimit struct {
	Kind     string  `json:"kind"` // session | weekly_all | weekly_scoped
	Group    string  `json:"group"`
	Percent  float64 `json:"percent"`
	Severity string  `json:"severity"` // normal | ... | critical
	ResetsAt string  `json:"resets_at"`
	Scope    *struct {
		Model *struct {
			DisplayName string `json:"display_name"`
		} `json:"model"`
		Surface *string `json:"surface"`
	} `json:"scope"`
	IsActive bool `json:"is_active"`
}

type legacyBucket struct {
	Utilization  float64 `json:"utilization"`
	ResetsAt     string  `json:"resets_at"`
	LockedReason *string `json:"locked_reason"`
}

type ExtraUsage struct {
	IsEnabled    bool    `json:"is_enabled"`
	MonthlyLimit float64 `json:"monthly_limit"`
	UsedCredits  float64 `json:"used_credits"`
	Utilization  float64 `json:"utilization"`
	Currency     string  `json:"currency"`
}

type UsageResponse struct {
	FiveHour   *legacyBucket `json:"five_hour"`
	SevenDay   *legacyBucket `json:"seven_day"`
	Limits     []UsageLimit  `json:"limits"`
	ExtraUsage *ExtraUsage   `json:"extra_usage"`
}

// normalizedLimits returns the limits to render, synthesizing from the legacy
// buckets when the `limits` array is missing (older backend responses).
func (u *UsageResponse) normalizedLimits() []UsageLimit {
	if len(u.Limits) > 0 {
		return u.Limits
	}
	var out []UsageLimit
	if u.FiveHour != nil {
		out = append(out, UsageLimit{Kind: "session", Percent: u.FiveHour.Utilization, ResetsAt: u.FiveHour.ResetsAt, Severity: "normal"})
	}
	if u.SevenDay != nil {
		out = append(out, UsageLimit{Kind: "weekly_all", Percent: u.SevenDay.Utilization, ResetsAt: u.SevenDay.ResetsAt, Severity: "normal"})
	}
	return out
}

func (l UsageLimit) Label() string {
	switch l.Kind {
	case "session":
		return "Session (5h)"
	case "weekly_all":
		return "Week (all models)"
	case "weekly_scoped":
		if l.Scope != nil && l.Scope.Model != nil && l.Scope.Model.DisplayName != "" {
			return "Week (" + l.Scope.Model.DisplayName + ")"
		}
		return "Week (scoped)"
	default:
		return l.Kind
	}
}

func fetchUsage(accessToken string) (*UsageResponse, []byte, error) {
	req, _ := http.NewRequest("GET", usageURL, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("User-Agent", "claude-code/"+claudeVersion())
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return nil, nil, &httpError{resp.StatusCode, fmt.Sprintf("usage API: HTTP %d: %s", resp.StatusCode, truncate(string(raw), 200))}
	}
	var u UsageResponse
	if err := json.Unmarshal(raw, &u); err != nil {
		return nil, nil, fmt.Errorf("usage API: bad response: %w", err)
	}
	return &u, raw, nil
}

// ---- cache (last-good response per account) ----

type cacheEntry struct {
	FetchedAt time.Time       `json:"fetched_at"`
	Response  json.RawMessage `json:"response"`
}

func cacheDir() string {
	if d := os.Getenv("CLAUDE_LIMITS_CACHE_DIR"); d != "" {
		return d
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".cache", "claude-limits")
}

func readCache(name string) *cacheEntry {
	b, err := os.ReadFile(filepath.Join(cacheDir(), name+".json"))
	if err != nil {
		return nil
	}
	var e cacheEntry
	if json.Unmarshal(b, &e) != nil {
		return nil
	}
	return &e
}

func writeCache(name string, raw []byte) {
	if err := os.MkdirAll(cacheDir(), 0o700); err != nil {
		return
	}
	b, _ := json.Marshal(cacheEntry{FetchedAt: time.Now(), Response: raw})
	_ = atomicWrite(filepath.Join(cacheDir(), name+".json"), b, 0o600)
}

func cacheTTL() time.Duration {
	if v := os.Getenv("CLAUDE_LIMITS_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return defaultCacheTTL
}

// AccountResult is everything the renderers need for one account.
// Email is the account's verified identity (from the API, see identity.go);
// when it's empty the account is UNRESOLVED and Ref names the config entry.
type AccountResult struct {
	Email      string         `json:"email,omitempty"`
	Ref        string         `json:"ref,omitempty"` // non-identity handle for error display only
	Tier       string         `json:"tier,omitempty"`
	Source     string         `json:"source"`
	FetchedAt  time.Time      `json:"fetched_at"`
	Stale      bool           `json:"stale"` // served from cache past TTL because live fetch failed
	Cached     bool           `json:"cached"`
	Err        string         `json:"error,omitempty"`
	Active     bool           `json:"active"`  // the login this machine holds right now (read live)
	Unadded    bool           `json:"unadded"` // the current login, not yet `add`ed (display-only)
	Limits     []UsageLimit   `json:"limits,omitempty"`
	ExtraUsage *ExtraUsage    `json:"extra_usage,omitempty"`
	Raw        *UsageResponse `json:"-"`
}

// refLabel is what to call an account whose identity we cannot verify - a
// handle for the config entry, explicitly NOT an identity claim.
func refLabel(acc Account) string {
	if acc.LegacyName != "" {
		return acc.LegacyName
	}
	if acc.Unadded || acc.Source == "keychain" || acc.Source == "" {
		return "this machine's Claude Code login"
	}
	return acc.Source
}

// collect resolves creds, verifies the account identity, and fetches usage
// (cache-first) for one account. The rendered email and the cache key are
// ALWAYS the token's API-verified identity - never a config label, so one
// account's data can never appear under another's name.
func collect(acc Account, cur localLogin, fresh bool) AccountResult {
	res := AccountResult{Source: acc.Source, Email: acc.Email, Ref: refLabel(acc), Unadded: acc.Unadded}
	creds, active, err := getCreds(acc, cur)
	if err != nil {
		res.Err = err.Error()
		res.applyStaleCache(acc.Email) // only under a verified email; no-op when unresolved
		return res
	}
	res.Active = active
	res.Tier = creds.RateLimitTier
	email := acc.Email
	if email == "" {
		var ierr error
		email, ierr = resolveEmail(creds.AccessToken)
		if email == "" {
			res.Err = fmt.Sprintf("cannot resolve account identity (%v) - re-add with `claude-limits add`", ierr)
			return res
		}
	}
	res.Email = email
	if ce := readCache(email); ce != nil && !fresh && time.Since(ce.FetchedAt) < cacheTTL() {
		if u := decodeCached(ce); u != nil {
			res.fill(u, ce.FetchedAt, true, false)
			return res
		}
	}
	u, raw, err := fetchUsageActive(acc, creds, active)
	if err != nil {
		res.Err = err.Error()
		res.applyStaleCache(email)
		return res
	}
	writeCache(email, raw)
	res.fill(u, time.Now(), false, false)
	return res
}

// fetchUsageActive hits the usage API. For a DORMANT account it recovers from a
// revoked-but-unexpired access token by self-refreshing once and retrying. For
// the ACTIVE login it never refreshes - Claude Code owns that token family, so
// a 401 there just surfaces (run any `claude` command to freshen it).
func fetchUsageActive(acc Account, creds *Creds, active bool) (*UsageResponse, []byte, error) {
	u, raw, err := fetchUsage(creds.AccessToken)
	if err != nil && isHTTPStatus(err, 401) && !active && creds.RefreshToken != "" {
		if rerr := refreshCreds(creds); rerr != nil {
			return nil, nil, fmt.Errorf("%v; refresh also failed: %v - dormant token lapsed; switch Claude Code to this account and run `claude-limits add`", err, rerr)
		}
		if werr := writeStoredCreds(acc.key(), creds); werr != nil {
			return nil, nil, fmt.Errorf("CRITICAL: token rotated but could not be saved: %w", werr)
		}
		u, raw, err = fetchUsage(creds.AccessToken)
	}
	return u, raw, err
}

func (r *AccountResult) fill(u *UsageResponse, at time.Time, cached, stale bool) {
	r.Raw = u
	r.Limits = u.normalizedLimits()
	r.ExtraUsage = u.ExtraUsage
	r.FetchedAt = at
	r.Cached = cached
	r.Stale = stale
}

// applyStaleCache falls back to the last-good response (labeled stale) when a
// live fetch fails - a 429 or offline run still shows something honest. The
// cache is keyed by verified email only; with no verified identity there is
// nothing safe to show.
func (r *AccountResult) applyStaleCache(email string) {
	if email == "" {
		return
	}
	if ce := readCache(email); ce != nil {
		if u := decodeCached(ce); u != nil {
			r.fill(u, ce.FetchedAt, true, true)
		}
	}
}

func decodeCached(ce *cacheEntry) *UsageResponse {
	var u UsageResponse
	if json.Unmarshal(ce.Response, &u) != nil {
		return nil
	}
	return &u
}
