# claude-limits

Claude usage limits for multiple accounts, side by side, in one fast command.

```
● you@example.com (max 20x)
  Session (5h)       █████████████▉░░░░░░░░░░   58%  resets in 30m (21:30)
  Week (all models)  ██████████████▍░░░░░░░░░   60%  resets in 4d 23h (Sun 20:00)
  Week (Fable)       ████████████████████████  100%  resets in 4d 23h (Sun 20:00)  ◉ AT LIMIT

● claude@example.com (max 5x)
  Session (5h)       ███▏░░░░░░░░░░░░░░░░░░░░   13%  resets in 3h 02m (23:58)
  Week (all models)  █████████▌░░░░░░░░░░░░░░   40%  resets in 2d 4h (Thu 01:00)
```

Shows every limit bucket the API reports for each account - the 5-hour session
window, the all-models weekly window, and any model-scoped weekly window (e.g.
a Fable/Opus weekly cap) - as smooth unicode progress bars in Claude brand
colors, with reset countdowns. Plus `--json` for scripting.

Each account is labeled by its email, verified against the API from its own
token - never a typed alias or a guess (see "identity is never guessed" below).

Why: hitting a limit is invisible until it kills your session mid-flight.
(This tool's own build run was killed by exactly that - an out-of-credits
error nobody saw coming. The 100% Fable bar above is real.)

## Install

```sh
go build -o claude-limits .   # single static binary, zero dependencies
cp claude-limits ~/.local/bin/
```

## The one command you need

```sh
claude-limits        # show usage for every account, plus the one you're logged into now
claude-limits add    # add the account this machine is CURRENTLY logged into
```

That's the whole workflow. You're signed into account A, run `add`, A is
tracked. Run out of A's limit, switch Claude Code to B, run `add` again, B is
tracked too. Keep going until all your accounts are in. No per-account
copy-pasting, no tokens to manage. Each account, once added, shows forever.

Prefer not to switch Claude Code around just to add accounts? Run `login`
instead: it opens a Claude browser login, catches the result on a local
callback, and adds that account - even one you've never logged into here.

```sh
claude-limits login           # add a Claude subscription account via a browser login
claude-limits login --manual  # headless/SSH: paste the code instead of catching it locally
claude-limits login --console # log into an Anthropic Console (API) account instead
```

`login` defaults to the Claude **subscription** login (Pro/Max) - the accounts
whose limits this tool is about. Pass `--console` for an Anthropic Console
(API/billing) account.

`login` mints its own token family, so it never touches or races your Claude
Code login; the account is stored and self-refreshed like any other.

```sh
claude-limits switch                              # switch Claude Code to another added account (no browser login)
claude-limits --json                              # machine-readable
claude-limits --fresh                             # bypass the cache
claude-limits --account claude@example.com        # just one account (by email)
claude-limits accounts                            # list added accounts
claude-limits remove-account claude@example.com   # forget one
```

A brand-new run (nothing added yet) still shows the account you're logged into,
tagged `(not added yet - run: claude-limits add)`.

## How it keeps every account alive without ever fighting Claude Code

Every account is stored, keyed by its verified email. On each run, for each
account, the tool decides automatically:

- **You're logged into it right now** (its email == this machine's Claude Code
  login): it's read **live** from Claude Code's keychain, and the stored copy is
  synced from that fresh token. The tool does **not** refresh it - Claude Code
  owns rotation while you're on it, so there's no two-owner race. Shown as
  `(logged in here)`.
- **You've switched away from it** (dormant): the tool uses the stored token and
  **self-refreshes** it (rotating and re-saving the pair atomically) so it keeps
  working. Shown as `(saved)`.

Net: Claude Code owns the active account's rotation; the tool owns every dormant
account's. They never fight, and dormant accounts stay alive because the tool
refreshes them. Because the stored copy is re-synced from the keychain every
time that account is the live login, your natural "check the tool, then switch"
rhythm keeps its token current.

**The one honest edge:** a dormant account the tool hasn't refreshed for longer
than the refresh-token window (~10 days) lapses. It's never shown wrong - it
renders a clear `dormant token lapsed - switch Claude Code to this account and
run claude-limits add`. Be on it at some point (you will be) and run `add`.

**Identity is never guessed.** The label on each account is its email as
verified against the API from that account's own token (`GET
/api/oauth/profile`, memoized per exact token). The bug this prevents: labeling
the login from `~/.claude.json`, which can lag the real credentials by a whole
login - a machine can hold one account's tokens while that file still names a
different account.

## Switching Claude Code between accounts without a browser login

```sh
claude-limits switch                     # shows the limits, then an arrow-key menu
claude-limits switch claude@example.com  # or straight to one by email
```

`switch` with no email first prints the usual side-by-side limits (so you pick
by how much each account has left), then shows an arrow-key menu (↑/↓ or j/k,
Enter to select, Esc to cancel).

Since the tool already holds a live token pair for every added account, it can
hand one to Claude Code directly: it syncs the outgoing login's fresh pair to
its store, verifies the target's stored pair against the API (refreshing it if
needed), writes it into the keychain item Claude Code reads, and rewrites the
account identity in `~/.claude.json`. No `/login`, no browser.

This is safe with sessions already running, verified against Claude Code's
own source (2.1.267): before every token refresh Claude Code re-reads the
keychain under a lock and, if the token there differs from the one in memory,
it adopts the keychain token instead of refreshing. So an old session never
rotates the old account's refresh token over the new one. New sessions use
the new account immediately; running ones move over at their next token check
(at the latest when their access token expires) - all sessions on the machine
share the one login.

Claude Code refetches the profile behind `/status` only when it is older than
24h, so the tool rewrites `oauthAccount` (email, account and organization ids)
in `~/.claude.json` and drops the fetch timestamp to force a refetch on next
start.

### Adding an account from a DIFFERENT machine (advanced)

If you can't switch this machine's login to it, carry its token over. On that
machine:

```sh
claude-limits extract --copy     # validates the login live, copies its blob to the clipboard
```

On this machine, **within a minute** (the token is single-use; Claude Code's
rotation kills the copy):

```sh
claude-limits add --token        # paste the blob on stdin (or pipe it)
```

It's validated against the API before anything is saved - a stale blob is
refused, not stored. An imported account is dormant here, so the tool
self-refreshes it. This works best for an account that otherwise lives on that
other machine; if Claude Code keeps actively using it elsewhere, the two copies
will rotate each other out (single-use refresh tokens) - in that case just run
`claude-limits` on that machine instead. You can also seed from 1Password:
`claude-limits add --from-op op://vault/item/field`.

(Configs from older versions - a `keychain` placeholder entry, or the typed
`{"name": ...}` alias format - migrate automatically on the next run.)

## The API, verified against the real endpoints

- Identity: `GET https://api.anthropic.com/api/oauth/profile` returns the
  account email for a token; memoized by the token's sha256 in
  `~/.cache/claude-limits/identities.json` (keyed to the exact token, so it can
  never cross accounts; a rotated token re-resolves).
- Usage: `GET https://api.anthropic.com/api/oauth/usage` with
  `Authorization: Bearer <token>`, `anthropic-beta: oauth-2025-04-20`, and
  `User-Agent: claude-code/<version>` (a wrong UA gets an instant 429).
  Response carries legacy buckets (`five_hour`, `seven_day`, per-model
  `seven_day_*`) plus a normalized `limits` array (`session` / `weekly_all` /
  `weekly_scoped`, each with percent, severity, reset time, model scope) which
  is what gets rendered, plus `extra_usage` (usage credits) shown when enabled.
- Refresh: `POST https://platform.claude.com/v1/oauth/token` with JSON
  `{"grant_type":"refresh_token","client_id":"9d1c250a-...","refresh_token":...}`
  (Claude Code's public client id; the endpoint is UA-fingerprinted, generic
  script UAs are rejected). Returns a new 8h access token, a **rotated** ~10-day
  refresh token, and the account email. Every rotation is persisted atomically
  before anything else - losing it would lose the account.

## Rate limiting / cache

The usage API is polled by Claude Code itself about every 3 minutes; this tool
never hammers it. Responses are cached per account (keyed by the verified
email) in `~/.cache/claude-limits/` (0600) for 60s (`CLAUDE_LIMITS_CACHE_TTL`, e.g.
`3m`), so rapid re-runs are free. When a live fetch fails (429, offline), the
last good response is shown clearly labeled `⚠ stale`.

## Env vars

| var | meaning |
| --- | --- |
| `CLAUDE_LIMITS_CACHE_TTL` | cache freshness window (Go duration, default `60s`) |
| `CLAUDE_LIMITS_CONFIG_DIR` / `CLAUDE_LIMITS_CACHE_DIR` | relocate config / cache |
| `CLAUDE_LIMITS_UA_VERSION` | pin the claude-code version used in User-Agent (default: newest locally installed) |
| `NO_COLOR` / `CLAUDE_LIMITS_NO_COLOR` | plain output |

## Security notes

- Tokens are stored 0600 under `~/.config/claude-limits/creds/` and are never
  printed, logged, or sent anywhere except `api.anthropic.com` /
  `platform.claude.com`.
- The account you're currently logged into is read-only against Claude Code's
  keychain entry - the tool never rotates the token Claude Code owns. The only
  keychain write is `switch`, which replaces the item with another added
  account's verified pair using the same `security add-generic-password -U`
  call Claude Code itself uses (same item, same ACL, no prompt).
