package main

// Where Claude Code's current login lives, which claude-limits reads (the
// account you're on) and writes (`switch`):
//
//   - macOS: the keychain item, plus the .credentials.json fallback when it
//     exists (switch.go).
//   - elsewhere (Linux): <config dir>/.credentials.json, which is what Claude
//     Code itself uses there, and ~/.claude.json's oauthAccount.
//   - CLAUDE_LIMITS_LOGIN_HELPER set: a command that reads and writes those
//     two for another user. hyperfocus-host sets it so claude-limits (and its
//     store of every other account) runs as the daemon's user, which the
//     agents can't read, while the agents' user holds only the active login.
//     The command gets one more argument:
//       read     print the credentials JSON (exit 1 when there is none)
//       write    the credentials JSON on stdin
//       account  the oauthAccount JSON {accountUuid, emailAddress,
//                organizationUuid} on stdin
//     Secrets go over stdin/stdout only, never argv (/proc/*/cmdline).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func loginHelper() []string { return strings.Fields(os.Getenv("CLAUDE_LIMITS_LOGIN_HELPER")) }

// usesKeychain: the macOS keychain holds the login (and place works).
func usesKeychain() bool { return len(loginHelper()) == 0 && runtime.GOOS == "darwin" }

func runLoginHelper(sub string, stdin []byte) ([]byte, error) {
	h := loginHelper()
	cmd := exec.Command(h[0], append(h[1:], sub)...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("login helper %s: %v %s", sub, err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// readLoginFile is the credentials JSON of the current login (nil if none).
func readLoginFile() []byte {
	if len(loginHelper()) > 0 {
		out, err := runLoginHelper("read", nil)
		if err != nil {
			return nil
		}
		return bytes.TrimSpace(out)
	}
	raw, err := os.ReadFile(filepath.Join(defaultConfigDir(), ".credentials.json"))
	if err != nil {
		return nil
	}
	return raw
}

// writeLoginFile makes c the current login, keeping the file's other keys
// (mcpOAuth). Running sessions watch the file and follow on their next request.
func writeLoginFile(c *Creds) error {
	merged := mergeClaudeAiOauth(readLoginFile(), c)
	if len(loginHelper()) > 0 {
		_, err := runLoginHelper("write", merged)
		return err
	}
	dir := defaultConfigDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return atomicWrite(filepath.Join(dir, ".credentials.json"), merged, 0o600)
}

// setLoginAccount names the account in ~/.claude.json's oauthAccount.
func setLoginAccount(p oauthProfile) error {
	if len(loginHelper()) > 0 {
		b, _ := json.Marshal(map[string]any{"accountUuid": p.AccountUUID, "emailAddress": p.Email, "organizationUuid": p.OrgUUID})
		_, err := runLoginHelper("account", b)
		return err
	}
	return updateOauthAccount(claudeJSONPath(), p)
}
