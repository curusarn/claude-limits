package main

import (
	"testing"
	"time"
)

func TestBackoffDelay(t *testing.T) {
	cases := []struct {
		failures   int
		retryAfter time.Duration
		want       time.Duration
	}{
		{1, 0, 2 * time.Minute},
		{2, 0, 4 * time.Minute},
		{4, 0, 16 * time.Minute},
		{5, 0, 30 * time.Minute},
		{12, 0, 30 * time.Minute},
		{1, 10 * time.Minute, 10 * time.Minute},
	}
	for _, c := range cases {
		if got := backoffDelay(c.failures, c.retryAfter); got != c.want {
			t.Errorf("backoffDelay(%d, %v) = %v, want %v", c.failures, c.retryAfter, got, c.want)
		}
	}
}

func TestRecordRateLimitKeepsLastGood(t *testing.T) {
	t.Setenv("CLAUDE_LIMITS_CACHE_DIR", t.TempDir())
	writeCache("a@example.com", []byte(`{"limits":[{"kind":"session","percent":12}]}`))
	b1 := recordRateLimit("a@example.com", 0)
	b2 := recordRateLimit("a@example.com", 0)
	if b1.Failures != 1 || b2.Failures != 2 || !b2.Until.After(b1.Until) {
		t.Fatalf("backoff did not grow: %+v then %+v", b1, b2)
	}
	e := readCache("a@example.com")
	if e == nil || decodeCached(e) == nil || e.Backoff == nil {
		t.Fatalf("last-good response or backoff lost: %+v", e)
	}
	writeCache("a@example.com", []byte(`{"limits":[]}`))
	if readCache("a@example.com").Backoff != nil {
		t.Fatal("a successful fetch should clear the backoff")
	}
}

func TestParseRetryAfter(t *testing.T) {
	if got := parseRetryAfter("120"); got != 2*time.Minute {
		t.Errorf("seconds: got %v", got)
	}
	if got := parseRetryAfter(""); got != 0 {
		t.Errorf("empty: got %v", got)
	}
}
