package main

// Terminal rendering: smooth unicode progress bars in Claude brand colors.
// Brand palette: crail #D97757 (primary orange/coral), dark #1F1E1D, cream #F0EEE5.

import (
	"fmt"
	"math"
	"os"
	"strings"
	"time"
)

const barWidth = 24

// eighth-block partials give the bar a smooth, non-steppy edge
var eighths = []rune{' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉'}

type palette struct {
	crail, cream, dim, amber, red, bold, reset string
}

func colors() palette {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("CLAUDE_LIMITS_NO_COLOR") != "" {
		return palette{}
	}
	rgb := func(r, g, b int) string { return fmt.Sprintf("\x1b[38;2;%d;%d;%dm", r, g, b) }
	return palette{
		crail: rgb(217, 119, 87),  // #D97757
		cream: rgb(240, 238, 229), // #F0EEE5
		dim:   "\x1b[2m",
		amber: rgb(224, 164, 88), // warning tint between crail and cream
		red:   rgb(209, 67, 67),  // critical
		bold:  "\x1b[1m",
		reset: "\x1b[0m",
	}
}

// fillColor picks the bar color from severity/percent.
func (p palette) fillColor(l UsageLimit) string {
	switch {
	case l.Severity == "critical" || l.Percent >= 100:
		return p.red
	case l.Severity != "" && l.Severity != "normal", l.Percent >= 80:
		return p.amber
	default:
		return p.crail
	}
}

func bar(percent float64, color string, p palette) string {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	cells := percent / 100 * barWidth
	full := int(cells)
	frac := cells - float64(full)
	var b strings.Builder
	b.WriteString(color)
	b.WriteString(strings.Repeat("█", full))
	rest := barWidth - full
	if full < barWidth {
		if idx := int(math.Round(frac * 8)); idx > 0 {
			if idx == 8 { // rounds up to a full cell
				b.WriteString("█")
			} else {
				b.WriteRune(eighths[idx])
			}
			rest--
		}
	}
	b.WriteString(p.reset)
	b.WriteString(p.dim)
	b.WriteString(strings.Repeat("░", rest))
	b.WriteString(p.reset)
	return b.String()
}

// resetIn renders "resets in 1h 12m (19:29)" / "resets in 5d 2h (Sun 13)".
func resetIn(resetsAt string) string {
	if resetsAt == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, resetsAt)
	if err != nil {
		return ""
	}
	t = t.Local()
	d := time.Until(t)
	if d < 0 {
		return "resets now"
	}
	var rel string
	switch {
	case d >= 48*time.Hour:
		rel = fmt.Sprintf("%dd %dh", int(d.Hours())/24, int(d.Hours())%24)
	case d >= time.Hour:
		rel = fmt.Sprintf("%dh %02dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		rel = fmt.Sprintf("%dm", int(d.Minutes()))
	}
	var abs string
	if d >= 24*time.Hour {
		abs = t.Format("Mon 15:04")
	} else {
		abs = t.Format("15:04")
	}
	return fmt.Sprintf("resets in %s (%s)", rel, abs)
}

func render(results []AccountResult) {
	p := colors()
	for i, r := range results {
		if i > 0 {
			fmt.Println()
		}
		renderAccount(r, p)
	}
}

func renderAccount(r AccountResult, p palette) {
	// header: ● email (tier) [staleness] - the email is the API-verified
	// identity of the token the data came from, never a config label
	head := p.crail + "●" + p.reset + " "
	if r.Email != "" {
		head += p.bold + r.Email + p.reset
	} else {
		head += p.bold + r.Ref + p.reset + " " + p.red + "(identity unresolved)" + p.reset
	}
	if t := tierLabel(r.Tier); t != "" {
		head += " " + p.dim + "(" + t + ")" + p.reset
	}
	switch {
	case r.Unadded:
		head += " " + p.amber + "(not added yet - run: claude-limits add)" + p.reset
	case r.Active:
		head += " " + p.dim + "(logged in)" + p.reset
	case r.Email != "":
		head += " " + p.dim + "(saved)" + p.reset
	}
	if r.Stale {
		head += " " + p.red + "⚠ stale: " + humanAge(r.FetchedAt) + " old" + p.reset
	} else if r.Cached {
		head += " " + p.dim + "(cached " + humanAge(r.FetchedAt) + " ago)" + p.reset
	}
	fmt.Println(head)

	if r.Err != "" && r.Limits == nil {
		fmt.Printf("  %s✗ %s%s\n", p.red, r.Err, p.reset)
		return
	}
	if r.Err != "" { // stale data shown below, but surface why it's stale
		fmt.Printf("  %s(%s)%s\n", p.dim, truncate(r.Err, 100), p.reset)
	}

	labelW := 0
	for _, l := range r.Limits {
		if n := len(l.Label()); n > labelW {
			labelW = n
		}
	}
	for _, l := range r.Limits {
		fill := p.fillColor(l)
		pct := fmt.Sprintf("%3.0f%%", l.Percent)
		pctCol := fill
		note := ""
		if l.Severity == "critical" || l.Percent >= 100 {
			note = "  " + p.red + p.bold + "◉ AT LIMIT" + p.reset
		} else if l.IsActive {
			note = "  " + p.amber + "◉ active" + p.reset
		}
		fmt.Printf("  %-*s  %s  %s%s%s%s  %s%s%s%s\n",
			labelW, l.Label(),
			bar(l.Percent, fill, p),
			p.bold, pctCol, pct, p.reset,
			p.dim, resetIn(l.ResetsAt), p.reset,
			note)
	}
	if eu := r.ExtraUsage; eu != nil && (eu.IsEnabled || eu.UsedCredits > 0) {
		fmt.Printf("  %sextra usage credits: %.2f / %.2f %s (%.0f%%)%s\n",
			p.dim, eu.UsedCredits/100, eu.MonthlyLimit/100, eu.Currency, eu.Utilization, p.reset)
	}
}

func tierLabel(t string) string {
	// "default_claude_max_20x" -> "max 20x"
	t = strings.TrimPrefix(t, "default_")
	t = strings.TrimPrefix(t, "claude_")
	return strings.ReplaceAll(t, "_", " ")
}

func humanAge(t time.Time) string {
	d := time.Since(t)
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd", int(d.Hours())/24)
	case d >= time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	default:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
}
