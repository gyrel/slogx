// Package redact detects potentially sensitive material in diagnostic data.
// Detection is heuristic and cannot establish that data is safe to disclose.
package redact

import (
	"bytes"
	"encoding/hex"
	"math"
	"net/url"
	"regexp"
	"strings"
)

// Options supplies the home directory's user name without reading the environment.
type Options struct{ HomeUser string }

// Violation identifies a detection without retaining the matched bytes.
type Violation struct {
	Rule    string
	Path    string
	Line    int
	Offset  int64
	NoValue bool
}
type rule struct {
	id string
	re *regexp.Regexp
}

var rules = []rule{
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)},
	{"bearer", regexp.MustCompile(`(?i)\bBearer[ \t]+[A-Za-z0-9._~+/=-]{8,}`)},
	{"openai_key", regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{16,}`)},
	{"github_token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{16,}`)},
	{"slack_token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}`)},
	{"aws_access_key", regexp.MustCompile(`\bAKIA[A-Z0-9]{16}\b`)},
	{"pem_private_key", regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----`)},
	{"inline_secret", regexp.MustCompile(`(?i)\b(?:password|api_key|secret)\s*=\s*[^\s&;,"']+`)},
}
var runs = regexp.MustCompile(`[A-Za-z0-9+/=_-]{32,}`)
var urls = regexp.MustCompile(`https?://[^\s"'<>]+`)
var homes = regexp.MustCompile(`(?:/Users/|/home/|[A-Za-z]:\\Users\\)([^/\\\s]+)[/\\]`)

// Scan returns locations of suspected secrets. No violation includes matched data.
// Offsets are zero-based byte offsets and lines are one-based.
//
//nolint:gocognit // Each detector has independent matching and location rules.
func Scan(data []byte, opts Options) []Violation {
	var out []Violation
	add := func(id string, offset int) {
		out = append(out, Violation{Rule: id, Line: 1 + bytes.Count(data[:offset], []byte{'\n'}), Offset: int64(offset), NoValue: true})
	}
	for _, r := range rules {
		for _, m := range r.re.FindAllIndex(data, -1) {
			add(r.id, m[0])
		}
	}
	for _, m := range runs.FindAllIndex(data, -1) {
		b := data[m[0]:m[1]]
		if len(b) == 64 {
			if _, err := hex.DecodeString(string(b)); err == nil {
				continue
			}
		}
		if entropy(b) >= 4.0 {
			add("high_entropy", m[0])
		}
	}
	for _, m := range urls.FindAllIndex(data, -1) {
		u, err := url.Parse(string(data[m[0]:m[1]]))
		if err != nil {
			continue
		}
		if u.User != nil {
			add("url_userinfo", m[0])
		}
		if u.ForceQuery || u.RawQuery != "" {
			add("url_query", m[0])
		}
	}
	for _, m := range homes.FindAllSubmatchIndex(data, -1) {
		id := "foreign_home"
		if opts.HomeUser != "" && strings.EqualFold(string(data[m[2]:m[3]]), opts.HomeUser) {
			id = "own_home"
		}
		add(id, m[0])
	}
	return out
}
func entropy(b []byte) float64 {
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	var h float64
	for _, n := range counts {
		if n > 0 {
			p := float64(n) / float64(len(b))
			h -= p * math.Log2(p)
		}
	}
	return h
}
