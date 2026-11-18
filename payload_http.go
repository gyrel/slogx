package slogx

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

const attrMethod = "method"

var defaultSensitiveHeaders = map[string]struct{}{
	"authorization":       {},
	"cookie":              {},
	"set-cookie":          {},
	"x-api-key":           {},
	"x-auth-token":        {},
	"proxy-authorization": {},
}

// HTTPRequest logs a sanitized HTTP request snapshot.
func HTTPRequest(name string, r *http.Request, opts ...DumpOption) slog.Attr {
	return HTTPRequestWith(nil, name, r, opts...)
}

// HTTPRequestWith logs a sanitized HTTP request using logger dump settings.
//
// The request body is never logged. Only its size, SHA-256 digest of the
// inspected prefix and a truncation marker are recorded. The body is restored
// for downstream handlers, including the bytes past the inspection limit.
func HTTPRequestWith(l *Logger, name string, r *http.Request, opts ...DumpOption) slog.Attr {
	if r == nil {
		return slog.String(name, "nil")
	}
	cfg := loadDumpConfig(l)
	body, truncated, restored := captureBody(r.Body, bodyLimit(cfg))
	r.Body = restored
	payload := map[string]any{
		attrMethod: r.Method,
		"url":      safeURL(r.URL),
		"headers":  sanitizeHeaders(r.Header, cfg),
	}
	if r.URL != nil && r.URL.RawQuery != "" {
		payload["url_query_redacted"] = true
	}
	addBodyMeta(payload, body, truncated)
	return slog.Any(name, Serialize(cfg, payload, opts...))
}

// HTTPResponse logs a sanitized HTTP response snapshot.
func HTTPResponse(name string, r *http.Response, opts ...DumpOption) slog.Attr {
	return HTTPResponseWith(nil, name, r, opts...)
}

// HTTPResponseWith logs a sanitized HTTP response using logger dump settings.
//
// Like HTTPRequestWith, the response body is summarized instead of logged and
// restored for downstream readers.
func HTTPResponseWith(l *Logger, name string, r *http.Response, opts ...DumpOption) slog.Attr {
	if r == nil {
		return slog.String(name, "nil")
	}
	cfg := loadDumpConfig(l)
	body, truncated, restored := captureBody(r.Body, bodyLimit(cfg))
	r.Body = restored
	payload := map[string]any{
		"status":  r.Status,
		"headers": sanitizeHeaders(r.Header, cfg),
	}
	addBodyMeta(payload, body, truncated)
	return slog.Any(name, Serialize(cfg, payload, opts...))
}

func sanitizeHeaders(h http.Header, cfg Config) map[string]any {
	out := make(map[string]any, len(h))
	masker := cfg.Masker
	if masker == nil {
		masker = &DefaultMasker{}
	}
	for key, vals := range h {
		if value, ok := maskHeaderValue(key, vals, cfg, masker); ok {
			out[key] = value
			continue
		}
		if headerRemoved(cfg.RemoveKeys, key) {
			continue
		}
		if value, ok := corporateHeaderValue(vals, masker); ok {
			out[key] = value
			continue
		}
		out[key] = headerValue(vals)
	}
	return out
}

func maskHeaderValue(key string, vals []string, cfg Config, masker Masker) (any, bool) {
	if _, sensitive := defaultSensitiveHeaders[strings.ToLower(key)]; sensitive {
		return masker.Mask(strings.Join(vals, ","), MaskSecret), true
	}
	if mType, ok := lookupMask(cfg.MaskKeys, key); ok {
		masked := make([]string, len(vals))
		for i, v := range vals {
			masked[i] = fmt.Sprint(masker.Mask(v, mType))
		}
		return masked, true
	}
	return nil, false
}

func headerRemoved(remove RemoveMap, key string) bool {
	if _, ok := remove[normalizeKey(key)]; ok {
		return true
	}
	_, ok := remove[strings.ToLower(key)]
	return ok
}

func corporateHeaderValue(vals []string, masker Masker) ([]string, bool) {
	if _, isCorp := masker.(*CorporateMasker); !isCorp {
		return nil, false
	}
	masked := make([]string, len(vals))
	changed := false
	for i, v := range vals {
		if detected, hit := detectSecret(v); hit {
			masked[i] = fmt.Sprint(masker.Mask(v, detected))
			changed = true
		} else {
			masked[i] = v
		}
	}
	return masked, changed
}

func headerValue(vals []string) any {
	if len(vals) == 1 {
		return vals[0]
	}
	return vals
}

func bodyLimit(cfg Config) int {
	if cfg.DumpMaxBodyBytes > 0 {
		return cfg.DumpMaxBodyBytes
	}
	return 16 * 1024
}

// captureBody reads at most limit+1 bytes for inspection and returns a reader
// that replays every byte read plus the still-unread remainder. The original
// closer stays owned by the returned ReadCloser.
func captureBody(body io.ReadCloser, limit int) ([]byte, bool, io.ReadCloser) {
	if body == nil {
		return nil, false, nil
	}
	if limit <= 0 {
		limit = 4096
	}
	data, err := io.ReadAll(io.LimitReader(body, int64(limit)+1))
	if err != nil {
		// The stream state is unreliable after a read error. Preserve what was
		// read without logging the raw error text.
		return data, false, &bodyReadCloser{Reader: bytes.NewReader(data), Closer: body}
	}
	truncated := len(data) > limit
	logged := data
	if truncated {
		logged = data[:limit]
	}
	return logged, truncated, &bodyReadCloser{
		Reader: io.MultiReader(bytes.NewReader(data), body),
		Closer: body,
	}
}

type bodyReadCloser struct {
	io.Reader
	io.Closer
}

func addBodyMeta(payload map[string]any, body []byte, truncated bool) {
	if len(body) > 0 {
		sum := sha256.Sum256(body)
		payload["body_bytes"] = len(body)
		payload["body_sha256"] = hex.EncodeToString(sum[:])
	}
	if truncated {
		payload["body_truncated"] = true
	}
}

// safeURL returns a URL without credentials, query values or fragment.
func safeURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	clean := *u
	clean.User = nil
	clean.RawQuery = ""
	clean.ForceQuery = false
	clean.Fragment = ""
	clean.RawFragment = ""
	if clean.Opaque != "" {
		clean.Opaque = ""
		if clean.Host == "" {
			return ""
		}
	}
	return clean.String()
}

// RestoreBody replaces r.Body with an in-memory reader. The HTTP payload
// helpers already restore bodies automatically; this is only for callers that
// consumed a body themselves.
func RestoreBody(r *http.Request, body string) {
	if r == nil {
		return
	}
	r.Body = io.NopCloser(bytes.NewBufferString(body))
}
