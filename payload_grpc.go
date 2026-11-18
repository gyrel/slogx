package slogx

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
)

// Metadata is a gRPC-style metadata map (key -> values).
type Metadata map[string][]string

// GRPCCall logs a sanitized gRPC request snapshot.
func GRPCCall(name, method string, req any, md Metadata, opts ...DumpOption) slog.Attr {
	return GRPCCallWith(nil, name, method, req, md, opts...)
}

// GRPCCallWith logs a sanitized gRPC request using logger dump settings.
func GRPCCallWith(l *Logger, name, method string, req any, md Metadata, opts ...DumpOption) slog.Attr {
	cfg := loadDumpConfig(l)
	payload := map[string]any{
		attrMethod: method,
		"metadata": sanitizeMetadata(md, cfg),
	}
	addSerializedMeta(payload, "request", cfg, req, opts...)
	return slog.Any(name, payload)
}

// GRPCResponse logs a sanitized gRPC response snapshot.
func GRPCResponse(name string, resp any, opts ...DumpOption) slog.Attr {
	return GRPCResponseWith(nil, name, resp, opts...)
}

// GRPCResponseWith logs a sanitized gRPC response using logger dump settings.
func GRPCResponseWith(l *Logger, name string, resp any, opts ...DumpOption) slog.Attr {
	cfg := loadDumpConfig(l)
	payload := map[string]any{}
	addSerializedMeta(payload, "response", cfg, resp, opts...)
	return slog.Any(name, payload)
}

// GRPCStreamEvent logs a streaming gRPC event with optional metadata.
func GRPCStreamEvent(name, method, event string, msg any, md Metadata, opts ...DumpOption) slog.Attr {
	return GRPCStreamEventWith(nil, name, method, event, msg, md, opts...)
}

// GRPCStreamEventWith logs a streaming gRPC event using logger dump settings.
func GRPCStreamEventWith(l *Logger, name, method, event string, msg any, md Metadata, opts ...DumpOption) slog.Attr {
	cfg := loadDumpConfig(l)
	payload := map[string]any{
		attrMethod: method,
		"event":    event,
		"metadata": sanitizeMetadata(md, cfg),
	}
	addSerializedMeta(payload, "message", cfg, msg, opts...)
	return slog.Any(name, payload)
}

// addSerializedMeta records the type and a digest of the bounded, masked
// serialization. Raw payload values are never written to the log.
func addSerializedMeta(payload map[string]any, prefix string, cfg Config, value any, opts ...DumpOption) {
	if value == nil {
		return
	}
	payload[prefix+"_type"] = fmt.Sprintf("%T", value)
	data, err := json.Marshal(Serialize(cfg, value, opts...))
	if err != nil {
		payload[prefix+"_serialization_error"] = true
		return
	}
	sum := sha256.Sum256(data)
	payload[prefix+"_bytes"] = len(data)
	payload[prefix+"_sha256"] = hex.EncodeToString(sum[:])
}

func sanitizeMetadata(md Metadata, cfg Config) map[string]any {
	if len(md) == 0 {
		return nil
	}
	masker := cfg.Masker
	if masker == nil {
		masker = &DefaultMasker{}
	}
	out := make(map[string]any, len(md))
	for key, vals := range md {
		lower := strings.ToLower(key)
		nk := normalizeKey(key)
		if _, sensitive := defaultSensitiveHeaders[lower]; sensitive {
			out[key] = masker.Mask(strings.Join(vals, ","), MaskSecret)
			continue
		}
		if mType, ok := lookupMask(cfg.MaskKeys, key); ok {
			masked := make([]string, len(vals))
			for i, v := range vals {
				masked[i] = fmt.Sprint(masker.Mask(v, mType))
			}
			out[key] = masked
			continue
		}
		if _, remove := cfg.RemoveKeys[nk]; remove {
			continue
		}
		if _, remove := cfg.RemoveKeys[lower]; remove {
			continue
		}
		if len(vals) == 1 {
			out[key] = vals[0]
		} else {
			out[key] = vals
		}
	}
	return out
}
