package slogx

import (
	"context"
	"log/slog"
	"strings"
	"sync/atomic"
)

// DynamicHandler is a slog.Handler with runtime reconfiguration, OTel context
// injection, and stack traces on errors.
type DynamicHandler struct {
	cfg *atomic.Pointer[Config]

	// exitFunc mirrors the logger exit hook so FromContext can recover it from
	// slog.Default(). Nil means the default os.Exit behavior.
	exitFunc func(int)

	attrs  []slog.Attr
	groups []string

	cachedHandler       atomic.Pointer[slog.Handler]
	cachedConfigVersion atomic.Pointer[Config]
}

// Enabled reports whether the record should be logged.
func (h *DynamicHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.cfg.Load().Level
}

// Handle processes a log record using a cached static handler chain.
func (h *DynamicHandler) Handle(ctx context.Context, r slog.Record) error {
	cfg := h.cfg.Load()

	appendStackAttr(&r, cfg)

	var ctxAttrs []slog.Attr
	for _, key := range cfg.ContextKeys {
		if val := ctx.Value(key); val != nil {
			ctxAttrs = append(ctxAttrs, slog.Any(key.String(), val))
		}
	}
	for _, ta := range traceAttrs(ctx, cfg) {
		ctxAttrs = append(ctxAttrs, slog.Any(ta.key, ta.val))
	}

	base := h.getOrBuildCachedHandler(cfg)
	if len(ctxAttrs) > 0 {
		base = base.WithAttrs(ctxAttrs)
	}
	return base.Handle(ctx, r)
}

func (h *DynamicHandler) getOrBuildCachedHandler(cfg *Config) slog.Handler {
	if h.cachedConfigVersion.Load() == cfg {
		if cached := h.cachedHandler.Load(); cached != nil {
			return *cached
		}
	}

	hOpts := &slog.HandlerOptions{
		Level:       cfg.Level,
		AddSource:   cfg.AddSource,
		ReplaceAttr: h.getReplaceAttr(cfg),
	}

	var base slog.Handler
	if cfg.Format == FormatJSON {
		base = slog.NewJSONHandler(cfg.Output, hOpts)
	} else {
		base = slog.NewTextHandler(cfg.Output, hOpts)
	}

	if len(h.attrs) > 0 {
		base = base.WithAttrs(h.attrs)
	}
	for _, g := range h.groups {
		base = base.WithGroup(g)
	}

	h.cachedHandler.Store(&base)
	h.cachedConfigVersion.Store(cfg)
	return base
}

// WithAttrs returns a new DynamicHandler with additional attributes.
func (h *DynamicHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, len(h.attrs)+len(attrs))
	copy(newAttrs, h.attrs)
	copy(newAttrs[len(h.attrs):], attrs)
	return &DynamicHandler{
		cfg:      h.cfg,
		exitFunc: h.exitFunc,
		attrs:    newAttrs,
		groups:   h.groups,
	}
}

// WithGroup returns a new DynamicHandler with an additional group.
func (h *DynamicHandler) WithGroup(name string) slog.Handler {
	newGroups := make([]string, len(h.groups)+1)
	copy(newGroups, h.groups)
	newGroups[len(h.groups)] = name
	return &DynamicHandler{
		cfg:      h.cfg,
		exitFunc: h.exitFunc,
		attrs:    h.attrs,
		groups:   newGroups,
	}
}

func (h *DynamicHandler) getReplaceAttr(cfg *Config) func([]string, slog.Attr) slog.Attr {
	return func(groups []string, a slog.Attr) slog.Attr {
		fullKey := joinKey(groups, a.Key)
		if attrRemoved(cfg.RemoveKeys, fullKey, a.Key) {
			return slog.Attr{}
		}
		if masked, ok := maskAttrValue(cfg, fullKey, a.Value); ok {
			a.Value = masked
			return a
		}
		if a.Key == slog.LevelKey {
			a.Value = replaceLevelValue(cfg, a.Value)
		}
		return a
	}
}

func joinKey(groups []string, key string) string {
	if len(groups) == 0 {
		return key
	}
	return strings.Join(append(append([]string{}, groups...), key), ".")
}

func attrRemoved(remove RemoveMap, fullKey, key string) bool {
	if _, ok := remove[normalizeKey(fullKey)]; ok {
		return true
	}
	_, ok := remove[normalizeKey(key)]
	return ok
}

// maskAttrValue applies key rules first, then corporate auto-detection on
// unregistered string values.
func maskAttrValue(cfg *Config, key string, v slog.Value) (slog.Value, bool) {
	if mType, ok := lookupMask(cfg.MaskKeys, key); ok {
		return slog.AnyValue(cfg.Masker.Mask(v.Any(), mType)), true
	}
	if _, isCorp := cfg.Masker.(*CorporateMasker); isCorp {
		if s, ok := v.Any().(string); ok {
			if detected, hit := detectSecret(s); hit {
				return slog.AnyValue(cfg.Masker.Mask(s, detected)), true
			}
		}
	}
	return v, false
}

func replaceLevelValue(cfg *Config, v slog.Value) slog.Value {
	if lvl, ok := v.Any().(slog.Level); ok {
		return slog.StringValue(getLevelName(lvl, cfg.LevelNames))
	}
	return v
}
