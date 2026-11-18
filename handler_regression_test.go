package slogx

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaskingAppliesToNestedGroups(t *testing.T) {
	buf := &bytes.Buffer{}
	l := New(
		WithOutput(buf),
		WithFormat(FormatJSON),
		WithMaskRules(NewMaskRules().
			Add("email", MaskEmail).
			Add("secret", MaskSecret)),
		WithRemoval(NewRemovalSet("password")),
	)

	l.Info("grouped", slog.Group("user",
		slog.String("email", "alice@example.com"),
		slog.String("password", "hide-me"),
		slog.String("secret", "top-secret"),
	))

	out := buf.String()
	assert.NotContains(t, out, "alice@example.com")
	assert.NotContains(t, out, "hide-me")
	assert.NotContains(t, out, "top-secret")
	assert.Contains(t, out, "al***@example.com")
	assert.Contains(t, out, "[SECRET]")
}

func TestStackOmitsInternalFrames(t *testing.T) {
	buf := &bytes.Buffer{}
	l := New(
		WithOutput(buf),
		WithFormat(FormatJSON),
		WithStackOnError(true),
	)

	l.Error("boom")

	var record map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &record))
	stack, ok := record["stack"].(string)
	require.True(t, ok)
	require.NotEmpty(t, stack)

	for _, internalFrame := range []string{
		"appendStackAttr",
		"DynamicHandler.Handle",
		internalPackagePath + ".(*Logger)",
	} {
		assert.NotContains(t, stack, internalFrame)
	}
}
