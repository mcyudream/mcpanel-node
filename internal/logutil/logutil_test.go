package logutil

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedact(t *testing.T) {
	require.Equal(t, Redacted, Redact("super-secret-value"))
	// Whitespace-only and empty values stay empty: logs must not imply a
	// secret exists when none does.
	require.Equal(t, "", Redact("  "))
	require.Equal(t, "", Redact(""))
}

func TestLoggerNeverEmitsSecretThroughRedact(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, "debug")
	secret := "s3cr3t-node-secret-value"
	l.Info("enroll ok", "nodeSecret", Redact(secret), "enrollToken", Redact("tok-123"))
	out := buf.String()
	require.False(t, strings.Contains(out, secret), "secret leaked into logs: %s", out)
	require.False(t, strings.Contains(out, "tok-123"), "token leaked into logs: %s", out)
	require.Contains(t, out, Redacted)
}

func TestLoggerLevels(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, "warn")
	l.Debug("d")
	l.Info("i")
	require.Equal(t, "", buf.String())
	l.Warn("w")
	require.True(t, strings.Contains(buf.String(), "w"))
	_ = slog.Default
}
