// Package logutil provides the node JSON logger and secret redaction helpers.
//
// Redaction rule: secrets (nodeSecret, enrollToken, frp token) must never be
// formatted into logs. Callers pass them through Redact so a mistake upstream
// still renders "[redacted]". Error values constructed from HTTP response
// bodies are forbidden in the enroll client; only status codes are logged.
package logutil

import (
	"context"
	"io"
	"log/slog"
	"strings"
)

// Redacted is the placeholder emitted for any sensitive value.
const Redacted = "[redacted]"

// Redact renders any non-empty sensitive value as a fixed placeholder.
// Empty values stay empty so logs do not imply a secret exists when none does.
func Redact(secret string) string {
	if strings.TrimSpace(secret) == "" {
		return ""
	}
	return Redacted
}

// New builds the process JSON logger. level is one of debug|info|warn|error.
func New(w io.Writer, level string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lv})
	return slog.New(h)
}

// ErrKey redacts an error message before attaching to a log record when the
// error may embed sensitive material. Normal errors should use slog.Any.
func ErrKey(ctx context.Context, l *slog.Logger, msg string, safeErr error) {
	if safeErr == nil {
		l.InfoContext(ctx, msg)
		return
	}
	l.InfoContext(ctx, msg, "err", safeErr.Error())
}
