package dockerx

import (
	"context"
	"net"
	"runtime"
)

func isWindows() bool { return runtime.GOOS == "windows" }

// unixDialContext returns a dialer for a unix socket path.
func unixDialContext(path string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", path)
	}
}
