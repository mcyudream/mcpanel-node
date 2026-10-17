package wsserver

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCompletePrefixAndLimit(t *testing.T) {
	c := &shellCompleter{names: []string{"docker", "docker-compose", "dotnet", "ls", "ps"}, scanned: time.Now()}

	require.Equal(t, []string{"docker", "docker-compose"}, c.complete("doc", 10))
	require.Equal(t, []string{"docker"}, c.complete("doc", 1), "limit caps the result")
	require.Equal(t, []string{"docker", "docker-compose", "dotnet"}, c.complete("d", 10))
	require.Equal(t, []string{"ls"}, c.complete("LS", 10), "prefix match is case-insensitive")
	require.Empty(t, c.complete("", 10), "empty prefix completes nothing")
	require.Empty(t, c.complete("docker ps", 10), "multi-word input is not a command token")
	require.Empty(t, c.complete("/bin/ls", 10), "paths are not completed")
	require.Empty(t, c.complete("zzz", 10))
}

func TestCompleteCacheTTL(t *testing.T) {
	c := &shellCompleter{names: []string{"marker"}, scanned: time.Now()}
	require.Equal(t, []string{"marker"}, c.snapshot(), "fresh cache is reused without rescan")

	c.scanned = time.Now().Add(-2 * completionCacheTTL)
	require.NotEqual(t, []string{"marker"}, c.snapshot(), "expired cache triggers a rescan")
}

func TestScanPathExecutables(t *testing.T) {
	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("PATHEXT", ".exe")
		require.NoError(t, os.WriteFile(filepath.Join(dir, "zzdemo.exe"), nil, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "zzskip.txt"), nil, 0o644))
	} else {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "zzdemo"), nil, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "zzskip"), nil, 0o644), "no exec bit must be skipped")
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+filepath.Dir(t.TempDir()))

	names := scanPathExecutables()
	require.Equal(t, []string{"zzdemo"}, names)
}
