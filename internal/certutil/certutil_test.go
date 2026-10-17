package certutil

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAutogenerateAndReload(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{DataDir: dir, Hostname: "node-a.example.internal"}

	cert, leaf, err := m.Ensure()
	require.NoError(t, err)
	require.NotEmpty(t, cert.Certificate)
	require.NotNil(t, leaf)
	require.Equal(t, "node-a.example.internal", leaf.Subject.CommonName)

	fp1 := FingerprintHex(leaf.Raw)

	// Second boot must reuse the persisted certificate.
	m2 := &Manager{DataDir: dir}
	cert2, leaf2, err := m2.Ensure()
	require.NoError(t, err)
	require.Equal(t, fp1, FingerprintHex(leaf2.Raw))
	require.Equal(t, cert, cert2)
}

func TestKeyFilePerm0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows 的 os.Chmod 只切换只读位，Perm() 不反映 0600/0644 语义。
		t.Skip("POSIX permission semantics unavailable on windows")
	}
	dir := t.TempDir()
	m := &Manager{DataDir: dir}
	_, _, err := m.Ensure()
	require.NoError(t, err)

	keyInfo, err := os.Stat(filepath.Join(dir, autoKeyFile))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), keyInfo.Mode().Perm(), "tls key must be 0600")

	certInfo, err := os.Stat(filepath.Join(dir, autoCertFile))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), certInfo.Mode().Perm())
}

func TestProvidedCertFilesTakePrecedence(t *testing.T) {
	dir := t.TempDir()
	gen := &Manager{DataDir: dir, Hostname: "gen.internal"}
	_, _, err := gen.Ensure()
	require.NoError(t, err)

	customDir := t.TempDir()
	custom := &Manager{DataDir: customDir, Hostname: "custom.internal"}
	_, _, err = custom.Ensure()
	require.NoError(t, err)

	m := &Manager{
		DataDir:  customDir,
		CertFile: filepath.Join(customDir, autoCertFile),
		KeyFile:  filepath.Join(customDir, autoKeyFile),
	}
	_, leaf, err := m.Ensure()
	require.NoError(t, err)
	require.Equal(t, "custom.internal", leaf.Subject.CommonName)
}

func TestCertFileRequiresKeyFile(t *testing.T) {
	m := &Manager{DataDir: t.TempDir(), CertFile: "/tmp/x.pem"}
	_, _, err := m.Ensure()
	require.Error(t, err)
}

func TestFingerprintStable(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{DataDir: dir}
	fp, leaf, err := m.FingerprintPath()
	require.NoError(t, err)
	require.Len(t, fp, 64)
	require.Equal(t, FingerprintHex(leaf.Raw), fp)

	fp2, _, err := m.FingerprintPath()
	require.NoError(t, err)
	require.Equal(t, fp, fp2)
}

func TestSanityTLSCertUsable(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{DataDir: dir, Hostname: "usable.internal"}
	cert, _, err := m.Ensure()
	require.NoError(t, err)
	_, err = tls.X509KeyPair(read(t, dir, "node-cert.pem"), read(t, dir, "node-key.pem"))
	require.NoError(t, err)
	require.NotEmpty(t, cert.Certificate)
}

func read(t *testing.T, dir, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	require.NoError(t, err)
	return data
}
