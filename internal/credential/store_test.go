package credential

import (
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

// 43 base64url chars decoding to 32 bytes (256-bit entropy), test-only value.
const testSecret = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY"

func validCredential() Credential {
	return Credential{
		NodeID:       "node-1",
		NodeSecret:   testSecret,
		ServerTimeMs: 1737619200000,
		ControlPlan:  ControlPlan{Mode: "direct"},
		EnrolledAtMs: 1737619200000,
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir, "")

	require.False(t, s.Exists())
	require.NoError(t, s.Save(validCredential()))
	require.True(t, s.Exists())

	got, err := s.Load()
	require.NoError(t, err)
	require.Equal(t, "node-1", got.NodeID)
	require.Equal(t, testSecret, got.NodeSecret)
	require.Equal(t, "direct", got.ControlPlan.Mode)
	require.NoError(t, got.Validate())
}

func TestFilePerm0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows 的 os.Chmod 只切换只读位，Perm() 不反映 0600 语义。
		t.Skip("POSIX permission semantics unavailable on windows")
	}
	dir := t.TempDir()
	s := NewStore(dir, "")
	require.NoError(t, s.Save(validCredential()))

	info, err := os.Stat(s.Path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "credential file must be 0600")
}

func TestAtomicNoTempLeftover(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir, "")
	require.NoError(t, s.Save(validCredential()))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "temp files must be cleaned up after atomic write")
	require.Equal(t, "credential.json", entries[0].Name())
}

func TestValidateRejectsWeakOrShortSecret(t *testing.T) {
	for _, bad := range []string{"short", "", "0123456789abcdef0123456789abcdef", // 32 chars, must now be 43
		"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYa"} { // 44 chars
		c := validCredential()
		c.NodeSecret = bad
		require.Error(t, c.Validate(), "secret %q must be rejected", bad)
	}

	c := validCredential()
	c.NodeID = ""
	require.Error(t, c.Validate())
}

func TestValidateRejectsBadBase64URL(t *testing.T) {
	c := validCredential()
	c.NodeSecret = "!!!!!!!!11111111111111111111111111111111111" // 43 chars, not valid base64url
	require.Error(t, c.Validate())
}

func TestValidateControlPlan(t *testing.T) {
	c := validCredential()
	c.ControlPlan = ControlPlan{Mode: "unknown"}
	require.Error(t, c.Validate())

	c.ControlPlan = ControlPlan{Mode: "frp"}
	require.Error(t, c.Validate(), "frp mode without frp section must fail")

	c.ControlPlan = ControlPlan{Mode: "frp", FRP: &FRPPlan{
		ServerAddr: "frps.example.com", ServerPort: 7000,
		ProxyUser: "node-1937", ProxyToken: "node-specific-proxy-token", RemotePort: 7101,
	}}
	require.NoError(t, c.Validate())
}

func TestLoadRejectsCorruptAndWeak(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir, "")

	require.NoError(t, os.WriteFile(s.Path, []byte("not json"), 0o600))
	_, err := s.Load()
	require.Error(t, err)
	require.NotContains(t, err.Error(), "not json", "load errors must not quote file content")

	// Remove the corrupt file first: it must not be mistaken for evidence
	// that a weak credential was persisted.
	require.NoError(t, os.Remove(s.Path))

	weak := validCredential()
	weak.NodeSecret = "nope"
	require.Error(t, s.Save(weak))
	require.False(t, s.Exists(), "weak credential must not be persisted")
}

func TestLoadRejectsOversizeAndIrregularAndLoosePerm(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Windows 的 os.Chmod 只切换只读位，Perm() 不反映 0644/0600 语义。
		t.Skip("POSIX permission semantics unavailable on windows")
	}
	dir := t.TempDir()
	s := NewStore(dir, "")

	// Oversize file (content not valid credential anyway; size checked first).
	big := make([]byte, 17<<10)
	require.NoError(t, os.WriteFile(s.Path, big, 0o600))
	_, err := s.Load()
	require.ErrorContains(t, err, "size cap")

	// Non-regular file (directory).
	require.NoError(t, os.Remove(s.Path))
	require.NoError(t, os.Mkdir(s.Path, 0o700))
	_, err = s.Load()
	require.ErrorContains(t, err, "regular file")
	require.NoError(t, os.Remove(s.Path))

	// Loose permissions on POSIX (test runs in a Linux container).
	require.NoError(t, s.Save(validCredential()))
	require.NoError(t, os.Chmod(s.Path, 0o644))
	_, err = s.Load()
	require.ErrorContains(t, err, "permissions too open")
}

func TestLoadRejectsHugeJSON(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir, "")
	require.NoError(t, os.WriteFile(s.Path, []byte(`{"nodeId":"x"}`), 0o600))
	_, err := s.Load()
	require.Error(t, err, "valid-json-but-invalid-credential must be rejected by Validate")
}
