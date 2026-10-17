package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaults(t *testing.T) {
	cfg, err := Load("")
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1:7443", cfg.Listen)
	require.True(t, cfg.TLS.AutoGen)
	require.Equal(t, "info", cfg.LogLevel)
}

func TestLoadYAMLErrors(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "config.yaml")
	yaml := `
listen: 127.0.0.1:9443
panel:
  url: https://panel.example.com
  tlsPinSha256: aa.bb
`
	require.NoError(t, os.WriteFile(yamlPath, []byte(yaml), 0o600))
	_, err := Load(yamlPath)
	require.Error(t, err, "invalid pin in file must fail validation")
}

func TestEnvPinOverridesBadFilePin(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "config.yaml")
	yaml := `
listen: 127.0.0.1:9443
panel:
  url: https://panel.example.com
  tlsPinSha256: aa.bb
`
	require.NoError(t, os.WriteFile(yamlPath, []byte(yaml), 0o600))
	t.Setenv("MCNODE_PANEL_TLS_PIN_SHA256", "0011223344556677889900aabbccddeeff0011223344556677889900aabbccdd")

	cfg, err := Load(yamlPath)
	require.NoError(t, err)
	require.Equal(t, "0011223344556677889900aabbccddeeff0011223344556677889900aabbccdd", cfg.Panel.TLSPinSha256)
}

func TestEnvOverridesValidConfig(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "config.yaml")
	yaml := `
listen: 127.0.0.1:9443
panel:
  url: https://panel.example.com
`
	require.NoError(t, os.WriteFile(yamlPath, []byte(yaml), 0o600))

	t.Setenv("MCNODE_LISTEN", "127.0.0.1:9555")
	t.Setenv("MCNODE_DATA_DIR", filepath.Join(dir, "data"))
	t.Setenv("MCNODE_LOG_LEVEL", "warn")

	cfg, err := Load(yamlPath)
	require.NoError(t, err)
	require.Equal(t, "127.0.0.1:9555", cfg.Listen)
	require.Equal(t, "warn", cfg.LogLevel)
	require.Equal(t, filepath.Join(dir, "data"), cfg.DataDir)
}

func TestValidatePinLength(t *testing.T) {
	cfg := Defaults()
	cfg.Panel.TLSPinSha256 = "tooshort"
	require.Error(t, cfg.Validate())
	cfg.Panel.TLSPinSha256 = "0011223344556677889900aabbccddeeff0011223344556677889900aabbccdd"
	require.NoError(t, cfg.Validate())
}

func TestValidateTLSCombos(t *testing.T) {
	cfg := Defaults()
	cfg.TLS.AutoGen = false
	require.Error(t, cfg.Validate())

	cfg.TLS.CertFile = "/certs/cert.pem"
	require.Error(t, cfg.Validate(), "cert without key must fail")

	cfg.TLS.KeyFile = "/certs/key.pem"
	require.NoError(t, cfg.Validate())
}

func TestValidateListen(t *testing.T) {
	cfg := Defaults()
	cfg.Listen = "7443"
	require.Error(t, cfg.Validate())
	cfg.Listen = "127.0.0.1:"
	require.Error(t, cfg.Validate())
	cfg.Listen = "127.0.0.1:74x3"
	require.Error(t, cfg.Validate())
	cfg.Listen = "127.0.0.1:7443"
	require.NoError(t, cfg.Validate())
}

func TestNoSecretDefaults(t *testing.T) {
	// Default configuration must never embed a usable secret.
	cfg := Defaults()
	require.Empty(t, cfg.Enroll.Token)
	require.Empty(t, cfg.FRPC.Token)
	require.Empty(t, cfg.Panel.TLSPinSha256)
}

func TestFileRootEmptyPathFallsBackToDataDir(t *testing.T) {
	// Default config: {name: data, path: ""} must resolve to the data dir,
	// otherwise every node.file.* call fails with 节点未配置文件根.
	cfg, err := Load("")
	require.NoError(t, err)
	require.Len(t, cfg.FileRoots, 1)
	require.Equal(t, "data", cfg.FileRoots[0].Name)
	require.Equal(t, cfg.DataDir, cfg.FileRoots[0].Path)
}

func TestFileRootExplicitPathUntouched(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "config.yaml")
	yaml := `
listen: 127.0.0.1:9443
panel:
  url: https://panel.example.com
dataDir: /srv/mcnode
fileRoots:
  - name: srv
    path: /srv/mc
  - name: data
`
	require.NoError(t, os.WriteFile(yamlPath, []byte(yaml), 0o600))
	cfg, err := Load(yamlPath)
	require.NoError(t, err)
	require.Equal(t, "/srv/mc", cfg.FileRoots[0].Path)
	require.Equal(t, "/srv/mcnode", cfg.FileRoots[1].Path, "empty path root falls back to dataDir")
	require.Equal(t, "data", cfg.FileRoots[1].Name, "unnamed fallback root keeps default name")
}
