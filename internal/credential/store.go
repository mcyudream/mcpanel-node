// Package credential persists the per-node identity issued by the panel
// bootstrap endpoint. The file contains a high-entropy secret and is written
// atomically with 0600 permissions.
package credential

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// MinSecretLen is the exact expected nodeSecret length: 43 base64url chars
// encoding 32 bytes of entropy (protocol §2).
const MinSecretLen = 43

// SecretEntropyBytes is the required decoded secret size.
const SecretEntropyBytes = 32

// FRPPlan carries the M1b (experimental) frp control plan issued at bootstrap.
// The embedded frpc uses it to establish the outbound TCP tunnel; the frp
// token is node-specific and never the frps admin token.
type FRPPlan struct {
	ServerAddr string `json:"serverAddr"`
	ServerPort int    `json:"serverPort"`
	ProxyUser  string `json:"proxyUser"`
	ProxyToken string `json:"proxyToken"`
	RemotePort int    `json:"remotePort"`
}

// ControlPlan describes how the panel reaches this node's control channel.
type ControlPlan struct {
	Mode string   `json:"mode"` // "direct" (M1a) | "frp" (M1b, experimental)
	FRP  *FRPPlan `json:"frp,omitempty"`
}

// Credential is the persisted node identity.
type Credential struct {
	NodeID          string      `json:"nodeId"`
	NodeSecret      string      `json:"nodeSecret"`
	ServerTimeMs    int64       `json:"serverTimeMs"`
	ControlPlan     ControlPlan `json:"controlPlan"`
	EnrolledAtMs    int64       `json:"enrolledAtMs"`
}

// Validate enforces invariants before the credential may be used or stored.
func (c Credential) Validate() error {
	if c.NodeID == "" {
		return errors.New("nodeId is empty")
	}
	if len(c.NodeSecret) != MinSecretLen {
		return fmt.Errorf("nodeSecret must be %d base64url chars (got %d)", MinSecretLen, len(c.NodeSecret))
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.NodeSecret)
	if err != nil || len(raw) != SecretEntropyBytes {
		return errors.New("nodeSecret must decode to 32 bytes of base64url entropy")
	}
	switch c.ControlPlan.Mode {
	case "direct":
	case "frp":
		if c.ControlPlan.FRP == nil {
			return errors.New("controlPlan frp mode requires frp section")
		}
		if c.ControlPlan.FRP.ServerAddr == "" || c.ControlPlan.FRP.ServerPort <= 0 ||
			c.ControlPlan.FRP.ProxyToken == "" || c.ControlPlan.FRP.RemotePort <= 0 {
			return errors.New("controlPlan frp section incomplete")
		}
	default:
		return fmt.Errorf("unsupported controlPlan mode %q", c.ControlPlan.Mode)
	}
	return nil
}

// Store reads and writes the credential file.
type Store struct {
	Path string
}

// DefaultPath returns <dataDir>/credential.json.
func DefaultPath(dataDir string) string {
	return filepath.Join(dataDir, "credential.json")
}

// NewStore builds a store for path (empty path -> DefaultPath under dataDir).
func NewStore(dataDir, path string) Store {
	if path == "" {
		path = DefaultPath(dataDir)
	}
	return Store{Path: path}
}

// Save writes the credential atomically with 0600 permissions. A partially
// written file can never be observed under the final path.
func (s Store) Save(c Credential) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return fmt.Errorf("create credential dir: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credential: %w", err)
	}
	return writeFileAtomic0600(s.Path, data)
}

// maxCredentialBytes bounds the credential file size. The file is a small
// JSON object; anything larger is corrupt or hostile.
const maxCredentialBytes = 16 << 10

// Load reads the credential from disk.
//
// Hardening: the path must be a regular file under the size cap; on POSIX
// systems the file mode must not expose the secret to group/other. Error
// messages never quote file content.
func (s Store) Load() (Credential, error) {
	info, err := os.Stat(s.Path)
	if err != nil {
		return Credential{}, err
	}
	if !info.Mode().IsRegular() {
		return Credential{}, errors.New("credential path is not a regular file")
	}
	if info.Size() > maxCredentialBytes {
		return Credential{}, errors.New("credential file exceeds size cap")
	}
	if err := checkFileMode(info.Mode()); err != nil {
		return Credential{}, err
	}
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return Credential{}, err
	}
	if len(data) > maxCredentialBytes {
		return Credential{}, errors.New("credential file exceeds size cap")
	}
	var c Credential
	if err := json.Unmarshal(data, &c); err != nil {
		// Deliberately no %w: decoder errors can echo fragments of content.
		return Credential{}, errors.New("credential file is corrupt or not valid JSON")
	}
	if err := c.Validate(); err != nil {
		return Credential{}, fmt.Errorf("invalid credential: %w", err)
	}
	return c, nil
}

// checkFileMode enforces secret hygiene on POSIX systems: group and other
// permission bits must be clear (0600 expected). Windows mode bits carry no
// POSIX semantics and are not enforced here (deployment target is Linux).
func checkFileMode(m os.FileMode) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if m.Perm()&0o077 != 0 {
		return fmt.Errorf("credential file permissions too open (%o); want 0600", m.Perm())
	}
	return nil
}

// Exists reports whether a credential file is present.
func (s Store) Exists() bool {
	_, err := os.Stat(s.Path)
	return err == nil
}

func writeFileAtomic0600(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".credential.tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return nil
}
