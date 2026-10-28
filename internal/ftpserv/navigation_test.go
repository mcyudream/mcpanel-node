package ftpserv

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func TestNestedNavigationTransfersAndSessionRevocation(t *testing.T) {
	manager, err := NewManager()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err = os.MkdirAll(filepath.Join(root, "plugins", "Example"), 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "plugins", "Example", "config.yml"), []byte("old-value"), 0644); err != nil {
		t.Fatal(err)
	}
	opened, err := manager.Open("nested", root, 0, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close("nested")
	conn, err := ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(opened.Port)), &ssh.ClientConfig{
		User: opened.User, Auth: []ssh.AuthMethod{ssh.Password(opened.Password)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client, err := sftp.NewClient(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for input, expected := range map[string]string{".": "/", "/plugins": "/plugins", "/plugins/Example/../Example": "/plugins/Example"} {
		actual, err := client.RealPath(input)
		if err != nil || actual != expected {
			t.Fatalf("RealPath(%q) = %q, %v; want %q", input, actual, err, expected)
		}
	}
	items, err := client.ReadDir("/plugins/Example")
	if err != nil || len(items) != 1 || items[0].Name() != "config.yml" {
		t.Fatalf("nested list: %v, %v", items, err)
	}
	// Opening without O_TRUNC is how clients resume uploads. Preserve the suffix.
	file, err := client.OpenFile("/plugins/Example/config.yml", os.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.WriteAt([]byte("new"), 0); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if err = client.Rename("/plugins/Example/config.yml", "/plugins/Example/renamed.yml"); err != nil {
		t.Fatal(err)
	}
	read, err := client.Open("/plugins/Example/renamed.yml")
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := io.ReadAll(read)
	read.Close()
	if err != nil || string(bytes) != "new-value" {
		t.Fatalf("nested file bytes=%q, err=%v", bytes, err)
	}
	if !manager.Close("nested") {
		t.Fatal("session not closed")
	}
	done := make(chan error, 1)
	go func() { _, err := client.ReadDir("/plugins"); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("closed credentials still have an active connection")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("active SFTP connection was not revoked")
	}
}

func TestAncestorSymlinkCannotEscapeVirtualRoot(t *testing.T) {
	root, outside := t.TempDir(), t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"/escape/new.txt", "/escape", "escape/child/new.txt"} {
		if _, err := ResolveSafe(root, rel); err == nil {
			t.Fatalf("escape allowed: %s", rel)
		}
	}
	if _, err := (&rootedChannel{root: root}).RealPath("/escape"); err == nil {
		t.Fatal("RealPath leaked outside root")
	}
	if _, err := ResolveSafe(root, "/plugins/new.txt"); err != nil {
		t.Fatalf("safe nonexistent target rejected: %v", err)
	}
}
