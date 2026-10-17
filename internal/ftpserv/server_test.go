package ftpserv

import (
 "fmt"
 "net"
 "os"
 "path/filepath"
 "testing"
 "time"

 "github.com/pkg/sftp"
 gossh "golang.org/x/crypto/ssh"
)

// 端到端：真实 Manager + pkg/sftp 客户端，验证根目录钉死——
// Getwd 与 ReadDir("/") 都必须落在实例数据目录内，绝不能见到 root 之外的内容。
func TestSftpSessionRootedAtInstanceDir(t *testing.T) {
 m, err := NewManager()
 if err != nil {
  t.Fatalf("NewManager: %v", err)
 }
 root := t.TempDir()
 if err := os.WriteFile(filepath.Join(root, "hello.txt"), []byte("hi"), 0644); err != nil {
  t.Fatal(err)
 }
 if err := os.Mkdir(filepath.Join(root, "sub"), 0755); err != nil {
  t.Fatal(err)
 }
 rootOut, _ := os.Getwd()
 _ = rootOut

 opened, err := m.Open("inst-e2e", root, 0, 5)
 if err != nil {
  t.Fatalf("Open: %v", err)
 }
 defer func() { _ = m.Close("inst-e2e") }()

 cfg := &gossh.ClientConfig{
  User:            opened.User,
  Auth:            []gossh.AuthMethod{gossh.Password(opened.Password)},
  HostKeyCallback: gossh.InsecureIgnoreHostKey(),
  Timeout:         5 * time.Second,
 }
 addr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", opened.Port))
 conn, err := gossh.Dial("tcp", addr, cfg)
 if err != nil {
  t.Fatalf("dial: %v", err)
 }
 defer conn.Close()

 client, err := sftp.NewClient(conn)
 if err != nil {
  t.Fatalf("sftp.NewClient: %v", err)
 }
 defer client.Close()

 wd, err := client.Getwd()
 t.Logf("Getwd=%q root=%q", wd, root)

 names := map[string]bool{}
 entries, err := client.ReadDir("/")
 if err != nil {
  t.Fatalf("ReadDir(/): %v", err)
 }
 for _, e := range entries {
  names[e.Name()] = true
 }
 t.Logf("ReadDir(/) names=%v", keys(names))

 if !names["hello.txt"] || !names["sub"] {
  t.Fatalf("根目录未映射到实例数据目录: %v", keys(names))
 }
 for _, leaked := range []string{"bin", "etc", "usr", "home", "var", "tmp", "windows", "program files"} {
  if names[leaked] {
   t.Fatalf("越权：根目录出现宿主系统目录 %q（全部条目=%v）", leaked, keys(names))
  }
 }
}

func keys(m map[string]bool) []string {
 out := make([]string, 0, len(m))
 for k := range m {
  out = append(out, k)
 }
 return out
}
