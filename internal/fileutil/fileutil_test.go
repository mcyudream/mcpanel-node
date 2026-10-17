package fileutil

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestResolveRejectsEscape(t *testing.T) {
	root := t.TempDir()
	for _, bad := range []string{"/etc/passwd", `C:\windows`, "../outside", "a/../../b", "a\x00b"} {
		if _, err := Resolve(root, bad, false); err == nil {
			t.Fatalf("Resolve(%q) 必须拒绝", bad)
		}
	}
	ok, err := Resolve(root, "plugins/config.yml", false)
	if err != nil || !strings.HasPrefix(ok, root) {
		t.Fatalf("合法相对路径被拒绝: %v", err)
	}
}

func TestResolveRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	mustWrite(t, filepath.Join(outside, "secret.txt"), "x")
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Skip("平台不支持符号链接")
	}
	if _, err := Resolve(root, "link/secret.txt", true); err == nil {
		t.Fatal("符号链接逃逸必须被拒绝")
	}
}

func TestWriteReadRoundtrip(t *testing.T) {
	root := t.TempDir()
	content := "server-port=25565\nmotd=hi\n"
	enc := base64.StdEncoding.EncodeToString([]byte(content))
	if err := Write(root, "server.properties", enc, "base64"); err != nil {
		t.Fatal(err)
	}
	got, err := Read(root, "server.properties")
	if err != nil {
		t.Fatal(err)
	}
	if got["encoding"] != "base64" || got["size"].(int) != len(content) {
		t.Fatalf("读取元数据不符: %v", got)
	}
	if decode, _ := base64.StdEncoding.DecodeString(got["content"].(string)); string(decode) != content {
		t.Fatalf("内容不一致: %q", decode)
	}
	if err := Write(root, "bad", "!!!not-base64!!!", "base64"); err == nil {
		t.Fatal("非法 base64 必须被拒绝")
	}
}

func TestListEntriesSortedDirsFirst(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "b.txt"), "1")
	mustWrite(t, filepath.Join(root, "a.txt"), "2")
	if err := os.MkdirAll(filepath.Join(root, "zdir"), 0755); err != nil {
		t.Fatal(err)
	}
	entries, err := List(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 || !entries[0].IsDir || entries[0].Name != "zdir" {
		t.Fatalf("目录应排在最前: %+v", entries)
	}
}

func TestChunkedUploadCommitVerifies(t *testing.T) {
	root := t.TempDir()
	mgr := NewManager(func(id string) (string, error) { return root, nil })
	payload := strings.Repeat("panel-", 4000) // 24KB > 单块，需分多块
	sum := sha256.Sum256([]byte(payload))
	id, err := mgr.Begin("i1", "world/data.bin", int64(len(payload)), hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(payload)
	off := 0
	for off < len(raw) {
		end := off + MaxDataBytes
		if end > len(raw) {
			end = len(raw)
		}
		if err := mgr.Chunk(id, int64(off), base64.StdEncoding.EncodeToString(raw[off:end])); err != nil {
			t.Fatal(err)
		}
		off = end
	}
	if _, err := mgr.Commit(id); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, "world", "data.bin"))
	if err != nil || string(b) != payload {
		t.Fatalf("上传内容不一致: %v", err)
	}
	// 坏 sha256 必须失败且不留临时文件
	id2, _ := mgr.Begin("i1", "bad.bin", int64(len(payload)), strings.Repeat("0", 64))
	_ = mgr.Chunk(id2, 0, base64.StdEncoding.EncodeToString(raw))
	if _, err := mgr.Commit(id2); err == nil {
		t.Fatal("sha256 不匹配必须失败")
	}
	files, _ := os.ReadDir(root)
	for _, f := range files {
		if strings.HasPrefix(f.Name(), ".panel-") {
			t.Fatalf("临时文件泄漏: %s", f.Name())
		}
	}
}

func TestBackupCreateRestoreRoundtrip(t *testing.T) {
	root := t.TempDir()
	backupDir := filepath.Join(t.TempDir(), "backups")
	mustWrite(t, filepath.Join(root, "server.properties"), "a=1")
	mustWrite(t, filepath.Join(root, "world", "level.dat"), "BIN")
	target, err := CreateBackup(root, backupDir, "i1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(target, ".zip") {
		t.Fatalf("备份文件名异常: %s", target)
	}
	// 清空后恢复
	_ = os.RemoveAll(filepath.Join(root, "world"))
	_ = os.Remove(filepath.Join(root, "server.properties"))
	if err := RestoreBackup(backupDir, filepath.Base(target), root); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "world", "level.dat")); string(b) != "BIN" {
		t.Fatal("恢复内容不一致")
	}
	list, err := ListBackups(backupDir)
	if err != nil || len(list) != 1 {
		t.Fatalf("备份列表异常: %v %v", list, err)
	}
	if err := DeleteBackup(backupDir, "../evil.zip"); err == nil {
		t.Fatal("备份删除必须拒绝路径穿越")
	}
}

func TestCheckPorts(t *testing.T) {
	results := CheckPorts([]struct {
		Port  int
		Proto string
	}{{Port: 0, Proto: "tcp"}, {Port: 65536, Proto: "tcp"}, {Proto: "tcp"}})
	for _, r := range results {
		if r["free"] == true {
			t.Fatalf("非法端口必须判不空闲: %v", r)
		}
	}
}

func TestAbortInstance(t *testing.T) {
	root := t.TempDir()
	mgr := NewManager(func(id string) (string, error) { return root, nil })
	sum := strings.Repeat("0", 64)
	idA, err := mgr.Begin("inst-a", "a.bin", 4, sum)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = mgr.Begin("inst-a", "b.bin", 4, sum); err != nil {
		t.Fatal(err)
	}
	idB, err := mgr.Begin("inst-b", "c.bin", 4, sum)
	if err != nil {
		t.Fatal(err)
	}
	// Abort 必须只清目标实例的会话与临时文件，其他实例不受影响。
	if n := mgr.AbortInstance("inst-a"); n != 2 {
		t.Fatalf("inst-a 应中止 2 个上传, got %d", n)
	}
	if _, err := os.Stat(filepath.Join(root, "a.bin")); !os.IsNotExist(err) {
		t.Fatal("已提交路径不应存在（会话处于上传中）")
	}
	// inst-b 会话仍可继续写入。
	if err := mgr.Chunk(idB, 0, base64.StdEncoding.EncodeToString([]byte("test"))); err != nil {
		t.Fatalf("其他实例会话不得被中止: %v", err)
	}
	// 全部会话结束后，临时文件必须一个不剩（Abort 负责关闭并删除 tmp）。
	if n := mgr.AbortInstance("inst-b"); n != 1 {
		t.Fatalf("inst-b 应中止 1 个上传, got %d", n)
	}
	entries, _ := os.ReadDir(root)
	for _, f := range entries {
		if strings.HasPrefix(f.Name(), ".panel-") {
			t.Fatalf("中止后临时文件泄漏: %s", f.Name())
		}
	}
	// 已中止的会话再次 Abort 幂等返回 nil（不报错）；重复 AbortInstance 返回 0。
	if err := mgr.Abort(idA); err != nil {
		t.Fatalf("重复中止必须幂等: %v", err)
	}
	if n := mgr.AbortInstance("inst-a"); n != 0 {
		t.Fatalf("重复中止应返回 0, got %d", n)
	}
}
