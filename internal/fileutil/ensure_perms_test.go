package fileutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// 启动前权限自动修复：root 写入的 0644/0755 文件与目录必须放开为「所有人
// 可读写」，否则容器内非 root uid（镜像决定）对节点侧写入的内容 EACCES。
// Windows 的 chmod 语义不适用（EnsureWorldWritable 直接跳过），仅在 Linux
// 上断言真实权限位。
func TestEnsureWorldWritable(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "config", "subdir")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(dir, "server.toml")
	if err := os.WriteFile(plain, []byte("k=v"), 0o644); err != nil {
		t.Fatal(err)
	}
	exec := filepath.Join(root, "run.sh")
	if err := os.WriteFile(exec, []byte("#!/bin/sh"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(plain, filepath.Join(root, "link.toml")); err != nil {
		t.Fatal(err)
	}

	if err := EnsureWorldWritable(root, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		return // Windows 上 chmod 不改变 rwx 位，以上不报错即可
	}
	for _, check := range []struct {
		path string
		want os.FileMode
	}{
		{root, 0o777},
		{dir, 0o777},
		{filepath.Dir(dir), 0o777},
		{plain, 0o666},
		{exec, 0o777}, // 既有执行位保留并放开
	} {
		info, err := os.Stat(check.path)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS == "windows" {
			continue
		}
		if info.Mode().Perm() != check.want {
			t.Fatalf("%s perm = %o, want %o", check.path, info.Mode().Perm(), check.want)
		}
	}
}

func TestEnsureWorldWritableDeadline(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 语义在 Windows 不适用")
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "a", "b"), 0o755); err != nil {
		t.Fatal(err)
	}
	// 零超时：立即放弃且不报错（尽力而为语义）。
	if err := EnsureWorldWritable(root, 0); err != nil {
		t.Fatalf("零超时应静默返回，got %v", err)
	}
}
