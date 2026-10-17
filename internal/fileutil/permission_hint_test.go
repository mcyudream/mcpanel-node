package fileutil

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

func TestPermissionHint(t *testing.T) {
	if got := PermissionHint(nil, "world"); got != nil {
		t.Fatalf("nil 必须原样返回，got %v", got)
	}
	plain := errors.New("boom")
	if got := PermissionHint(plain, "world"); got != plain {
		t.Fatalf("非权限错误必须原样返回，got %v", got)
	}

	denied := &fs.PathError{Op: "open", Path: "/data/instances/i/world/level.dat", Err: syscall.EACCES}
	hinted := PermissionHint(denied, "world/level.dat")
	if !errors.Is(hinted, fs.ErrPermission) {
		t.Fatalf("提示包装后必须保留 errno 语义：%v", hinted)
	}
	if !errors.Is(hinted, denied) {
		t.Fatalf("必须能通过 errors.Is 回溯到原始错误：%v", hinted)
	}
	msg := hinted.Error()
	for _, want := range []string{"无权访问", "world/level.dat", "permission denied"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("提示缺少 %q：%s", want, msg)
		}
	}
	if again := PermissionHint(hinted, "world/level.dat"); again != hinted {
		t.Fatalf("已提示错误不得重复包装：%v", again)
	}

	// EPERM（改权限/写入被拒）同样覆盖；空 rel 回退为实例数据目录。
	perm := PermissionHint(&fs.PathError{Op: "chmod", Path: "/data/instances/i", Err: syscall.EPERM}, "")
	if perm == nil || !strings.Contains(perm.Error(), "实例数据目录") {
		t.Fatalf("空 rel 需回退为实例数据目录：%v", perm)
	}
}

// Resolve 的 mustExist 分支过去把一切 Lstat 失败都归为 NotExist；权限类必须
// 保留原错误（否则面板会把「无权访问」误导成「文件不存在」）。
func TestResolveKeepsNotExistForMissingPath(t *testing.T) {
	root := t.TempDir()
	if _, err := Resolve(root, "nope", true); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("缺失路径必须报 os.ErrNotExist：%v", err)
	}
}

// 真实 EACCES 只能在非 root 的 POSIX 环境构造：属主受限文件参与打包时必须
// 得到带指引的错误，而不是裸 open errno。
func TestZipPathsHintsPermissionError(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("需要非 root 的 POSIX 环境才能构造 EACCES")
	}
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "world", "level.dat"), "BIN")
	if err := os.Chmod(filepath.Join(root, "world", "level.dat"), 0); err != nil {
		t.Fatal(err)
	}
	if _, err := ZipPaths(root, []string{"world"}, "out"); err == nil {
		t.Fatal("无读权限的条目必须让打包失败")
	} else if !strings.Contains(err.Error(), "无权访问") {
		t.Fatalf("权限错误必须带可操作指引：%v", err)
	}
}
