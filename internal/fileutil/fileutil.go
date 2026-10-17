package fileutil

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const MaxDataBytes = 96 * 1024

// EnsureWorldWritable 递归放开实例数据目录为「所有人可读写」（目录附加 x，
// 保留文件既有执行位），修复节点侧 root 写入（装核心/整合包/文件管理）与
// 容器内非 root uid（镜像决定，如 openjdk25 的 10001）之间的属主错位——
// 否则容器内服务端对 root 建的目录/文件 EACCES，启动即崩。每次启动前由
// instances.Service 调用；权限位是元数据操作，整树遍历成本可接受（有界）。
// Windows 的 chmod 语义不适用（仅只读位），直接跳过。尽力而为：单项失败
// 跳过不中断整树；总时长超时后放弃剩余项（残缺权限下次启动继续修复）。
func EnsureWorldWritable(root string, timeout time.Duration) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	deadline := time.Now().Add(timeout)
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // 单项不可达跳过，不中断整树
		}
		if time.Now().After(deadline) {
			return fs.SkipAll
		}
		info, ierr := d.Info()
		if ierr != nil || info.Mode()&fs.ModeSymlink != 0 {
			return nil // 跳过符号链接（chmod 会作用到目标）
		}
		mode := info.Mode().Perm()
		if d.IsDir() {
			if mode != 0o777 {
				_ = os.Chmod(path, 0o777)
			}
			return nil
		}
		want := mode | 0o666
		if mode&0o111 != 0 {
			want |= 0o111
		}
		if mode != want {
			_ = os.Chmod(path, want)
		}
		return nil
	})
}

// hintedError 标记已附带权限指引的错误，避免多层包装重复叠加提示文案。
type hintedError struct{ err error }

func (e *hintedError) Error() string { return e.err.Error() }
func (e *hintedError) Unwrap() error { return e.err }

// PermissionHint 把权限类错误（EACCES/EPERM）翻译成可操作的指引。实例数据是
// bind mount：文件属主由容器内镜像 uid（如 openjdk25 的 10001）与节点侧写入
// 共同决定，节点进程缺 DAC_OVERRIDE/FOWNER 时读、写、改权限都失败且无法自愈；
// 裸 errno 无法告诉面板该在主机上修什么。非权限错误与已提示过的错误原样返回，
// errno 语义保持（errors.Is/As 仍可判定）。
func PermissionHint(err error, rel string) error {
	if err == nil || !errors.Is(err, fs.ErrPermission) {
		return err
	}
	var hinted *hintedError
	if errors.As(err, &hinted) {
		return err
	}
	where := rel
	if where == "" {
		where = "实例数据目录"
	}
	return &hintedError{fmt.Errorf("节点进程无权访问「%s」：文件属主与节点运行用户不一致（容器内非 root uid 写盘所致）；请在节点主机执行 chmod -R a+rX <实例数据目录>（或 chown -R root:root）后重试：%w", where, err)}
}

// Resolve 把实例内相对路径钉死在 root 下：拒绝绝对路径、.. 逃逸与符号链接逃逸。
// 空 rel 表示实例根本身（仅用于列目录）。
func Resolve(root, rel string, mustExist bool) (string, error) {
	if strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "\\") || filepath.IsAbs(rel) {
		return "", errors.New("路径必须为实例内相对路径")
	}
	if len(rel) > 1 && rel[1] == ':' {
		return "", errors.New("路径必须为实例内相对路径")
	}
	if strings.Contains(rel, "\x00") {
		return "", errors.New("路径含非法字符")
	}
	if rel == "" {
		if mustExist {
			if _, err := os.Lstat(root); err != nil {
				return "", os.ErrNotExist
			}
		}
		return root, nil
	}
	clean := filepath.Clean(rel)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("路径不允许超出实例目录")
	}
	full := filepath.Join(root, clean)
	// 逐段校验符号链接，任何一段指向 root 之外即拒绝。
	cur := root
	segments := strings.Split(clean, string(filepath.Separator))
	for _, seg := range segments {
		if seg == "." || seg == "" {
			continue
		}
		cur = filepath.Join(cur, seg)
		if info, err := os.Lstat(cur); err == nil && info.Mode()&os.ModeSymlink != 0 {
			target, err := filepath.EvalSymlinks(cur)
			if err != nil {
				return "", errors.New("路径解析失败")
			}
			if target != cur && !strings.HasPrefix(target+string(filepath.Separator), root+string(filepath.Separator)) && target != root {
				return "", errors.New("路径不允许超出实例目录")
			}
		}
	}
	if mustExist {
		if _, err := os.Lstat(full); err != nil {
			if errors.Is(err, fs.ErrPermission) {
				return "", PermissionHint(err, rel)
			}
			return "", os.ErrNotExist
		}
	}
	return full, nil
}

type Entry struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	IsDir   bool   `json:"isDir"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	ModTime int64  `json:"modTime"`
}

func List(root, rel string) (entries []Entry, err error) {
	defer func() { err = PermissionHint(err, rel) }()
	full, err := Resolve(root, rel, true)
	if err != nil {
		return nil, err
	}
	items, err := os.ReadDir(full)
	if err != nil {
		return nil, err
	}
	entries = make([]Entry, 0, len(items))
	for _, it := range items {
		info, err := it.Info()
		if err != nil {
			continue
		}
		mode := "file"
		if it.IsDir() {
			mode = "dir"
		}
		if info.Mode()&os.ModeSymlink != 0 {
			mode = "symlink"
		}
		entries = append(entries, Entry{Name: it.Name(), Path: filepath.ToSlash(filepath.Join(rel, it.Name())), IsDir: it.IsDir(), Size: info.Size(), Mode: mode, ModTime: info.ModTime().UnixMilli()})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir
		}
		return entries[i].Name < entries[j].Name
	})
	return entries, nil
}

// ListPage 目录分页列表：目录优先排序后按 page/size 切片，keyword 对名称做
// 不区分大小写子串过滤。size<=0 表示不分页（兼容旧面板整目录返回）。
// 返回 (当页条目, 过滤后总数)。
//
// 性能关键：过滤/排序/切片只依赖 dirent（ReadDir 自带，零 stat），
// Info()（一次 stat）只对最终返回的条目调用——Windows Docker Desktop
// 的绑定挂载上逐文件 stat 极慢，万级目录全量 stat 是 file.list 超时的
// 直接原因。分页 50 条 = 50 次 stat。
func ListPage(root, rel, keyword string, page, size int64) (entries []Entry, total int, err error) {
	defer func() { err = PermissionHint(err, rel) }()
	full, err := Resolve(root, rel, true)
	if err != nil {
		return nil, 0, err
	}
	items, err := os.ReadDir(full)
	if err != nil {
		return nil, 0, err
	}
	type scan struct {
		name  string
		isDir bool
		mode  string
		entry os.DirEntry
	}
	scanned := make([]scan, 0, len(items))
	kw := strings.ToLower(strings.TrimSpace(keyword))
	for _, it := range items {
		if kw != "" && !strings.Contains(strings.ToLower(it.Name()), kw) {
			continue
		}
		mode := "file"
		if it.IsDir() {
			mode = "dir"
		}
		if it.Type()&os.ModeSymlink != 0 {
			mode = "symlink"
		}
		scanned = append(scanned, scan{name: it.Name(), isDir: it.IsDir(), mode: mode, entry: it})
	}
	sort.Slice(scanned, func(i, j int) bool {
		if scanned[i].isDir != scanned[j].isDir {
			return scanned[i].isDir
		}
		return scanned[i].name < scanned[j].name
	})
	total = len(scanned)
	if size > 0 {
		start := (page - 1) * size
		if start < 0 {
			start = 0
		}
		if start >= int64(total) {
			scanned = nil
		} else {
			end := start + size
			if end > int64(total) {
				end = int64(total)
			}
			scanned = scanned[start:end]
		}
	}
	entries = make([]Entry, 0, len(scanned))
	for _, item := range scanned {
		var sizeBytes int64
		var mod int64
		if info, infoErr := item.entry.Info(); infoErr == nil {
			sizeBytes = info.Size()
			mod = info.ModTime().UnixMilli()
		}
		entries = append(entries, Entry{Name: item.name, Path: filepath.ToSlash(filepath.Join(rel, item.name)), IsDir: item.isDir, Size: sizeBytes, Mode: item.mode, ModTime: mod})
	}
	return entries, total, nil
}

func Read(root, rel string) (out map[string]any, err error) {
	defer func() { err = PermissionHint(err, rel) }()
	full, err := Resolve(root, rel, true)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(full)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, errors.New("目标是目录")
	}
	if info.Size() > MaxDataBytes {
		return nil, fmt.Errorf("文件超过 %d 字币，请使用分块通道", MaxDataBytes)
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return nil, err
	}
	return map[string]any{"content": base64.StdEncoding.EncodeToString(b), "encoding": "base64", "size": len(b)}, nil
}

func Write(root, rel, content, encoding string) (err error) {
	defer func() { err = PermissionHint(err, rel) }()
	full, err := Resolve(root, rel, false)
	if err != nil {
		return err
	}
	var b []byte
	switch encoding {
	case "", "base64":
		b, err = base64.StdEncoding.DecodeString(content)
		if err != nil {
			return errors.New("base64 内容无效")
		}
	case "utf8", "text":
		b = []byte(content)
	default:
		return errors.New("不支持的编码")
	}
	if len(b) > MaxDataBytes {
		return fmt.Errorf("单次写入超过 %d 字节", MaxDataBytes)
	}
	return atomicWrite(full, b, 0644)
}

func atomicWrite(path string, b []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".panel-file-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(b)
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, path)
}

func Mkdir(root, rel string) (err error) {
	defer func() { err = PermissionHint(err, rel) }()
	full, err := Resolve(root, rel, false)
	if err != nil {
		return err
	}
	return os.MkdirAll(full, 0755)
}

func Rename(root, from, to string) (err error) {
	defer func() { err = PermissionHint(err, from) }()
	src, err := Resolve(root, from, true)
	if err != nil {
		return err
	}
	dst, err := Resolve(root, to, false)
	if err != nil {
		return err
	}
	if src == filepath.Join(root, "") || dst == root {
		return errors.New("不允许移动实例根目录")
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	return os.Rename(src, dst)
}

func Delete(root, rel string) (err error) {
	defer func() { err = PermissionHint(err, rel) }()
	full, err := Resolve(root, rel, true)
	if err != nil {
		return err
	}
	if full == root {
		return errors.New("不允许删除实例根目录")
	}
	return os.RemoveAll(full)
}

// ---- 分块上传/下载会话 ----

type uploadSession struct {
	instanceID   string
	path         string
	expectSize   int64
	expectSha256 string
	tmp          *os.File
	written      int64
	deadline     time.Time
}

type Manager struct {
	mu      sync.Mutex
	uploads map[string]*uploadSession
	rootOf  func(instanceID string) (string, error)
}

func NewManager(rootOf func(string) (string, error)) *Manager {
	m := &Manager{uploads: map[string]*uploadSession{}, rootOf: rootOf}
	go m.gcLoop()
	return m
}

func (m *Manager) gcLoop() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		m.gc(time.Now())
	}
}

// AbortInstance 中止某实例的全部进行中分块上传（实例删除/回收迁移前释放
// Windows 句柄）。返回成功中止的数量；会话已被 GC 的情况不计入也不报错。
func (m *Manager) AbortInstance(instanceID string) int {
	m.mu.Lock()
	ids := []string{}
	for id, s := range m.uploads {
		if s.instanceID == instanceID {
			ids = append(ids, id)
		}
	}
	m.mu.Unlock()
	aborted := 0
	for _, id := range ids {
		if err := m.Abort(id); err == nil {
			aborted++
		}
	}
	return aborted
}

func (m *Manager) gc(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.uploads {
		if now.After(s.deadline) {
			_ = s.tmp.Close()
			_ = os.Remove(s.tmp.Name())
			delete(m.uploads, id)
		}
	}
}

func (m *Manager) Begin(instanceID, rel string, size int64, sha256hex string) (id string, err error) {
	defer func() { err = PermissionHint(err, rel) }()
	root, err := m.rootOf(instanceID)
	if err != nil {
		return "", err
	}
	if _, err = Resolve(root, rel, false); err != nil {
		return "", err
	}
	if size < 0 || size > 8<<30 {
		return "", errors.New("上传大小无效")
	}
	if len(sha256hex) != 64 {
		return "", errors.New("sha256 必须为64位十六进制")
	}
	tmp, err := os.CreateTemp(filepath.Join(root), ".panel-upload-*")
	if err != nil {
		return "", err
	}
	id = fmt.Sprintf("up-%d-%s", time.Now().UnixNano(), filepath.Base(tmp.Name())[13:])
	m.mu.Lock()
	defer m.mu.Unlock()
	m.uploads[id] = &uploadSession{instanceID: instanceID, path: rel, expectSize: size, expectSha256: strings.ToLower(sha256hex), tmp: tmp, deadline: time.Now().Add(10 * time.Minute)}
	return id, nil
}

func (m *Manager) Chunk(uploadID string, offset int64, contentB64 string) error {
	m.mu.Lock()
	s, ok := m.uploads[uploadID]
	if ok {
		s.deadline = time.Now().Add(10 * time.Minute)
	}
	m.mu.Unlock()
	if !ok {
		return errors.New("上传会话不存在或已过期")
	}
	b, err := base64.StdEncoding.DecodeString(contentB64)
	if err != nil {
		return errors.New("base64 内容无效")
	}
	if len(b) > MaxDataBytes {
		return fmt.Errorf("分块超过 %d 字节", MaxDataBytes)
	}
	if offset != s.written {
		return errors.New("分块偏移不连续")
	}
	n, err := s.tmp.WriteAt(b, offset)
	if err != nil {
		return err
	}
	s.written += int64(n)
	return nil
}

func (m *Manager) Commit(uploadID string) (out map[string]any, err error) {
	m.mu.Lock()
	s, ok := m.uploads[uploadID]
	delete(m.uploads, uploadID)
	m.mu.Unlock()
	if !ok {
		return nil, errors.New("上传会话不存在或已过期")
	}
	defer func() { err = PermissionHint(err, s.path) }()
	fail := func(err error) (map[string]any, error) {
		_ = s.tmp.Close()
		_ = os.Remove(s.tmp.Name())
		return nil, err
	}
	if _, err := s.tmp.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	h := sha256.New()
	size, err := io.Copy(h, s.tmp)
	if err != nil {
		return fail(err)
	}
	if size != s.expectSize {
		return fail(fmt.Errorf("大小校验失败：期望 %d 实际 %d", s.expectSize, size))
	}
	if hex.EncodeToString(h.Sum(nil)) != s.expectSha256 {
		return fail(errors.New("sha256 校验失败"))
	}
	root, err := m.rootOf(s.instanceID)
	if err != nil {
		return fail(err)
	}
	target, err := Resolve(root, s.path, false)
	if err != nil {
		return fail(err)
	}
	if err := s.tmp.Close(); err != nil {
		return fail(err)
	}
	if err := os.Chmod(s.tmp.Name(), 0644); err != nil {
		_ = os.Remove(s.tmp.Name())
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		_ = os.Remove(s.tmp.Name())
		return nil, err
	}
	if err := os.Rename(s.tmp.Name(), target); err != nil {
		_ = os.Remove(s.tmp.Name())
		return nil, err
	}
	return map[string]any{"size": size}, nil
}

func (m *Manager) Abort(uploadID string) error {
	m.mu.Lock()
	s, ok := m.uploads[uploadID]
	delete(m.uploads, uploadID)
	m.mu.Unlock()
	if !ok {
		return nil
	}
	_ = s.tmp.Close()
	_ = os.Remove(s.tmp.Name())
	return nil
}

func DownloadChunk(root, rel string, offset, length int64) (out map[string]any, err error) {
	defer func() { err = PermissionHint(err, rel) }()
	full, err := Resolve(root, rel, true)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(full)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, errors.New("目标是目录")
	}
	if offset < 0 || offset > info.Size() {
		return nil, errors.New("读取偏移无效")
	}
	if length <= 0 || length > MaxDataBytes {
		length = MaxDataBytes
	}
	f, err := os.Open(full)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, length)
	n, err := f.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return map[string]any{"content": base64.StdEncoding.EncodeToString(buf[:n]), "size": n, "eof": offset+int64(n) >= info.Size()}, nil
}

// ZipPath 将实例内相对路径打包为实例内 zip（dest 亦为相对路径）。
func ZipPath(root, rel, dest string) (string, error) {
	return ZipPaths(root, []string{rel}, dest)
}

// ZipPaths 将多个实例内相对路径打包为同一个实例内 zip（dest 亦为相对路径，自动补 .zip）。
// 用于文件管理批量压缩：目录递归打包，符号链接跳过，条目路径以实例根为基准。
func ZipPaths(root string, rels []string, dest string) (name string, err error) {
	defer func() { err = PermissionHint(err, strings.Join(rels, "、")) }()
	if len(rels) == 0 {
		return "", errors.New("没有可压缩的路径")
	}
	destFull, err := Resolve(root, dest, false)
	if err != nil {
		return "", err
	}
	if !strings.HasSuffix(destFull, ".zip") {
		destFull += ".zip"
	}
	f, err := os.Create(destFull)
	if err != nil {
		return "", err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	add := func(zw *zip.Writer, p string, info os.FileInfo) error {
		relPath, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		if info.IsDir() {
			_, err := zw.Create(filepath.ToSlash(relPath) + "/")
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		w, err := zw.Create(filepath.ToSlash(relPath))
		if err != nil {
			return err
		}
		src, err := os.Open(p)
		if err != nil {
			return err
		}
		defer src.Close()
		_, err = io.Copy(w, src)
		return err
	}
	for _, rel := range rels {
		srcFull, err := Resolve(root, rel, true)
		if err != nil {
			return "", err
		}
		info, err := os.Lstat(srcFull)
		if err != nil {
			return "", err
		}
		if info.IsDir() {
			err = filepath.Walk(srcFull, func(p string, fi os.FileInfo, werr error) error {
				if werr != nil {
					return werr
				}
				return add(zw, p, fi)
			})
		} else {
			err = add(zw, srcFull, info)
		}
		if err != nil {
			_ = zw.Close()
			_ = os.Remove(destFull)
			return "", err
		}
	}
	if err := zw.Close(); err != nil {
		_ = os.Remove(destFull)
		return "", err
	}
	return filepath.Base(destFull), nil
}

// UnzipPath 解压实例内 zip 到目标目录（默认 zip 同名目录或 ""=根），拒绝 zip-slip。
func UnzipPath(root, zipRel, destRel string) (out map[string]int, err error) {
	defer func() { err = PermissionHint(err, zipRel) }()
	zipFull, err := Resolve(root, zipRel, true)
	if err != nil {
		return nil, err
	}
	destFull, err := Resolve(root, destRel, false)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(destFull, 0755); err != nil {
		return nil, err
	}
	zr, err := zip.OpenReader(zipFull)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	files := 0
	for _, zf := range zr.File {
		name := filepath.Clean(zf.Name)
		if name == "." || name == ".." || filepath.IsAbs(name) || strings.HasPrefix(name, "..") {
			return nil, errors.New("zip 条目路径非法")
		}
		target := filepath.Join(destFull, name)
		if !strings.HasPrefix(target, destFull+string(os.PathSeparator)) && target != destFull {
			return nil, errors.New("zip 条目越界")
		}
		if zf.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0755); err != nil {
				return nil, err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return nil, err
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, err
		}
		dst, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			rc.Close()
			return nil, err
		}
		_, err = io.Copy(dst, rc)
		rc.Close()
		dst.Close()
		if err != nil {
			return nil, err
		}
		files++
	}
	return map[string]int{"files": files}, nil
}

// ---- 实例级 zip 备份 ----

const (
	maxBackupBytes = 4 << 30
	maxBackupFiles = 200000
)

func CreateBackup(root, backupDir, instanceID string) (target string, err error) {
	defer func() { err = PermissionHint(err, instanceID) }()
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return "", err
	}
	target = filepath.Join(backupDir, instanceID+"-"+time.Now().UTC().Format("20060102T150405Z")+".zip")
	f, err := os.Create(target)
	if err != nil {
		return "", err
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	files := 0
	total := int64(0)
	err = filepath.Walk(root, func(p string, info os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		} // 备份跳过符号链接，恢复时自然缺失
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		if rel == "." {
			return nil
		}
		if strings.HasPrefix(rel, ".panel-") {
			return nil
		}
		files++
		if files > maxBackupFiles {
			return errors.New("备份文件数超限")
		}
		if info.IsDir() {
			_, err := zw.Create(filepath.ToSlash(rel) + "/")
			return err
		}
		total += info.Size()
		if total > maxBackupBytes {
			return errors.New("备份总大小超限")
		}
		w, err := zw.Create(filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		src, err := os.Open(p)
		if err != nil {
			return err
		}
		defer src.Close()
		_, err = io.Copy(w, src)
		return err
	})
	if cerr := zw.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(target)
		return "", err
	}
	return target, nil
}

func ListBackups(backupDir string) ([]map[string]any, error) {
	items, err := listBackupItems(backupDir, "")
	if err != nil {
		return nil, err
	}
	return items, nil
}

// ListInstanceBackups 只返回属于指定实例的备份（文件名前缀 {instanceId}-）。
func ListInstanceBackups(backupDir, instanceID string) ([]map[string]any, error) {
	return listBackupItems(backupDir, instanceID+"-")
}

func listBackupItems(backupDir, prefix string) ([]map[string]any, error) {
	items, err := os.ReadDir(backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []map[string]any{}, nil
		}
		return nil, err
	}
	out := []map[string]any{}
	for _, it := range items {
		if it.IsDir() || !strings.HasSuffix(it.Name(), ".zip") {
			continue
		}
		if prefix != "" && !strings.HasPrefix(it.Name(), prefix) {
			continue
		}
		info, err := it.Info()
		if err != nil {
			continue
		}
		out = append(out, map[string]any{"file": it.Name(), "size": info.Size(), "at": info.ModTime().UnixMilli()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["at"].(int64) > out[j]["at"].(int64) })
	return out, nil
}

// PruneBackups 按保留策略清理单个实例的备份：
// keepCount>0 时仅保留最新 N 份；keepDays>0 时删除超过 N 天的旧份。返回删除数量。
// 恢复用临时档（-restore- 前缀）不在策略内，由恢复流程自行清理。
func PruneBackups(backupDir, instanceID string, keepCount, keepDays int) (int, error) {
	if keepCount <= 0 && keepDays <= 0 {
		return 0, nil
	}
	items, err := ListInstanceBackups(backupDir, instanceID)
	if err != nil {
		return 0, err
	}
	cutoff := int64(0)
	if keepDays > 0 {
		cutoff = time.Now().Add(-time.Duration(keepDays) * 24 * time.Hour).UnixMilli()
	}
	removed := 0
	for i, item := range items {
		at, _ := item["at"].(int64)
		name, _ := item["file"].(string)
		if name == "" || strings.Contains(name, "-restore-") {
			continue
		}
		expired := cutoff > 0 && at > 0 && at < cutoff
		overCount := keepCount > 0 && i >= keepCount
		if !expired && !overCount {
			continue
		}
		if err := os.Remove(filepath.Join(backupDir, name)); err == nil {
			removed++
		}
	}
	return removed, nil
}

// RestoreBackup 拒绝 zip-slip：所有条目必须落在 root 内，且恢复仅在实例停止时调用。
func RestoreBackup(backupDir, name, root string) (err error) {
	defer func() { err = PermissionHint(err, "") }()
	if filepath.Base(name) != name || !strings.HasSuffix(name, ".zip") {
		return errors.New("备份文件名无效")
	}
	fullPath := filepath.Join(backupDir, name)
	info, err := os.Stat(fullPath)
	if err != nil {
		return err
	}
	f, err := os.Open(fullPath)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := zip.NewReader(f, info.Size())
	if err != nil {
		return err
	}
	files := 0
	total := int64(0)
	for _, zf := range zr.File {
		clean := filepath.Clean(zf.Name)
		if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
			return errors.New("备份包含非法路径")
		}
		files++
		if files > maxBackupFiles {
			return errors.New("备份文件数超限")
		}
		if zf.UncompressedSize64 > maxBackupBytes {
			return errors.New("备份条目过大")
		}
		total += int64(zf.UncompressedSize64)
		if total > maxBackupBytes {
			return errors.New("备份总大小超限")
		}
		target := filepath.Join(root, clean)
		if strings.HasSuffix(zf.Name, "/") {
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		tmp, err := os.CreateTemp(filepath.Dir(target), ".panel-restore-*")
		if err != nil {
			rc.Close()
			return err
		}
		n, cerr := io.Copy(tmp, rc)
		rc.Close()
		tmp.Close()
		if cerr != nil {
			_ = os.Remove(tmp.Name())
			return cerr
		}
		if n != int64(zf.UncompressedSize64) {
			_ = os.Remove(tmp.Name())
			return errors.New("备份条目大小不一致")
		}
		if err := os.Chmod(tmp.Name(), 0644); err != nil {
			_ = os.Remove(tmp.Name())
			return err
		}
		if err := os.Rename(tmp.Name(), target); err != nil {
			_ = os.Remove(tmp.Name())
			return err
		}
	}
	return nil
}

func DeleteBackup(backupDir, name string) error {
	if filepath.Base(name) != name || !strings.HasSuffix(name, ".zip") {
		return errors.New("备份文件名无效")
	}
	err := os.Remove(filepath.Join(backupDir, name))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// CheckPorts 本地双探测：TCP 尝试监听，UDP 尝试绑定。
func CheckPorts(checks []struct {
	Port  int
	Proto string
}) []map[string]any {
	results := make([]map[string]any, 0, len(checks))
	for _, c := range checks {
		free := false
		if c.Port < 1 || c.Port > 65535 || (c.Proto != "tcp" && c.Proto != "udp") {
			results = append(results, map[string]any{"port": c.Port, "proto": c.Proto, "free": false, "reason": "参数无效"})
			continue
		}
		if c.Proto == "tcp" {
			ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", c.Port))
			if err == nil {
				free = true
				_ = ln.Close()
			}
		} else {
			pc, err := net.ListenPacket("udp", fmt.Sprintf("0.0.0.0:%d", c.Port))
			if err == nil {
				free = true
				_ = pc.Close()
			}
		}
		results = append(results, map[string]any{"port": c.Port, "proto": c.Proto, "free": free})
	}
	return results
}
