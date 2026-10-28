// Package ftpserv 提供实例级临时 SFTP 服务（协议 §9 ftp.open/close）。
//
// 安全模型：每次 ftp.open 生成随机账号/密码、根目录钉死在实例数据根内
// （经 fileutil.Resolve 防逃逸）、TTL 到期自动关闭；仅 SFTP 子系统，无 shell。
package ftpserv

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/yudream/mcpanel-node/internal/fileutil"
	"io"
	"net"
	"os"
	virtualpath "path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Opened 描述一次开启结果（面板据此展示连接信息并落审计）。
type Opened struct {
	Port      int    `json:"port"`
	User      string `json:"user"`
	Password  string `json:"password"`
	ExpiresAt int64  `json:"expiresAt"`
}

type session struct {
	instanceID string
	root       string
	user       string
	password   string
	port       int
	listener   net.Listener
	expiresAt  time.Time
	cancel     context.CancelFunc
}

// Manager 管理本节点全部 SFTP 会话；同一实例同时至多一个会话。
type Manager struct {
	mu       sync.Mutex
	sessions map[string]*session
	hostKeys []ssh.Signer
}

func NewManager() (*Manager, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	edSigner, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}
	// 双主机密钥（Ed25519 + RSA）：现代客户端优先 Ed25519；只支持 RSA 的旧
	// 客户端（如部分面板网关运行环境）也能完成协商。
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	rsaSigner, err := ssh.NewSignerFromKey(rsaPriv)
	if err != nil {
		return nil, err
	}
	return &Manager{sessions: map[string]*session{}, hostKeys: []ssh.Signer{edSigner, rsaSigner}}, nil
}

// Open 在 port（0=随机空闲）上启动实例 SFTP；到期自动关闭。
func (m *Manager) Open(instanceID, root string, port, ttlMinutes int) (Opened, error) {
	m.mu.Lock()
	if old, ok := m.sessions[instanceID]; ok {
		m.mu.Unlock()
		old.cancel()
		_ = old.listener.Close()
	} else {
		m.mu.Unlock()
	}
	user := "mcpanel"
	password := newPassword(24)
	if ttlMinutes < 1 {
		ttlMinutes = 120
	}
	if ttlMinutes > 120 {
		ttlMinutes = 120
	}
	expiresAt := time.Now().Add(time.Duration(ttlMinutes) * time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	addr := fmt.Sprintf("0.0.0.0:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		cancel()
		return Opened{}, fmt.Errorf("监听端口 %d 失败：%w", port, err)
	}
	sess := &session{instanceID: instanceID, root: root, user: user, password: password,
		port: ln.Addr().(*net.TCPAddr).Port, listener: ln, expiresAt: expiresAt, cancel: cancel}
	m.mu.Lock()
	m.sessions[instanceID] = sess
	m.mu.Unlock()

	go func() {
		serveDone := make(chan struct{})
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					close(serveDone)
					return
				}
				go m.handleConn(ctx, conn, sess)
			}
		}()
		timer := time.AfterFunc(time.Until(expiresAt), func() { cancel(); _ = ln.Close() })
		select {
		case <-ctx.Done():
		case <-serveDone:
		}
		timer.Stop()
	}()
	return Opened{Port: sess.port, User: user, Password: password, ExpiresAt: expiresAt.UnixMilli()}, nil
}

// Close 手动关闭实例的 SFTP 会话；不存在返回 false。
func (m *Manager) Close(instanceID string) bool {
	m.mu.Lock()
	sess, ok := m.sessions[instanceID]
	delete(m.sessions, instanceID)
	m.mu.Unlock()
	if !ok {
		return false
	}
	sess.cancel()
	_ = sess.listener.Close()
	return true
}

func (m *Manager) handleConn(ctx context.Context, conn net.Conn, sess *session) {
	defer conn.Close()
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close() // Revoke established sessions as well as new logins.
		case <-finished:
		}
	}()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if meta.User() == sess.user && subtleEqual(string(password), sess.password) {
				return nil, nil
			}
			return nil, fmt.Errorf("认证失败")
		},
	}
	for _, k := range m.hostKeys {
		cfg.AddHostKey(k)
	}
	sshConn, channels, requests, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(requests)
	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "SFTP only")
			continue
		}
		channel, reqs, err := newChannel.Accept()
		if err != nil {
			return
		}
		go func() {
			for req := range reqs {
				// 标准 SFTP 客户端（面板网关、OpenSSH -s sftp 等）在通道上先发
				// subsystem: sftp 请求，批准后客户端才开始发 SFTP 帧；SFTP 服务
				// 已在下方 Serve() 直接跑，无需额外处理。其余请求一律拒绝。
				if req.Type == "subsystem" {
					_ = req.Reply(true, nil)
					continue
				}
				_ = req.Reply(false, nil)
			}
		}()
		select {
		case <-ctx.Done():
			channel.Close()
			return
		default:
		}
		// 必须 NewRequestServer（handlers 模式）：sftp.NewServer 是经典 OS 文件系统
		// 后端，直接对真实文件系统操作，rootedChannel 的 handlers 与 ResolveSafe
		// 根本不会被调用（曾因此导致客户端可见宿主盘根，越权）。
		rc := &rootedChannel{channel: channel, root: sess.root}
		server := sftp.NewRequestServer(rc, sftp.Handlers{
			FileGet:  rc,
			FilePut:  rc,
			FileCmd:  rc,
			FileList: rc,
		})
		_ = server.Serve()
		_ = server.Close()
		channel.Close()
		return
	}
}

func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func newPassword(n int) string {
	const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// rootedChannel 把 SFTP 协议帧透传给 pkg/sftp 请求服务器。
type rootedChannel struct {
	channel ssh.Channel
	root    string
}

func (r *rootedChannel) Read(p []byte) (int, error)  { return r.channel.Read(p) }
func (r *rootedChannel) Write(p []byte) (int, error) { return r.channel.Write(p) }
func (r *rootedChannel) Close() error                { return r.channel.Close() }

// ---- pkg/sftp request-server handlers：全部经 Resolve 钉死在 root 内 ----

func (r *rootedChannel) Filecmd(request *sftp.Request) error {
	switch request.Method {
	case "Mkdir":
		full, err := ResolveSafe(r.root, request.Filepath)
		if err != nil {
			return err
		}
		return os.MkdirAll(full, 0755)
	case "Remove":
		full, err := ResolveSafe(r.root, request.Filepath)
		if err != nil {
			return err
		}
		return removeAll(full, r.root)
	case "Rename":
		src, err := ResolveSafe(r.root, request.Filepath)
		if err != nil {
			return err
		}
		dst, err := ResolveSafe(r.root, request.Target)
		if err != nil {
			return err
		}
		return os.Rename(src, dst)
	case "Setstat":
		return nil // 不支持 chmod/utimes，静默接受
	case "Rmdir":
		full, err := ResolveSafe(r.root, request.Filepath)
		if err != nil {
			return err
		}
		return os.Remove(full)
	}
	return sftp.ErrSSHFxOpUnsupported
}

func (r *rootedChannel) Filelist(request *sftp.Request) (sftp.ListerAt, error) {
	if request.Method != "List" && request.Method != "Stat" && request.Method != "Lstat" {
		return nil, sftp.ErrSshFxOpUnsupported
	}
	full, err := ResolveSafe(r.root, request.Filepath)
	if err != nil {
		return nil, err
	}
	fi, err := os.Lstat(full)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() || (request.Method == "Stat" || request.Method == "Lstat") {
		// Stat（或非目录）只返回目标自身；List 不夹带目录自身条目。
		return &listEntry{entries: []os.FileInfo{fi}}, nil
	}
	items, err := os.ReadDir(full)
	if err != nil {
		return nil, err
	}
	entries := make([]os.FileInfo, 0, len(items))
	for _, it := range items {
		if info, err := it.Info(); err == nil {
			entries = append(entries, info)
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return &listEntry{entries: entries}, nil
}

type listEntry struct {
	entries []os.FileInfo
	offset  int
}

func (l *listEntry) ListAt(ls []os.FileInfo, offset int64) (int, error) {
	l.offset = int(offset)
	n := 0
	for l.offset < len(l.entries) && n < len(ls) {
		ls[n] = l.entries[l.offset]
		l.offset++
		n++
	}
	if l.offset >= len(l.entries) && n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

func (r *rootedChannel) Fileread(request *sftp.Request) (io.ReaderAt, error) {
	if request.Method != "Get" {
		return nil, sftp.ErrSshFxOpUnsupported
	}
	full, err := ResolveSafe(r.root, request.Filepath)
	if err != nil {
		return nil, err
	}
	return os.Open(full)
}

func (r *rootedChannel) Filewrite(request *sftp.Request) (io.WriterAt, error) {
	if request.Method != "Put" {
		return nil, sftp.ErrSshFxOpUnsupported
	}
	full, err := ResolveSafe(r.root, request.Filepath)
	if err != nil {
		return nil, err
	}
	flags := os.O_WRONLY
	pflags := request.Pflags()
	if pflags.Read {
		flags = os.O_RDWR
	}
	if pflags.Creat {
		flags |= os.O_CREATE
	}
	if pflags.Trunc {
		flags |= os.O_TRUNC
	}
	if pflags.Excl {
		flags |= os.O_EXCL
	}
	if pflags.Append {
		flags |= os.O_APPEND
	}
	f, err := os.OpenFile(full, flags, 0644)
	if err != nil {
		return nil, err
	}
	return &closeWriter{File: f, appendMode: pflags.Append}, nil
}

func (r *rootedChannel) FilecmdSlurp(request *sftp.Request) error {
	return sftp.ErrSSHFxOpUnsupported
}

// RealPath 实现 RealPathFileLister：把客户端视角钉死在虚拟根 "/"（chroot
// 语义）。客户端 realpath(".") 后将直接落在实例数据目录，不会看到宿主路径。
func (r *rootedChannel) RealPath(value string) (string, error) {
	clean := virtualpath.Clean("/" + value)
	full, err := ResolveSafe(r.root, clean)
	if err != nil {
		return "", err
	}
	// Canonicalize existing links but return only the path within the virtual root.
	if actual, err := filepath.EvalSymlinks(full); err == nil {
		root, err := filepath.EvalSymlinks(r.root)
		if err != nil {
			return "", err
		}
		rel, err := filepath.Rel(root, actual)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("路径不允许超出实例目录")
		}
		return virtualpath.Clean("/" + filepath.ToSlash(rel)), nil
	}
	return clean, nil
}

type closeWriter struct {
	*os.File
	appendMode bool
}

func (w *closeWriter) WriteAt(p []byte, offset int64) (int, error) {
	if w.appendMode {
		return w.File.Write(p)
	}
	return w.File.WriteAt(p, offset)
}

// ResolveSafe 供包内使用的防逃逸解析（fileutil.Resolve 的薄封装，避免循环依赖）。
func ResolveSafe(root, rel string) (string, error) {
	if strings.ContainsAny(rel, "\\\x00") || strings.Contains(rel, ":") {
		return "", fmt.Errorf("路径含非法字符")
	}
	clean := virtualpath.Clean("/" + rel)
	return fileutil.Resolve(root, strings.TrimPrefix(clean, "/"), false)
}

func removeAll(full, root string) error {
	if full == root || full == filepath.Dir(full) && full == root {
		return fmt.Errorf("不允许删除根目录")
	}
	return os.RemoveAll(full)
}
