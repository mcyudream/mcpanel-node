// Package shellterm 提供节点机本身的持久终端会话（对标 MCSM 节点终端）。
//
// 安全模型：无 PTY（跨平台管道模式），适合命令交互但不含全屏应用渲染；
// 并发终端数有上限；输出环形缓冲有界；空闲超时自动回收。
package shellterm

import (
 "context"
 "fmt"
 "io"
 "os"
 "os/exec"
 "runtime"
 "sync"
 "time"
)

const (
 maxOutputChunk  = 16 * 1024
 maxConcurrent   = 3
 idleTimeout     = 30 * time.Minute
 readChunk       = 4096
)

// Terminal 一个活跃的节点机 shell 会话。
type Terminal struct {
 ID        string
 outputCh  <-chan string
 cancel    context.CancelFunc
 cmd       *exec.Cmd
 mu        sync.Mutex
 stdin     io.WriteCloser
 closed    bool
 StartedAt time.Time
}

// Manager 管理节点机 shell 会话。
type Manager struct {
 mu        sync.Mutex
 terminals map[string]*Terminal
 seq       int
}

func NewManager() *Manager {
 return &Manager{terminals: map[string]*Terminal{}}
}

// Open 启动一个持久 shell（Unix: bash -i，无 bash 时回落 sh；Windows: cmd）。
// shell 为空时按平台默认。同 ID 已有会话时先关闭旧会话再开（重连幂等）。
func (m *Manager) Open(ctx context.Context, id, shell string) (*Terminal, error) {
	m.mu.Lock()
	old, dup := m.terminals[id]
	if dup {
		delete(m.terminals, id)
	}
	free := !dup && len(m.terminals) < maxConcurrent
	m.mu.Unlock()
	if dup {
		old.kill()
	} else if !free {
		return nil, fmt.Errorf("终端并发数已达上限（%d）", maxConcurrent)
	}

	if shell == "" {
		if runtime.GOOS == "windows" {
			shell = "cmd"
		} else if _, err := exec.LookPath("bash"); err == nil {
			shell = "bash"
		} else {
			// alpine/busybox 等精简节点环境没有 bash：回落 sh（ash），
			// 否则节点终端在容器化节点上必然 internal.error。
			shell = "sh"
		}
	}
	args := []string{}
	if shell == "bash" {
		args = []string{"-i"}
	}
	cmd := exec.Command(shell, args...)
	cmd.Env = append(os.Environ(), "TERM=dumb")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	setProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	outCh := make(chan string, 256)
	tctx, cancel := context.WithCancel(ctx)
	term := &Terminal{ID: id, outputCh: outCh, cancel: cancel, stdin: stdin, cmd: cmd, StartedAt: time.Now()}

	// 读/聚合分离：阻塞 Read 必须放在专职 goroutine，否则聚合泵的
	// select 会被 default 分支的阻塞读饿死，定时 flush 永不触发。
	rawCh := make(chan []byte, 64)
	var wg sync.WaitGroup
	read := func(r io.Reader) {
		buf := make([]byte, readChunk)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				b := make([]byte, n)
				copy(b, buf[:n])
				select {
				case rawCh <- b:
				case <-tctx.Done():
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	wg.Add(2)
	go func() { defer wg.Done(); read(stdout) }()
	go func() { defer wg.Done(); read(stderr) }()
	go func() {
		wg.Wait()
		close(rawCh)
		_ = stdin.Close()
	}()

	go func() {
		defer close(outCh)
		var agg []byte
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		flush := func() {
			if len(agg) == 0 {
				return
			}
			text := string(agg)
			agg = agg[:0]
			if len(text) > maxOutputChunk {
				text = text[:maxOutputChunk]
			}
			select {
			case outCh <- text:
			case <-tctx.Done():
			}
		}
		for {
			select {
			case b, ok := <-rawCh:
				if !ok {
					flush()
					return
				}
				agg = append(agg, b...)
				if len(agg) >= maxOutputChunk {
					flush()
				}
			case <-ticker.C:
				flush()
			case <-tctx.Done():
				flush()
				return
			}
		}
	}()

	// 唯一 Wait 所有者：进程自行退出（如输入 exit）或被杀后立刻回收登记，
	// 否则条目残留会以「终端已存在」占坑直至空闲超时，并泄漏僵尸进程。
	waitDone := make(chan struct{})
	go func() {
		_ = cmd.Wait() // Wait 随进程退出关闭管道，读端得到 EOF
		close(waitDone)
	}()

	// 空闲回收：写端关闭或超时结束进程。
	go func() {
		timer := time.AfterFunc(idleTimeout, func() { m.Close(id) })
		defer timer.Stop()
		select {
		case <-tctx.Done():
			timer.Stop()
			_ = cmd.Process.Kill()
		case <-waitDone:
			timer.Stop()
		}
		<-waitDone
		// 会话级取消（如控制连接被替换）也要移除登记，否则条目泄漏
		// 会永久占用并发名额；仅当仍是本终端时才删。
		m.mu.Lock()
		if cur, ok := m.terminals[id]; ok && cur == term {
			delete(m.terminals, id)
		}
		m.mu.Unlock()
	}()

	m.mu.Lock()
	m.terminals[id] = term
	m.mu.Unlock()
	return term, nil
}

// Input 向终端 stdin 写入（调用方自带换行）。
func (m *Manager) Input(id string, data string) error {
 m.mu.Lock()
 term, ok := m.terminals[id]
 m.mu.Unlock()
 if !ok {
  return fmt.Errorf("终端不存在：%s", id)
 }
 term.mu.Lock()
 defer term.mu.Unlock()
 if term.closed {
  return fmt.Errorf("终端已关闭")
 }
 _, err := io.WriteString(term.stdin, data)
 return err
}

// OutputChan 返回输出通道；通道关闭表示终端结束。
func (m *Manager) OutputChan(id string) (<-chan string, bool) {
 m.mu.Lock()
 defer m.mu.Unlock()
 t, ok := m.terminals[id]
 if !ok {
  return nil, false
 }
 return t.outputCh, true
}

// Close 关闭终端（杀进程并移除登记）；进程回收由唯一 Wait 所有者完成。
func (m *Manager) Close(id string) bool {
	m.mu.Lock()
	term, ok := m.terminals[id]
	delete(m.terminals, id)
	m.mu.Unlock()
	if !ok {
		return false
	}
	term.kill()
	return true
}

// kill 终止终端进程并触发回收（Wait 由 watcher goroutine 唯一持有）。
func (t *Terminal) kill() {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	t.cancel()
	if t.cmd.Process != nil {
		_ = t.cmd.Process.Kill()
	}
}

// CloseAll 关闭全部（节点关闭时调用）。
func (m *Manager) CloseAll() {
 m.mu.Lock()
 ids := make([]string, 0, len(m.terminals))
 for id := range m.terminals {
  ids = append(ids, id)
 }
 m.mu.Unlock()
 for _, id := range ids {
  m.Close(id)
 }
}
