package shellterm

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

// waitForOutput 从通道读取直到匹配文本或超时。
func waitForOutput(t *testing.T, ch <-chan string, needle string, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case <-deadline:
			t.Fatalf("%ds 内未见到 %q", int(timeout.Seconds()), needle)
		case text, ok := <-ch:
			if ok && strings.Contains(text, needle) {
				return
			}
		}
	}
}

// TestReopenReplacesExistingTerminal：同 ID 重开必须幂等——旧会话被关闭，
// 新会话可用。修复前返回「终端已存在」，面板「重连」永远失败。
func TestReopenReplacesExistingTerminal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("linux 专项验证")
	}
	m := NewManager()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := m.Open(ctx, "term-reopen", ""); err != nil {
		t.Fatalf("first open: %v", err)
	}
	oldCh, ok := m.OutputChan("term-reopen")
	if !ok {
		t.Fatal("old output chan missing")
	}
	term2, err := m.Open(ctx, "term-reopen", "")
	if err != nil {
		t.Fatalf("同 ID 重开必须成功而非「终端已存在」: %v", err)
	}
	if term2 == nil {
		t.Fatal("reopened terminal is nil")
	}
	// 旧终端的输出通道必须关闭（旧会话终止信号）
	deadline := time.After(5 * time.Second)
closed:
	for {
		select {
		case <-deadline:
			t.Fatal("旧终端 outCh 未关闭")
		case _, ok := <-oldCh:
			if !ok {
				break closed
			}
		}
	}
	// 新终端必须能正常输入输出
	ch, ok := m.OutputChan("term-reopen")
	if !ok {
		t.Fatal("new output chan missing")
	}
	if err := m.Input("term-reopen", "echo REOPEN_OK\n"); err != nil {
		t.Fatalf("input on reopened terminal: %v", err)
	}
	waitForOutput(t, ch, "REOPEN_OK", 5*time.Second)
}

// TestExitRemovesEntryPromptly：shell 退出（如输入 exit）后登记必须立即回收，
// 修复前条目残留至空闲超时（30 分钟），期间以「终端已存在」占坑并泄漏僵尸进程。
func TestExitRemovesEntryPromptly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("linux 专项验证")
	}
	m := NewManager()
	if _, err := m.Open(context.Background(), "term-exit", ""); err != nil {
		t.Fatalf("open: %v", err)
	}
	ch, ok := m.OutputChan("term-exit")
	if !ok {
		t.Fatal("output chan missing")
	}
	if err := m.Input("term-exit", "exit\n"); err != nil {
		t.Fatalf("input exit: %v", err)
	}
	// 输出通道关闭 = 聚合泵结束；登记随即被 watcher 清理。
	deadline := time.After(5 * time.Second)
closed:
	for {
		select {
		case <-deadline:
			t.Fatal("退出后 outCh 未关闭")
		case _, ok := <-ch:
			if !ok {
				break closed
			}
		}
	}
	removed := false
	deadline = time.After(5 * time.Second)
	for !removed {
		select {
		case <-deadline:
			t.Fatal("退出后登记未在 5s 内回收（僵尸条目占坑）")
		case <-time.After(20 * time.Millisecond):
			m.mu.Lock()
			_, present := m.terminals["term-exit"]
			m.mu.Unlock()
			removed = !present
		}
	}
	// 回收后同 ID 可再次打开（maxConcurrent 名额不被泄漏占用）
	if _, err := m.Open(context.Background(), "term-exit", ""); err != nil {
		t.Fatalf("回收后重开必须成功: %v", err)
	}
}
