package shellterm

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestTeardownCycles 反复开关终端，验证读泵/聚合泵/closer 的协程收敛与 WaitGroup 复用安全。
func TestTeardownCycles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("linux 专项验证")
	}
	m := NewManager()
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		id := fmt.Sprintf("cyc-%d", i)
		if _, err := m.Open(ctx, id, ""); err != nil {
			t.Fatalf("open %s: %v", id, err)
		}
		ch, ok := m.OutputChan(id)
		if !ok {
			t.Fatalf("output chan missing: %s", id)
		}
		if err := m.Input(id, fmt.Sprintf("echo CYCLE_%d\n", i)); err != nil {
			t.Fatalf("input %s: %v", id, err)
		}
		seen := false
		deadline := time.After(5 * time.Second)
	read:
		for {
			select {
			case <-deadline:
				t.Fatalf("%s: 5s 未见输出", id)
			case text, ok := <-ch:
				if !ok {
					break read
				}
				if strings.Contains(text, fmt.Sprintf("CYCLE_%d", i)) {
					seen = true
					break read
				}
			}
		}
		if !seen {
			t.Fatalf("%s: 未读到回显", id)
		}
		cancel()
		// 等 outCh 关闭（读泵结束 → closer 触发），验证无 panic 且通道收敛。
		deadline = time.After(5 * time.Second)
	drain:
		for {
			select {
			case <-deadline:
				t.Fatalf("%s: outCh 未关闭", id)
			case _, ok := <-ch:
				if !ok {
					break drain
				}
			}
		}
	}
}
