package wsserver

import "testing"

// 启动成功检测窗口（starting）内 docker 容器实际已 running：实时输出订阅必须
// 放行，否则启动阶段的控制台输出（含启动失败堆栈）整段丢失。
func TestOutputAttachable(t *testing.T) {
	allowed := map[string]bool{
		"running":  true,
		"starting": true,
	}
	denied := []string{"created", "exited", "paused", "stopped", "missing", "unknown", ""}
	for state, want := range allowed {
		if got := outputAttachable(state); got != want {
			t.Fatalf("outputAttachable(%q) = %v, want %v", state, got, want)
		}
	}
	for _, state := range denied {
		if outputAttachable(state) {
			t.Fatalf("outputAttachable(%q) 应拒绝", state)
		}
	}
}
