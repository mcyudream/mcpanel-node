package wsserver

import (
 "time"
 "context"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"

 "github.com/yudream/mcpanel-node/internal/tasks"
)

// task.get 的真实出口 JSON 必须带 files 快照（面板安装明细行的数据源）；
// 终态快照保留完整，用快速完成的下载即可断言。
func TestTaskGetWireContainsFiles(t *testing.T) {
 good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
  w.Header().Set("Content-Length", "5")
  _, _ = w.Write([]byte("hello"))
 }))
 defer good.Close()
 bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
  http.Error(w, "nope", http.StatusNotFound)
 }))
 defer bad.Close()

 reg := tasks.New()
 id := reg.RunInstall(context.Background(), t.TempDir(), []tasks.PlanItem{
  {URL: good.URL + "/a.jar", Path: "mods/a.jar"},
  {URL: bad.URL + "/b.jar", Path: "mods/b.jar"},
 })
 deadline := time.Now().Add(5 * time.Second)
 for time.Now().Before(deadline) {
  if s, ok := reg.Get(id); ok && s.State != "running" {
   break
  }
  time.Sleep(10 * time.Millisecond)
 }

 s := New(Options{Tasks: reg})
 res, err := s.Dispatch(context.Background(), "task.get", map[string]any{"taskId": id}, "")
 if err != nil {
  t.Fatalf("task.get 失败：%v", err)
 }
 raw, err := json.Marshal(res)
 if err != nil {
  t.Fatalf("编码失败：%v", err)
 }
 if !strings.Contains(string(raw), `"files"`) || !strings.Contains(string(raw), `"total":2`) || !strings.Contains(string(raw), `"failed":1`) {
  t.Fatalf("wire JSON 缺 files 快照：%s", raw)
 }
}
