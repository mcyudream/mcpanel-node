package tasks

import (
 "context"
 "fmt"
 "net/http"
 "net/http/httptest"
 "os"
 "path/filepath"
 "sync/atomic"
 "testing"
 "time"
)

func waitForTerminal(t *testing.T, r *Registry, id string) State {
 t.Helper()
 deadline := time.Now().Add(5 * time.Second)
 for time.Now().Before(deadline) {
  s, ok := r.Get(id)
  if ok && s.State != "running" {
   return s
  }
  time.Sleep(10 * time.Millisecond)
 }
 t.Fatal("任务 5s 内未到终态")
 return State{}
}

func TestRunInstallReportsFileSnapshot(t *testing.T) {
 good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
  w.Header().Set("Content-Length", "5")
  _, _ = w.Write([]byte("hello"))
 }))
 defer good.Close()
 bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
  http.Error(w, "nope", http.StatusNotFound)
 }))
 defer bad.Close()

 root := t.TempDir()
 r := New()
 id := r.RunInstall(context.Background(), root, []PlanItem{
  {URL: good.URL + "/a.jar", Path: "mods/a.jar"},
  {URL: bad.URL + "/b.jar", Path: "mods/b.jar"},
  {URL: "", Path: "mods/invalid.jar"},
 })
 s := waitForTerminal(t, r, id)
 if s.State != "failed" {
  t.Fatalf("期望 failed，得到 %s", s.State)
 }
 if s.Files == nil {
  t.Fatal("终态快照缺少 files")
 }
 if s.Files.Total != 3 || s.Files.Done != 1 || s.Files.Failed != 2 {
  t.Fatalf("计数不符：total=%d done=%d failed=%d", s.Files.Total, s.Files.Done, s.Files.Failed)
 }
 if len(s.Files.Active) != 0 {
  t.Fatalf("终态仍残留 active：%v", s.Files.Active)
 }
 if len(s.Files.FailedList) != 2 {
  t.Fatalf("失败明细应为 2 条：%v", s.Files.FailedList)
 }
 var seenInvalid, seen404 bool
 for _, item := range s.Files.FailedList {
  switch filepath.Base(item.Path) {
  case "b.jar":
   seen404 = item.Error != "" && item.State == "failed"
  case "invalid.jar":
   seenInvalid = item.Error == "安装项无效"
  }
 }
 if !seenInvalid || !seen404 {
  t.Fatalf("失败明细内容不符：%+v", s.Files.FailedList)
 }
 if _, err := os.Stat(filepath.Join(root, "mods", "a.jar")); err != nil {
  t.Fatalf("成功文件未落盘：%v", err)
 }
}

func TestRunInstallSnapshotBoundedOnAllFailed(t *testing.T) {
 var srv *httptest.Server
 srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
  http.Error(w, "nope", http.StatusNotFound)
 }))
 defer srv.Close()

 plan := make([]PlanItem, 0, maxTrackedFailures+10)
 for i := 0; i < maxTrackedFailures+10; i++ {
  plan = append(plan, PlanItem{URL: fmt.Sprintf("%s/%d.jar", srv.URL, i), Path: fmt.Sprintf("mods/%d.jar", i)})
 }
 r := New()
 id := r.RunInstall(context.Background(), t.TempDir(), plan)
 s := waitForTerminal(t, r, id)
 if s.Files == nil {
  t.Fatal("终态快照缺少 files")
 }
 if s.Files.Failed != maxTrackedFailures+10 {
  t.Fatalf("失败计数应完整：%d", s.Files.Failed)
 }
 if len(s.Files.FailedList) != maxTrackedFailures {
  t.Fatalf("失败明细应封顶 %d：%d", maxTrackedFailures, len(s.Files.FailedList))
 }
}

func TestRunInstallRetriesTransientFailure(t *testing.T) {
 var attempts atomic.Int32
 srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
  if attempts.Add(1) < 2 {
   http.Error(w, "busy", http.StatusInternalServerError)
   return
  }
  w.Header().Set("Content-Length", "5")
  _, _ = w.Write([]byte("hello"))
 }))
 defer srv.Close()

 oldBackoff := retryBackoff
 retryBackoff = 10 * time.Millisecond
 defer func() { retryBackoff = oldBackoff }()

 root := t.TempDir()
 r := New()
 id := r.RunInstall(context.Background(), root, []PlanItem{{URL: srv.URL + "/a.jar", Path: "server.jar"}})
 s := waitForTerminal(t, r, id)
 if s.State != "done" {
  t.Fatalf("重试后应成功，得到 %s（%s）", s.State, s.Error)
 }
 if got := attempts.Load(); got != 2 {
  t.Fatalf("应尝试 2 次，实际 %d 次", got)
 }
 if _, err := os.Stat(filepath.Join(root, "server.jar")); err != nil {
  t.Fatalf("重试成功后文件未落盘：%v", err)
 }
}

func TestRunInstallStallWatchdog(t *testing.T) {
 oldStall := stallTimeout
 stallTimeout = 120 * time.Millisecond
 defer func() { stallTimeout = oldStall }()
 oldBackoff := retryBackoff
 retryBackoff = 10 * time.Millisecond
 defer func() { retryBackoff = oldBackoff }()

 // 写 5 字节后永久挂起：每次尝试都应被看门狗中止。
 srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("Content-Length", "100")
  w.WriteHeader(http.StatusOK)
  _, _ = w.Write([]byte("hello"))
  if f, ok := w.(http.Flusher); ok {
   f.Flush()
  }
  <-r.Context().Done()
 }))
 defer srv.Close()

 r := New()
 id := r.RunInstall(context.Background(), t.TempDir(), []PlanItem{{URL: srv.URL + "/big.jar", Path: "big.jar"}})
 s := waitForTerminal(t, r, id)
 if s.State != "failed" {
  t.Fatalf("停滞任务应 failed，得到 %s", s.State)
 }
 if s.Error == "" {
  t.Fatal("停滞任务应带错误信息")
 }
 if len(s.Files.FailedList) != 1 || s.Files.FailedList[0].Error == "" {
  t.Fatalf("失败明细缺失：%+v", s.Files)
 }
}

func TestDownloadOneNotFoundIsPermanent(t *testing.T) {
 srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
  http.Error(w, "nope", http.StatusNotFound)
 }))
 defer srv.Close()
 r := New()
 err := r.downloadOne(context.Background(), t.TempDir(), srv.URL+"/x.jar",
  PlanItem{URL: srv.URL + "/x.jar", Path: "x.jar"}, "x.jar", nil)
 if err == nil || !isPermanent(err) {
  t.Fatalf("404 应为永久性错误：%v", err)
 }
}

func TestRunInstallPermanentErrorFallsBackToNextUrl(t *testing.T) {
	var primaryHits, secondaryHits atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryHits.Add(1)
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer primary.Close()
	secondary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		secondaryHits.Add(1)
		w.Header().Set("Content-Length", "5")
		_, _ = w.Write([]byte("hello"))
	}))
	defer secondary.Close()

	oldBackoff := retryBackoff
	retryBackoff = 10 * time.Millisecond
	defer func() { retryBackoff = oldBackoff }()

	root := t.TempDir()
	r := New()
	id := r.RunInstall(context.Background(), root, []PlanItem{{
		URL:  primary.URL + "/a.jar",
		Urls: []string{secondary.URL + "/a.jar"},
		Path: "server.jar",
	}})
	s := waitForTerminal(t, r, id)
	if s.State != "done" {
		t.Fatalf("永久性错误应回退下一源成功，得到 %s（%s）", s.State, s.Error)
	}
	// 404 是永久性错误：主源只打一次，立即换源。
	if got := primaryHits.Load(); got != 1 {
		t.Fatalf("主源应只尝试 1 次，实际 %d", got)
	}
	if got := secondaryHits.Load(); got != 1 {
		t.Fatalf("次源应尝试 1 次，实际 %d", got)
	}
	if _, err := os.Stat(filepath.Join(root, "server.jar")); err != nil {
		t.Fatalf("回退成功后文件未落盘：%v", err)
	}
}

func TestRunInstallTransientExhaustionFallsBackToNextUrl(t *testing.T) {
	var primaryHits, secondaryHits atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryHits.Add(1)
		http.Error(w, "busy", http.StatusInternalServerError)
	}))
	defer primary.Close()
	secondary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		secondaryHits.Add(1)
		w.Header().Set("Content-Length", "5")
		_, _ = w.Write([]byte("hello"))
	}))
	defer secondary.Close()

	oldBackoff := retryBackoff
	retryBackoff = 5 * time.Millisecond
	defer func() { retryBackoff = oldBackoff }()

	r := New()
	id := r.RunInstall(context.Background(), t.TempDir(), []PlanItem{{
		URL:  primary.URL + "/a.jar",
		Urls: []string{secondary.URL + "/a.jar"},
		Path: "server.jar",
	}})
	s := waitForTerminal(t, r, id)
	if s.State != "done" {
		t.Fatalf("瞬时失败耗尽后应回退下一源成功，得到 %s（%s）", s.State, s.Error)
	}
	if got := primaryHits.Load(); got != int32(maxAttempts) {
		t.Fatalf("主源应尝试 %d 次，实际 %d", maxAttempts, got)
	}
	if got := secondaryHits.Load(); got != 1 {
		t.Fatalf("次源应尝试 1 次，实际 %d", got)
	}
}
