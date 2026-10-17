// Package tasks 提供节点侧长任务登记（镜像拉取、整合包安装）：
// 控制信道 req 立即返回 taskId，终态与进度经 task.get 查询。
package tasks

import (
 "context"
 "crypto/sha512"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "net/http"
 "os"
 "path/filepath"
 "sort"
 "strings"
 "sync"
 "sync/atomic"
 "time"
)

const maxConcurrent = 4

// 单文件下载自愈参数：stallTimeout 内没有任何字节进展即中止本次尝试（连接挂死
// 不会把 install.run 卡成永久 running）；瞬时失败最多尝试 maxAttempts 次，
// 间隔按次数递增。测试可覆盖 stallTimeout 缩短等待。
var (
	stallTimeout = 60 * time.Second
	maxAttempts  = 3
	retryBackoff = 2 * time.Second
)

// errDownloadStalled 表示本次尝试在看门狗超时内零字节进展（可重试）。
var errDownloadStalled = errors.New("下载停滞超时")

// permanentError 包装永久性失败（地址无效、4xx、超限），重试无意义直接抛出。
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

func permanentf(format string, args ...any) error {
	return &permanentError{err: fmt.Errorf(format, args...)}
}

func isPermanent(err error) bool {
	var pe *permanentError
	return errors.As(err, &pe)
}

type State struct {
 ID string `json:"taskId"`
 Kind string `json:"kind"`
 State string `json:"state"` // running | done | failed | canceled
 Detail string `json:"detail,omitempty"`
 Progress float64 `json:"progress"`
 Files *FilesProgress `json:"files,omitempty"`
 Error string `json:"error,omitempty"`
 At int64 `json:"at"`
}

// FileState 是安装计划内单个文件的实时快照；idx 仅用于并发下回写匹配，不序列化。
type FileState struct {
 Path string `json:"path"`
 State string `json:"state"` // running | done | failed
 Bytes int64 `json:"bytes,omitempty"`
 Total int64 `json:"total,omitempty"` // Content-Length 未知时为 0
 Error string `json:"error,omitempty"`
 idx int
}

// FilesProgress 是 install.run 的文件级进度快照：总数/完成/失败计数，
// Active 为正在下载的条目（并发上限 4），FailedList 只保留前 maxTrackedFailures
// 条失败明细（超出仅计数），保证 2000 文件计划的内存与 payload 有界。
type FilesProgress struct {
 Total int `json:"total"`
 Done int `json:"done"`
 Failed int `json:"failed"`
 Active []FileState `json:"active,omitempty"`
 FailedList []FileState `json:"failedList,omitempty"`
}

const maxTrackedFailures = 50

type Registry struct {
 mu sync.Mutex
 tasks map[string]*State
 order []string
 client *http.Client
}

func New() *Registry {
 r := &Registry{tasks: map[string]*State{}, client: &http.Client{Timeout: 0}}
 go r.gcLoop()
 return r
}

func (r *Registry) gcLoop() {
 t := time.NewTicker(10 * time.Minute); defer t.Stop()
 for range t.C {
  r.mu.Lock()
  cutoff := time.Now().Add(-24 * time.Hour).UnixMilli()
  for id, s := range r.tasks {
   if s.At < cutoff && s.State != "running" { delete(r.tasks, id) }
  }
  r.order = r.order[:0]
  for id := range r.tasks { r.order = append(r.order, id) }
  sort.Strings(r.order)
  r.mu.Unlock()
 }
}

func (r *Registry) begin(kind, detail string) string {
 id := fmt.Sprintf("task-%d", time.Now().UnixNano())
 r.mu.Lock(); defer r.mu.Unlock()
 r.tasks[id] = &State{ID: id, Kind: kind, State: "running", Detail: detail, At: time.Now().UnixMilli()}
 if len(r.tasks) > 1000 { // 有界：超限先清最旧终态
  for _, k := range r.order { if s := r.tasks[k]; s != nil && s.State != "running" { delete(r.tasks, k); if len(r.tasks) <= 1000 { break } } }
  r.order = r.order[:0]; for k := range r.tasks { r.order = append(r.order, k) }; sort.Strings(r.order)
 }
 return id
}

func (r *Registry) update(id string, progress float64) {
 r.mu.Lock(); defer r.mu.Unlock()
 if s, ok := r.tasks[id]; ok && s.State == "running" { s.Progress = progress; s.At = time.Now().UnixMilli() }
}

func (r *Registry) finish(id string, err error) {
 r.mu.Lock(); defer r.mu.Unlock()
 s, ok := r.tasks[id]; if !ok { return }
 if err != nil {
  if errors.Is(err, context.Canceled) { s.State = "canceled" } else { s.State = "failed"; s.Error = truncate(err.Error()) }
 } else { s.State = "done"; s.Progress = 1 }
 s.At = time.Now().UnixMilli()
}

func truncate(s string) string { if len(s) > 512 { s = s[:512] }; return s }

func (r *Registry) Get(id string)(State, bool){
 r.mu.Lock(); defer r.mu.Unlock()
 s, ok := r.tasks[id]; if !ok { return State{}, false }
 copied := *s
 if s.Files != nil {
  fc := *s.Files
  fc.Active = append([]FileState(nil), s.Files.Active...)
  fc.FailedList = append([]FileState(nil), s.Files.FailedList...)
  copied.Files = &fc
 }
 return copied, true
}

// mutateFiles 在任务锁内修改 Files 快照（任务不存在或已离开 running 时忽略；
// 所有文件事件都发生在 finish 之前，终态快照因此完整保留）。
func (r *Registry) mutateFiles(id string, fn func(*FilesProgress)) {
 r.mu.Lock(); defer r.mu.Unlock()
 if s, ok := r.tasks[id]; ok && s.State == "running" && s.Files != nil {
  fn(s.Files)
  s.At = time.Now().UnixMilli()
 }
}

// fileDone 在快照里摘除 active 条目并落计数/失败明细。
func (r *Registry) fileDone(id string, file FileState, err error) {
 r.mutateFiles(id, func(f *FilesProgress) {
  for i := range f.Active {
   if f.Active[i].idx == file.idx {
    f.Active = append(f.Active[:i], f.Active[i+1:]...)
    break
   }
  }
  if err != nil {
   f.Failed++
   file.State = "failed"
   file.Error = truncate(err.Error())
   if len(f.FailedList) < maxTrackedFailures {
    f.FailedList = append(f.FailedList, file)
   }
  } else {
   f.Done++
  }
 })
}

// fileBytes 更新 active 条目的字节进度。
func (r *Registry) fileBytes(id string, idx int, done, total int64) {
 r.mutateFiles(id, func(f *FilesProgress) {
  for i := range f.Active {
   if f.Active[i].idx == idx {
    f.Active[i].Bytes = done
    f.Active[i].Total = total
    return
   }
  }
 })
}

// PullImage 拉取镜像；ctx 取消即中止（节点关闭时清理）。
func (r *Registry) PullImage(ctx context.Context, pull func(context.Context,string)error, image string) string {
 id := r.begin("image.pull", image)
 go func() { err := pull(ctx, image); r.finish(id, maskImageError(err)) }()
 return id
}

func maskImageError(err error) error {
 if err == nil { return nil }
 msg := err.Error()
 // 不透传 registry 鉴权头或完整 URL 查询串。
 if i := strings.Index(msg, "?"); i >= 0 { msg = msg[:i] }
 return errors.New(truncate(msg))
}

type PlanItem struct {
	URL string `json:"url"`
	// Urls 是源回退列表（可选）：按顺序尝试的下载地址（如镜像源在前、官方在后）。
	// 兼容旧面板只发 url 的形态；两者合并去重后作为候选。
	Urls []string `json:"urls,omitempty"`
	Path string `json:"path"`
	Sha512 string `json:"sha512,omitempty"`
	Size int64 `json:"size,omitempty"`
}

// candidatesOf 汇总下载候选地址：url + urls 保序去重去空；url 非空但 urls 缺失时
// 兼容退化为单候选。
func candidatesOf(item PlanItem) []string {
	seen := make(map[string]bool, len(item.Urls)+1)
	out := make([]string, 0, len(item.Urls)+1)
	for _, u := range append([]string{item.URL}, item.Urls...) {
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	return out
}

// RunInstall 按计划并发下载并校验文件到实例 root（相对路径已由面板生成、节点再校验）。
// 进度按「已完成文件数 + 当前文件内字节进度」加权聚合（0-1）；Content-Length 未知
// 的分块响应不贡献中间进度（不伪造估算值）。
func (r *Registry) RunInstall(ctx context.Context, root string, plan []PlanItem) string {
 id := r.begin("install.run", fmt.Sprintf("%d 个文件", len(plan)))
 r.mu.Lock()
 r.tasks[id].Files = &FilesProgress{Total: len(plan)}
 r.mu.Unlock()
 go func() {
  err := r.runInstall(ctx, id, root, plan)
  r.finish(id, err)
 }()
 return id
}

func (r *Registry) runInstall(ctx context.Context, taskID string, root string, plan []PlanItem) error {
 if len(plan) > 2000 { return errors.New("安装计划文件数超限") }
 total := int64(len(plan))
 var done int64
 last := int64(-1) // 上次写入的万分比（1% 步进节流）
 report := func(fileProgress float64) {
  permille := int64(((float64(done) + clamp01(fileProgress)) / float64(total)) * 10000)
  if permille > last {
   last = permille
   r.update(taskID, float64(permille)/10000)
  }
 }
 markDone := func(file FileState, err error) {
  atomic.AddInt64(&done, 1)
  r.fileDone(taskID, file, err)
 }
 sem := make(chan struct{}, maxConcurrent)
 var wg sync.WaitGroup
 errs := make([]error, len(plan))
 for i, item := range plan {
  if ctx.Err() != nil { break }
  file := FileState{idx: i, Path: item.Path}
  if len(candidatesOf(item)) == 0 || item.Path == "" || strings.ContainsAny(item.Path, "\x00") {
   markDone(file, errors.New("安装项无效")); continue
  }
  clean := filepath.Clean(item.Path)
  if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
   markDone(file, errors.New("安装路径越界")); continue
  }
  file.Path = clean
  r.mutateFiles(taskID, func(f *FilesProgress) { f.Active = append(f.Active, file) })
  wg.Add(1); sem <- struct{}{}
  go func(file FileState, item PlanItem, clean string) {
   defer wg.Done(); defer func() { <-sem }()
   errs[file.idx] = r.downloadWithRetry(ctx, root, item, clean, func(bytesDone, total int64) {
    r.fileBytes(taskID, file.idx, bytesDone, total)
    if total > 0 { report(float64(bytesDone) / float64(total)) }
   })
   markDone(file, errs[file.idx])
  }(file, item, clean)
 }
 wg.Wait()
 for _, err := range errs { if err != nil { return err } }
 return ctx.Err()
}

func clamp01(v float64) float64 { if v < 0 { return 0 }; if v > 1 { return 1 }; return v }

 // downloadWithRetry 逐个候选源下载：每个源内做瞬时失败自动重试（停滞、网络
 // 错误、5xx、校验失败）；永久性错误（地址无效、4xx 不存在、超过 2GiB）或源内
 // 重试耗尽后跳到下一个源，全部源耗尽返回最后一次错误。节点关闭立即中止。
func (r *Registry) downloadWithRetry(ctx context.Context, root string, item PlanItem, clean string,
 onTick func(bytesDone, total int64)) error {
 var last error
 candidates := candidatesOf(item)
 for index, candidate := range candidates {
  if index > 0 {
   // 换源前重置字节进度，让面板 per-file 明细能看出从头开始。
   onTick(0, item.Size)
  }
  for attempt := 1; attempt <= maxAttempts; attempt++ {
   if attempt > 1 {
    // 重试前重置字节进度，让面板 per-file 明细能看出从头开始。
    onTick(0, item.Size)
    timer := time.NewTimer(retryBackoff * time.Duration(attempt-1))
    select {
    case <-ctx.Done():
     timer.Stop()
     return ctx.Err()
    case <-timer.C:
    }
   }
   last = r.downloadOne(ctx, root, candidate, item, clean, onTick)
   if last == nil || ctx.Err() != nil {
    return last
   }
   if isPermanent(last) {
    break // 该源无此文件，换下一个源
   }
  }
 }
 return last
}

func (r *Registry) downloadOne(ctx context.Context, root string, url string, item PlanItem, clean string,
 onTick func(bytesDone, total int64)) error {
 // 停滞看门狗：每次读到字节就重置计时；超时取消本文件本次尝试（不影响其他并发下载）。
 stallCtx, cancelStall := context.WithCancel(ctx)
 defer cancelStall()
 stallTimer := time.AfterFunc(stallTimeout, cancelStall)
 defer stallTimer.Stop()
 poke := func() { stallTimer.Reset(stallTimeout) }
 req, err := http.NewRequestWithContext(stallCtx, http.MethodGet, url, nil)
 if err != nil { return permanentf("下载地址无效") }
 // 只允许公网 http(s) 直连，禁 file/localhost 私有协议由 transport 层默认保证。
 resp, err := r.client.Do(req); if err != nil {
  if stallCtx.Err() != nil && ctx.Err() == nil { return errDownloadStalled }
  return fmt.Errorf("下载失败：%w", err)
 }
 defer resp.Body.Close()
 if resp.StatusCode != http.StatusOK {
  if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusRequestTimeout {
   return permanentf("下载返回 %d", resp.StatusCode)
  }
  return fmt.Errorf("下载返回 %d", resp.StatusCode)
 }
 total := resp.ContentLength // <=0（分块）时不做中间进度
 target := filepath.Join(root, clean)
 if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil { return err }
 tmp, err := os.CreateTemp(filepath.Dir(target), ".panel-install-*"); if err != nil { return err }
 name := tmp.Name(); defer os.Remove(name)
 h := sha512.New(); size := int64(0)
 buf := make([]byte, 64*1024)
 for {
  if ctx.Err() != nil { tmp.Close(); return ctx.Err() }
  n, rerr := resp.Body.Read(buf)
  if n > 0 {
   poke()
   size += int64(n)
   if size > 2<<30 { tmp.Close(); return permanentf("安装文件超过2GiB") }
   if _, werr := tmp.Write(buf[:n]); werr != nil { tmp.Close(); return werr }
   if _, werr := h.Write(buf[:n]); werr != nil { tmp.Close(); return werr }
   if onTick != nil { onTick(size, total) }
    }
  if rerr == io.EOF { break }
  if rerr != nil {
   tmp.Close()
   if stallCtx.Err() != nil && ctx.Err() == nil { return errDownloadStalled }
   return rerr
  }
 }
 if item.Size > 0 && size != item.Size { tmp.Close(); return fmt.Errorf("大小校验失败：%s", clean) }
 if item.Sha512 != "" && hex.EncodeToString(h.Sum(nil)) != strings.ToLower(item.Sha512) { tmp.Close(); return fmt.Errorf("sha512 校验失败：%s", clean) }
 if err := tmp.Close(); err != nil { return err }
 if err := os.Chmod(name, 0644); err != nil { return err }
 return os.Rename(name, target)
}
