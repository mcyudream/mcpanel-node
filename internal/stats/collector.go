// Package stats assembles the node.stats snapshot (protocol §5.2).
//
// Collection is context-aware end to end: cancelling the session context
// aborts host metric reads and in-flight Docker stats calls. Docker queries
// are read-only and bounded (per-call timeout, bounded concurrency).
package stats

import (
	"context"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"

	"github.com/yudream/mcpanel-node/internal/dockerx"
	"github.com/yudream/mcpanel-node/internal/version"
)

// ManagedContainerLabel marks containers as mcpanel-managed instances.
// M1 has no instance creation yet, so the stats containers list is naturally
// empty until M2 starts labelling containers. The label value carries the
// panel-issued instanceId.
const (
	LabelManaged   = "mcpanel.managed"
	LabelInstance  = "mcpanel.instanceId"
	statsTimeout   = 2 * time.Second
	collectWorkers = 8
	// collectDeadline bounds the whole snapshot assembly so the 5s stats
	// period (and the panel's 15s offline detection) stays meaningful even
	// when Docker is slow.
	collectDeadline = 4 * time.Second
	sampleInterval  = 250 * time.Millisecond
)

// ContainerStat mirrors protocol §5.2 container entry.
type ContainerStat struct {
	InstanceID string  `json:"instanceId"`
	State      string  `json:"state"`
	CPUPercent float64 `json:"cpuPercent"`
	MemUsedMb  int64   `json:"memUsedMb"`
}

// Snapshot is the evt node.stats payload (field names and units fixed by
// the protocol: cpu percent one decimal, memory MB integers, disk GB integers).
type Snapshot struct {
	CPUPercent    float64         `json:"cpuPercent"`
	MemUsedMb     int64           `json:"memUsedMb"`
	MemTotalMb    int64           `json:"memTotalMb"`
	DiskUsedGb    int64           `json:"diskUsedGb"`
	DiskTotalGb   int64           `json:"diskTotalGb"`
	Load1         *float64        `json:"load1,omitempty"`
	Containers    []ContainerStat `json:"containers"`
	DockerVersion string          `json:"dockerVersion,omitempty"`
	AgentVersion  string          `json:"agentVersion"`
}

// Collector gathers host + container metrics.
type Collector struct {
	dataDir string
	log     *slog.Logger

	docker      *dockerx.Client // nil when Docker is unavailable
	versionOnce sync.Once
	dockerVer   string

	// startingLookup 可选：返回实例当前是否处于「启动中」窗口（启动成功检测
	// 尚未命中）。命中时快照把 docker 的 running 覆写为 starting，让面板
	// 三处口径（快照纠偏/详情 liveState/总览）一致看到启动中。
	startingLookup func(instanceID string) bool
}

// SetStartingLookup 注册启动中判定（instances.Service.IsStarting）；nil 安全。
func (c *Collector) SetStartingLookup(lookup func(instanceID string) bool) {
	c.startingLookup = lookup
}

// New builds a collector. docker may be nil (Docker unavailable): the
// snapshot then omits dockerVersion and reports an empty containers list.
func New(dataDir string, docker *dockerx.Client, log *slog.Logger) *Collector {
	if log == nil {
		log = slog.Default()
	}
	return &Collector{dataDir: dataDir, log: log, docker: docker}
}

// DockerVersion returns the cached daemon version ("" when unavailable).
func (c *Collector) DockerVersion(ctx context.Context) string {
	if c.docker == nil {
		return ""
	}
	c.versionOnce.Do(func() {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		v, err := c.docker.Version(ctx)
		if err != nil {
			c.log.WarnContext(ctx, "docker version probe failed", "err", err)
			return
		}
		c.dockerVer = v
	})
	return c.dockerVer
}

// Collect assembles one snapshot. The whole assembly is bounded by
// collectDeadline; individual sub-reads degrade gracefully: a failing part
// logs a warning and leaves its fields zeroed rather than failing the event.
func (c *Collector) Collect(ctx context.Context) Snapshot {
	ctx, cancel := context.WithTimeout(ctx, collectDeadline)
	defer cancel()

	snap := Snapshot{AgentVersion: version.Version, Containers: []ContainerStat{}}

	var wg sync.WaitGroup
	var mu sync.Mutex

	// Host CPU: short blocking sample so consecutive ticks produce deltas.
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(ctx, sampleInterval+2*time.Second)
		defer cancel()
		percents, err := cpu.PercentWithContext(ctx, sampleInterval, false)
		if err != nil || len(percents) == 0 {
			c.log.DebugContext(ctx, "cpu sample failed", "err", err)
			return
		}
		mu.Lock()
		snap.CPUPercent = round1(percents[0])
		mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		vm, err := mem.VirtualMemoryWithContext(ctx)
		if err != nil {
			c.log.DebugContext(ctx, "memory sample failed", "err", err)
			return
		}
		mu.Lock()
		snap.MemUsedMb = bytesToMb(vm.Used)
		snap.MemTotalMb = bytesToMb(vm.Total)
		mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		du, err := disk.UsageWithContext(ctx, c.dataDir)
		if err != nil {
			c.log.DebugContext(ctx, "disk sample failed", "err", err)
			return
		}
		mu.Lock()
		snap.DiskUsedGb = bytesToGb(du.Used)
		snap.DiskTotalGb = bytesToGb(du.Total)
		mu.Unlock()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if runtime.GOOS == "windows" {
			return // no load concept; protocol allows omitting load1
		}
		avg, err := load.AvgWithContext(ctx)
		if err != nil {
			return
		}
		v := round2(avg.Load1)
		mu.Lock()
		snap.Load1 = &v
		mu.Unlock()
	}()

	if c.docker != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			containers := c.collectContainers(ctx)
			mu.Lock()
			snap.Containers = containers
			mu.Unlock()
		}()
	}

	wg.Wait()
	snap.DockerVersion = c.DockerVersion(ctx)
	return snap
}

// collectContainers lists mcpanel-managed running containers and samples
// their stats with a fixed worker pool (bounded goroutines) and ctx-aware
// enqueue. Only containers carrying the mcpanel.instanceId label are
// reported (protocol: instanceId is the panel-issued id; unlabelled
// containers are not managed instances and are skipped).
func (c *Collector) collectContainers(ctx context.Context) []ContainerStat {
	dctx, cancel := context.WithTimeout(ctx, collectDeadline)
	defer cancel()

	// 全量受管容器（含 exited/created/paused）：快照必须覆盖非运行系，否则
	// 容器退出后从快照消失，面板只能依赖 instance.state 事件纠偏——事件在
	// docker events 断流/WS 重连窗口会整段丢失，面板将长期显示运行中。
	refs, err := c.docker.ListManagedAll(dctx, LabelManaged+"=true")
	if err != nil {
		c.log.WarnContext(ctx, "docker container list failed", "err", err)
		return []ContainerStat{}
	}

	type job struct {
		ref dockerx.ContainerRef
		idx int
	}
	jobs := make(chan job)
	out := make([]ContainerStat, len(refs))
	filled := make([]bool, len(refs))
	var fillMu sync.Mutex

	var wg sync.WaitGroup
	for w := 0; w < collectWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				stat := c.sampleContainer(ctx, j.ref)
				fillMu.Lock()
				out[j.idx] = stat
				filled[j.idx] = true
				fillMu.Unlock()
			}
		}()
	}

enqueue:
	for i, ref := range refs {
		if instanceIDFromLabels(ref.Labels) == "" {
			continue // not a panel-managed instance; skip entirely
		}
		if ref.State != "running" {
			// 非运行系不进采样池（stats 接口对停止容器无意义）：直接报状态，
			// cpu/mem 置 0，让面板把「不在快照中」升级为「快照明确报 exited」。
			out[i] = ContainerStat{
				InstanceID: instanceIDFromLabels(ref.Labels),
				State:      normalizeState(ref.State),
			}
			filled[i] = true
			continue
		}
		select {
		case <-ctx.Done():
			break enqueue
		case jobs <- job{ref: ref, idx: i}:
		}
	}
	close(jobs)
	wg.Wait()

	result := make([]ContainerStat, 0, len(out))
	for i := range out {
		if filled[i] {
			result = append(result, out[i])
		}
	}
	return result
}

func (c *Collector) sampleContainer(ctx context.Context, ref dockerx.ContainerRef) ContainerStat {
	stat := ContainerStat{
		InstanceID: instanceIDFromLabels(ref.Labels),
		State:      normalizeState(ref.State),
	}
	// 启动成功检测窗口内：docker 视角已 running，但面板口径应为 starting，
	// 直到检测命中或超时（instances.Service 负责结束窗口并回推 running）。
	if stat.State == "running" && c.startingLookup != nil && c.startingLookup(stat.InstanceID) {
		stat.State = "starting"
	}
	sctx, scancel := context.WithTimeout(ctx, statsTimeout)
	sample, err := c.docker.StatsOneShot(sctx, ref.ID)
	scancel()
	if err == nil {
		stat.CPUPercent = round1(sample.CPUPercent)
		stat.MemUsedMb = bytesToMb(sample.MemBytes)
	} else if ctx.Err() == nil {
		c.log.DebugContext(ctx, "container stats failed", "container", ref.ID, "err", err)
	}
	return stat
}

// instanceIDFromLabels resolves the panel-issued instanceId from container
// labels. Empty when the label is absent or blank.
func instanceIDFromLabels(labels map[string]string) string {
	if labels == nil {
		return ""
	}
	return strings.TrimSpace(labels[LabelInstance])
}

func normalizeState(s string) string {
	switch s {
	case "created", "running", "paused", "stopped", "exited":
		return s
	default:
		return "unknown"
	}
}

func bytesToMb(b uint64) int64 { return int64(b / (1024 * 1024)) }
func bytesToGb(b uint64) int64 { return int64(b / (1024 * 1024 * 1024)) }

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }
func round2(v float64) float64 { return float64(int64(v*100+0.5)) / 100 }
