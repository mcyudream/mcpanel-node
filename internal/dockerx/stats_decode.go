package dockerx

import (
	"encoding/json"
	"fmt"
	"io"
)

// statsJSON is a local partial view of the Docker stats JSON. Decoding into
// our own struct keeps this package independent of SDK stats struct churn
// while only touching fields the engine documents in the API.
type statsJSON struct {
	CPUStats    cpuStats    `json:"cpu_stats"`
	PreCPUStats cpuStats    `json:"precpu_stats"`
	MemoryStats memoryStats `json:"memory_stats"`
}

type cpuStats struct {
	CPUUsage struct {
		TotalUsage uint64 `json:"total_usage"`
	} `json:"cpu_usage"`
	SystemUsage uint64 `json:"system_cpu_usage"`
	OnlineCPUs  uint32 `json:"online_cpus"`
}

type memoryStats struct {
	Usage uint64 `json:"usage"`
	Limit uint64 `json:"limit"`
}

func decodeStats(r io.Reader) (statsJSON, error) {
	var s statsJSON
	if err := json.NewDecoder(io.LimitReader(r, 256<<10)).Decode(&s); err != nil {
		return statsJSON{}, fmt.Errorf("decode stats json: %w", err)
	}
	return s, nil
}

// CPUPercent computes the classic delta formula:
// (cpuDelta / systemDelta) * onlineCPUs * 100.
func (s statsJSON) CPUPercent() float64 {
	cpuDelta := float64(s.CPUStats.CPUUsage.TotalUsage) - float64(s.PreCPUStats.CPUUsage.TotalUsage)
	sysDelta := float64(s.CPUStats.SystemUsage) - float64(s.PreCPUStats.SystemUsage)
	if cpuDelta <= 0 || sysDelta <= 0 {
		return 0
	}
	cpus := float64(s.CPUStats.OnlineCPUs)
	if cpus == 0 {
		cpus = 1
	}
	return round1(cpuDelta / sysDelta * cpus * 100)
}

func round1(v float64) float64 {
	return float64(int64(v*10+0.5)) / 10
}
