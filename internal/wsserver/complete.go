package wsserver

// 真实系统命令补全：扫描 PATH 各目录下的可执行文件名，供节点终端的
// 补全下拉使用（node.term.complete）。与 PTY 会话无关——不发命令、
// 不碰 shell，只在节点本地做一次目录扫描 + 内存前缀过滤。
//
// 结果按 TTL 缓存：补全是按键级高频请求，全量扫描 PATH 每 60s 一次足够；
// 新装的可执行文件最迟一个 TTL 后可被补全到。

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// completionCacheTTL 可执行文件名缓存的存活时间。
	completionCacheTTL = time.Minute
	// completionDefaultLimit 单次补全返回的最大候选数。
	completionDefaultLimit = 10
	// completionMaxLimit 允许调用方请求的上限，防止无界返回。
	completionMaxLimit = 25
)

// shellCompleter 提供按前缀的系统可执行文件补全。
type shellCompleter struct {
	mu      sync.Mutex
	names   []string
	scanned time.Time
}

// complete 返回以 prefix 开头的可执行文件名（最多 limit 个，字典序）。
// prefix 为空或包含路径分隔符/空白时视为无补全——本补全只针对单个命令词。
func (c *shellCompleter) complete(prefix string, limit int) []string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || limit <= 0 {
		return nil
	}
	if strings.ContainsAny(prefix, " \t/\\") {
		return nil
	}
	names := c.snapshot()
	lower := strings.ToLower(prefix)
	// Windows 文件系统大小写不敏感，匹配与去重统一按小写。
	fold := runtime.GOOS == "windows"
	seen := map[string]bool{}
	matches := make([]string, 0, limit)
	for _, name := range names {
		key := name
		if fold {
			key = strings.ToLower(name)
		}
		if seen[key] || !strings.HasPrefix(key, lower) {
			continue
		}
		seen[key] = true
		matches = append(matches, name)
		if len(matches) >= limit {
			break
		}
	}
	sort.Strings(matches)
	return matches
}

// snapshot 返回缓存的可执行文件名列表，过期时重新扫描。
func (c *shellCompleter) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.names != nil && time.Since(c.scanned) < completionCacheTTL {
		return c.names
	}
	c.names = scanPathExecutables()
	c.scanned = time.Now()
	return c.names
}

// scanPathExecutables 遍历 PATH 各目录，收集可执行文件名。
// Windows 仅接受 PATHEXT 扩展名并去掉扩展名；Unix 要求可执行位。
func scanPathExecutables() []string {
	exts := executableExtensions()
	fold := runtime.GOOS == "windows"
	seen := map[string]bool{}
	names := []string{}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name, ok := executableName(entry, exts)
			if !ok {
				continue
			}
			key := name
			if fold {
				key = strings.ToLower(name)
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

func executableExtensions() []string {
	if runtime.GOOS != "windows" {
		return nil
	}
	exts := filepath.SplitList(os.Getenv("PATHEXT"))
	if len(exts) == 0 {
		return []string{".com", ".exe", ".bat", ".cmd"}
	}
	for i := range exts {
		exts[i] = strings.ToLower(strings.TrimSpace(exts[i]))
	}
	return exts
}

func executableName(entry os.DirEntry, exts []string) (string, bool) {
	if entry.IsDir() {
		return "", false
	}
	name := entry.Name()
	if runtime.GOOS == "windows" {
		ext := strings.ToLower(filepath.Ext(name))
		for _, allowed := range exts {
			if ext == allowed {
				return strings.TrimSuffix(name, filepath.Ext(name)), true
			}
		}
		return "", false
	}
	info, err := entry.Info()
	if err != nil || info.Mode()&0o111 == 0 {
		return "", false
	}
	return name, true
}
