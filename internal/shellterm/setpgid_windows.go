//go:build windows

package shellterm

import "os/exec"

func setProcessGroup(cmd *exec.Cmd) {
 // Windows 无进程组语义；任务对象回收由超时 Kill 覆盖。
}
