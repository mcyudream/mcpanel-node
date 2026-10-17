//go:build unix

package shellterm

import (
 "os/exec"
 "syscall"
)

func setProcessGroup(cmd *exec.Cmd) {
 cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}
