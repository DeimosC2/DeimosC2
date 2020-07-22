// +build windows
package shellexec

import (
	"os/exec"
	"syscall"
)

//ShellExecute will execute the commands passed and return the byte result
func ShellExecute(data []string, cwd string) []byte {
	cmd := exec.Command(data[0], data[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Dir = cwd
	result, err := cmd.Output()
	if err != nil {
		return []byte(err.Error())
	}
	return result
}
