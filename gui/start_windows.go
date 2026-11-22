package main

import (
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// agentCommand runs hem-ssh-agentw.exe (the agent without a console, logging
// to %LOCALAPPDATA%\hem-ssh-agent\agent.log) from the directory this window
// was started from: the two are installed together.
func agentCommand(args []string) (*exec.Cmd, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(filepath.Join(filepath.Dir(exe), "hem-ssh-agentw.exe"), args...)
	// Its own process group, no console: it outlives this window.
	cmd.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
		HideWindow:    true,
	}
	return cmd, nil
}
