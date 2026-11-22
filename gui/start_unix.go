//go:build !windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// agentCommand runs hem-ssh-agent from the directory this window was started
// from (the app bundle, ~/.local/bin), else from PATH, logging to the file
// Show log opens.
func agentCommand(args []string) (*exec.Cmd, error) {
	path := "hem-ssh-agent"
	if exe, err := os.Executable(); err == nil {
		if p := filepath.Join(filepath.Dir(exe), path); fileExists(p) {
			path = p
		}
	}
	if !filepath.IsAbs(path) {
		p, err := exec.LookPath(path)
		if err != nil {
			return nil, err
		}
		path = p
	}
	// `run` must stay the subcommand right after the global flags.
	args = append(args, "--log-file", agentLog())
	cmd := exec.Command(path, args...)
	// A session of its own: it outlives this window and its terminal.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd, nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
