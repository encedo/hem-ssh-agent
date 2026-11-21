//go:build !windows

package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
)

// defaultControl must agree with default_control_address in src/listen.rs:
// $XDG_RUNTIME_DIR, else ~/.hem-ssh-agent.
var defaultControl = func() string {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".hem-ssh-agent")
	}
	return filepath.Join(dir, "hem-ssh-agent-control.sock")
}()

func dialControl(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}

// agentLog: src/app.rs default_log_path ($XDG_STATE_HOME or ~/.local/state).
func agentLog() string {
	dir := os.Getenv("XDG_STATE_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(dir, "hem-ssh-agent", "agent.log")
}
