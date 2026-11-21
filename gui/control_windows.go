package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// defaultControl must agree with CONTROL_PIPE in src/listen.rs.
const defaultControl = `\\.\pipe\hem-ssh-agent-control`

// dialControl opens the control channel. From encedo-wg-hsm gui (MIT): the
// impersonation level is spelled out because winio's default is anonymous,
// and a timeout because a busy pipe waits rather than failing.
func dialControl(ctx context.Context, path string) (net.Conn, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	return winio.DialPipeAccessImpLevel(ctx, path,
		windows.GENERIC_READ|windows.GENERIC_WRITE, winio.PipeImpLevelIdentification)
}

// agentLog is where hem-ssh-agentw.exe writes (src/app.rs default_log_path).
func agentLog() string {
	return filepath.Join(os.Getenv("LOCALAPPDATA"), "hem-ssh-agent", "agent.log")
}
