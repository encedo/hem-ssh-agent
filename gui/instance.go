package main

// One window per user: a second launch hands over to the first (which may be
// hidden in the tray) instead of starting another that would notify twice.
// From encedo-wg-hsm gui/instance.go (MIT, same author), unchanged in substance.

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// instanceFile holds the loopback address the running window listens on.
const instanceFile = "instance.port"

// pokeTimeout: a loopback connection to a process on the same machine; longer
// than this and there is nothing there - the file is left from a crash.
const pokeTimeout = 300 * time.Millisecond

// claimInstance makes this process the window, or pokes the one that exists.
func claimInstance(dir string) (ln net.Listener, handedOver bool, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, false, err
	}
	path := filepath.Join(dir, instanceFile)

	if raw, rerr := os.ReadFile(path); rerr == nil {
		if addr := strings.TrimSpace(string(raw)); addr != "" {
			if c, derr := net.DialTimeout("tcp", addr, pokeTimeout); derr == nil {
				c.Close() // the connection is the message
				return nil, true, nil
			}
		}
	}

	// Loopback only: a doorbell between two copies on one machine.
	ln, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, false, err
	}
	if err := os.WriteFile(path, []byte(ln.Addr().String()+"\n"), 0o600); err != nil {
		ln.Close()
		return nil, false, err
	}
	return ln, false, nil
}

// serveInstance answers later launches by showing this window.
func serveInstance(ln net.Listener, show func()) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Close()
		show()
	}
}

// instanceDir is per user, beside this application's settings.
func instanceDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("finding the configuration directory: %w", err)
	}
	return filepath.Join(base, appID), nil
}
