//go:build !linux

package main

// Windows and macOS always have a tray (tray_linux.go is the exception).
func trayAvailable() bool { return true }
