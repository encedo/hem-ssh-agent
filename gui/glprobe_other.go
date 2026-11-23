//go:build !windows

package main

// Linux and macOS: Mesa (llvmpipe) or the system's OpenGL is always there, so
// no probe (glprobe_windows.go is the exception).
func openGLAvailable() bool { return true }
