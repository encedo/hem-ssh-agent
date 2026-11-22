//go:build !linux

package main

// Windows and macOS report the display scale themselves (see scale_linux.go).
func alignScaleWithDesktop() (string, bool) { return "", false }
