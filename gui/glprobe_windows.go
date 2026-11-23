//go:build windows

package main

// Windows without OpenGL 2.1 (a virtual machine without 3D acceleration, some
// remote desktops): Fyne's driver ends the whole process (os.Exit) when it
// cannot create a window, tray and all. So before Fyne starts, a hidden 1x1
// window is created the way Fyne creates its windows (GLFW, OpenGL 2.1) and
// everything is torn down again; Fyne initialises GLFW afresh in Run.

import "github.com/go-gl/glfw/v3.4/glfw"

func openGLAvailable() bool {
	if err := glfw.Init(); err != nil {
		return false
	}
	defer glfw.Terminate()
	glfw.WindowHint(glfw.Visible, glfw.False)
	glfw.WindowHint(glfw.ContextVersionMajor, 2)
	glfw.WindowHint(glfw.ContextVersionMinor, 1)
	w, err := glfw.CreateWindow(1, 1, "probe", nil, nil)
	if err != nil {
		return false
	}
	w.Destroy()
	glfw.DefaultWindowHints()
	return true
}
