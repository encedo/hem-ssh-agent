//go:build windows

package main

// Windows without a working OpenGL 2.1 (a virtual machine without 3D
// acceleration, some remote desktops): Fyne's driver ends the whole process,
// tray and all, when it cannot create a window (os.Exit) or cannot link its
// shader programs (panic). So before Fyne starts, a hidden 1x1 window is
// created the way Fyne creates its windows (GLFW, OpenGL 2.1), one shader
// program is linked the way Fyne links them, and everything is torn down
// again; Fyne initialises GLFW afresh in Run.

import (
	"github.com/go-gl/gl/v2.1/gl"
	"github.com/go-gl/glfw/v3.4/glfw"
)

func openGLAvailable() bool {
	if err := glfw.Init(); err != nil {
		return false
	}
	defer glfw.Terminate()
	glfw.WindowHint(glfw.Visible, glfw.False)
	glfw.WindowHint(glfw.ContextVersionMajor, 2)
	glfw.WindowHint(glfw.ContextVersionMinor, 1)
	w, err := glfw.CreateWindow(1, 1, "probe", nil, nil)
	glfw.DefaultWindowHints()
	if err != nil {
		return false
	}
	defer w.Destroy()
	// A context alone is not enough: a broken driver (VirtualBox 3D after a
	// host reboot: "VMware: IOCTL failed -1: EPERM") gives one, then fails the
	// first program link with GL_OUT_OF_MEMORY and Fyne panics.
	w.MakeContextCurrent()
	defer glfw.DetachCurrentContext()
	return gl.Init() == nil && linkProbe()
}

// linkProbe compiles and links a trivial program and checks what Fyne's
// createProgramFromSource checks: the link status and glGetError.
func linkProbe() bool {
	vs := compileProbe(gl.VERTEX_SHADER, "#version 110\nattribute vec2 p;\nvoid main() { gl_Position = vec4(p, 0.0, 1.0); }\n\x00")
	fs := compileProbe(gl.FRAGMENT_SHADER, "#version 110\nvoid main() { gl_FragColor = vec4(1.0); }\n\x00")
	defer gl.DeleteShader(vs) // 0 is ignored
	defer gl.DeleteShader(fs)
	if vs == 0 || fs == 0 {
		return false
	}
	prog := gl.CreateProgram()
	defer gl.DeleteProgram(prog)
	gl.AttachShader(prog, vs)
	gl.AttachShader(prog, fs)
	gl.LinkProgram(prog)
	var ok int32
	gl.GetProgramiv(prog, gl.LINK_STATUS, &ok)
	return ok == gl.TRUE && gl.GetError() == gl.NO_ERROR
}

func compileProbe(kind uint32, src string) uint32 {
	s := gl.CreateShader(kind)
	if s == 0 {
		return 0
	}
	cs, free := gl.Strs(src)
	gl.ShaderSource(s, 1, cs, nil)
	free()
	gl.CompileShader(s)
	var ok int32
	gl.GetShaderiv(s, gl.COMPILE_STATUS, &ok)
	if ok != gl.TRUE {
		gl.DeleteShader(s)
		return 0
	}
	return s
}
