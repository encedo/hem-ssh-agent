package main

// From encedo-wg-hsm's gui/scale_linux.go (MIT, same author). On Linux Fyne
// sizes a pixel from the monitor's physical size only. A virtual monitor
// (Linux in a VM) reports 0 mm, so Fyne falls back to 1.0 while the desktop
// runs at, say, 2x (Xft.dpi 192) and the window comes out half size. This
// predicts Fyne's conclusion, compares it with Xft.dpi and sets FYNE_SCALE
// only for the difference; never over a FYNE_SCALE somebody set.

import (
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

const (
	baseDPI         = 96.0  // X11: Xft.dpi 96 means no scaling
	fyneBaselineDPI = 120.0 // Fyne's internal/driver/glfw/scale.go
)

func alignScaleWithDesktop() (string, bool) {
	// X11 - XWayland under a Wayland session - whenever there is a DISPLAY:
	// there the window can centre and raise itself (on native Wayland Fyne
	// cannot without an xdg-activation token, which a tray click does not
	// carry) and Fyne sizes it the way this file predicts. Fyne already does
	// this on GNOME; KDE, sway and the like would get native Wayland. Never
	// over a FYNE_PLATFORM somebody set.
	if os.Getenv("FYNE_PLATFORM") == "" && os.Getenv("DISPLAY") != "" {
		os.Setenv("FYNE_PLATFORM", "x11")
	}
	// Native Wayland, chosen explicitly: the compositor scales and Fyne's own
	// scale is 1 - nothing to correct (the X11 prediction made it 0.8x).
	if os.Getenv("FYNE_PLATFORM") == "wayland" {
		return "", false
	}
	if os.Getenv("FYNE_SCALE") != "" {
		return "", false
	}
	dpi, ok := xftDPI()
	if !ok {
		return "", false
	}
	widthMm, widthPx, ok := primaryMonitor()
	if !ok {
		return "", false
	}
	detected := fyneDetectedScale(widthMm, widthPx)
	if detected <= 0 {
		return "", false
	}
	correction := (dpi / baseDPI) / detected
	if correction > 0.9 && correction < 1.1 {
		return "", false
	}
	value := strconv.FormatFloat(correction, 'f', 2, 32)
	os.Setenv("FYNE_SCALE", value)
	return value, true
}

func fyneDetectedScale(widthMm, widthPx int) float64 {
	dpi := fyneBaselineDPI
	if widthMm > 0 {
		if d := float64(widthPx) / (float64(widthMm) / 25.4); d >= 10 && d <= 1000 {
			dpi = d
		}
	}
	if scale := dpi / fyneBaselineDPI; scale > 1 {
		return scale
	}
	return 1
}

var xftLine = regexp.MustCompile(`(?m)^Xft\.dpi:\s*([0-9.]+)`)

func xftDPI() (float64, bool) {
	out, err := exec.Command("xrdb", "-query").Output()
	if err != nil {
		return 0, false
	}
	m := xftLine.FindSubmatch(out)
	if m == nil {
		return 0, false
	}
	dpi, err := strconv.ParseFloat(string(m[1]), 64)
	if err != nil || dpi <= 0 {
		return 0, false
	}
	return dpi, true
}

var connectedLine = regexp.MustCompile(`^\S+ connected (?:primary )?(\d+)x\d+\+\d+\+\d+.*?(\d+)mm x \d+mm`)

// primaryMonitor: the primary display when one is marked, else the first
// connected one.
func primaryMonitor() (widthMm, widthPx int, ok bool) {
	out, err := exec.Command("xrandr", "--query").Output()
	if err != nil {
		return 0, 0, false
	}
	var first [2]int
	found := false
	for _, line := range strings.Split(string(out), "\n") {
		m := connectedLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		px, _ := strconv.Atoi(m[1])
		mm, _ := strconv.Atoi(m[2])
		if strings.Contains(line, " primary ") {
			return mm, px, true
		}
		if !found {
			first, found = [2]int{mm, px}, true
		}
	}
	if !found {
		return 0, 0, false
	}
	return first[0], first[1], true
}
