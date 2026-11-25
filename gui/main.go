// hem-ssh-agent-gui: the tray window for hem-ssh-agent.
//
// The agent (Rust, src/) holds no password and asks nobody anything; this
// window shows its state, tells the person when the phone is asking, and in
// password mode logs in to the HEM itself and hands the agent only a token.
// By default it keeps nothing: when the token expires new signs fail until it
// is unlocked again. "Remember the password" is the person's choice: the
// window then keeps the per-boot session secret made from the password and
// the HEM's spk (never the password; a HEM restart ends it)
// in memory and hands the agent a fresh token before each one expires, until
// Lock, an `ssh-add -x`, or Quit (docs/DESIGN.md, control channel).
//
// It also starts the agent when it is not running, so that logging on starts
// this window and the window starts the agent.
//
// Built on encedo-wg-hsm's gui (MIT, same author): Fyne, the tray, the
// single-instance doorbell, the pipe dial, the theme.
package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"

	hem "github.com/encedo/hem-sdk-go"
)

const (
	appID       = "com.encedo.hem-ssh-agent"
	windowTitle = "HEM SSH agent"
	// prefRemember: the old check box (true = until Lock), read once when
	// prefKeepFor is not set yet.
	prefRemember = "remember"
	// prefKeepFor: how long the password is remembered, seconds; 0 = not at
	// all, keepUntilLock = until Lock.
	prefKeepFor = "keep_for"
)

// keepUntilLock: remember the password until Lock (no time limit).
const keepUntilLock = -1 * time.Second

// keepChoices: the remember options of the window, in the order shown.
var keepChoices = []struct {
	label string
	d     time.Duration
}{
	{"Do not remember the password", 0},
	{"Remember the password for 15 minutes", 15 * time.Minute},
	{"Remember the password for 1 hour", time.Hour},
	{"Remember the password for 4 hours", 4 * time.Hour},
	{"Remember the password until Lock", keepUntilLock},
}

//go:embed icon.svg
var iconSVG []byte

// iconPNG: the window's own icon - a raster, since X11 window managers read
// _NET_WM_ICON, which stayed empty with the SVG (Vostro, 2026-11-24).
//
//go:embed icon.png
var iconPNG []byte

type ui struct {
	app  fyne.App
	desk desktop.App
	// menu: the one tray menu for the whole run - Fyne keeps the first one it
	// was given and renders it again when the tray registers, so only its
	// items change.
	menu *fyne.Menu
	// trayUp: a tray host shows the icon, so closing the window hides it;
	// without one closing the window quits (UI goroutine only).
	trayUp bool
	// win: made at the first present (build), never before - see present.
	win     fyne.Window
	control string
	// agentArgs start the agent (`run` and what it needs); nil: never start it.
	agentArgs []string

	mu      sync.Mutex
	last    Status // the latest snapshot
	seen    bool   // a snapshot has arrived on this connection
	down    string // why the agent cannot be reached, "" when it can
	started bool   // this window has tried to start the agent

	// Remember the password: the client holding the session secret, and the
	// renewal timer. keep is nil unless the person chose it. keepUntil: when
	// the remembering ends by itself (zero: at Lock); keepTimer ends it then.
	keep      *hem.Client
	keepUntil time.Time
	keepTimer *time.Timer
	renewAt   int64
	timer     *time.Timer
	failing   bool
	handOver  sync.Mutex // a token hand-over and Lock never interleave
	// expiry draws the state again when the token runs out: the agent sends no
	// snapshot then (UI goroutine only).
	expiry *time.Timer

	// noGL: no OpenGL here (a virtual machine without 3D, some remote
	// desktops) - Fyne cannot open a window, so none is ever shown.
	noGL bool

	pass     *widget.Entry
	remember *widget.Select
	info     *widget.Label
	// message: the outcome of the last Unlock, under the state; it replaces
	// the one before and goes when the window is shown again (UI goroutine).
	message string
	unlock  *widget.Button
	lockBtn *widget.Button
	// addr: the HEM's address - the agent's, or typed for Choose keys;
	// addrShown is what was last put there, so a typed one is not overwritten.
	addr      *widget.Entry
	addrShown string
	keysBtn   *widget.Button
	phoneBtn  *widget.Button
	busy      bool // Choose keys is listing (UI goroutine)
}

func main() {
	control := flag.String("control", defaultControl, "the agent's control channel (pipe or socket)")
	config := flag.String("config", "", "the agent's configuration file, passed on when this window starts the agent")
	noStart := flag.Bool("no-start", false, "never start the agent; only follow one that runs")
	themeName := flag.String("theme", "auto", "auto, dark or light")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	th, err := themeFor(*themeName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	alignScaleWithDesktop()
	// Before Fyne starts: a window Fyne cannot create ends the whole process
	// (os.Exit in its driver), tray and all.
	noGL := !openGLAvailable()

	a := app.NewWithID(appID)
	a.Settings().SetTheme(th)
	icon := fyne.NewStaticResource("icon.svg", iconSVG)
	a.SetIcon(icon)
	u := &ui{app: a, control: *control, noGL: noGL}
	if !*noStart {
		u.agentArgs = agentArgs(*config, *control)
	}

	if dir, err := instanceDir(); err == nil {
		ln, handedOver, err := claimInstance(dir)
		if handedOver {
			return // the running window shows itself
		}
		if err == nil {
			go serveInstance(ln, func() { fyne.Do(u.present) })
		}
	}

	desk, hasDesk := a.(desktop.App)
	if hasDesk {
		// Always before Run: Fyne starts its tray only there (a first tray
		// menu set later never shows, and Quit then crashes). A tray host that
		// registers later picks the icon up by itself (systray re-registers
		// with the watcher); trayAvailable only decides about the window.
		u.useTray(desk, icon)
	}
	if hasDesk && trayAvailable() {
		u.trayUp = true
	} else {
		u.present() // no tray: the window is the only way in
		if hasDesk {
			go u.waitForTray()
		}
	}
	if noGL {
		u.notify("No window", noWindowHelp)
	}
	go u.follow()
	a.Run()
}

const noWindowHelp = "This computer has no OpenGL (a virtual machine without 3D acceleration, " +
	"some remote desktops), so the window cannot open. The tray menu works; unlock with " +
	"ssh-add -X in a terminal (it asks for the HEM password)."

func (u *ui) useTray(desk desktop.App, icon fyne.Resource) {
	u.desk = desk
	u.desk.SetSystemTrayIcon(icon)
	u.renderMenu()
}

// waitForTray: a tray host that registers after this window started (a
// login autostart racing the desktop) shows the icon by itself; from then on
// closing the window hides it instead of quitting - asked every few seconds
// for two minutes. Until then the window is the way in.
func (u *ui) waitForTray() {
	for range 40 {
		time.Sleep(3 * time.Second)
		if trayAvailable() {
			fyne.Do(func() { u.trayUp = true })
			return
		}
	}
}

// agentArgs: `[--config FILE] run [--control ADDR]`; the control address
// only when it was given here, otherwise the agent's own default or file.
func agentArgs(config, control string) []string {
	var args []string
	if config != "" {
		if abs, err := filepath.Abs(config); err == nil {
			config = abs
		}
		args = append(args, "--config", config)
	}
	args = append(args, "run")
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "control" {
			args = append(args, "--control", control)
		}
	})
	return args
}

// build makes the unlock window. With a tray it is shown from the tray and
// hidden, not closed, so the application keeps running; without one (yet) it
// is the application (closeWindow).
func (u *ui) build() {
	u.win = u.app.NewWindow(windowTitle)
	u.win.SetIcon(fyne.NewStaticResource("icon.png", iconPNG))
	u.pass = widget.NewPasswordEntry()
	u.pass.SetPlaceHolder("HEM password")
	labels := make([]string, len(keepChoices))
	for i, c := range keepChoices {
		labels[i] = c.label
	}
	u.remember = widget.NewSelect(labels, func(label string) {
		u.app.Preferences().SetInt(prefKeepFor, int(keepFor(label)/time.Second))
	})
	u.remember.SetSelected(keepLabel(u.savedKeepFor()))
	hint := widget.NewLabel("Remembering keeps a session secret made from the password in this window (a HEM restart ends it) and renews the agent's token by itself until the time is up. Otherwise unlock again when the token expires.")
	hint.Wrapping = fyne.TextWrapWord
	hint.Importance = widget.LowImportance
	u.info = widget.NewLabel("")
	u.info.Wrapping = fyne.TextWrapWord
	// The window never changes size (owner: constant width and height): the
	// state and messages scroll inside a box of six lines.
	infoBox := container.NewVScroll(u.info)
	infoBox.SetMinSize(fyne.NewSize(0, widget.NewLabel("1\n2\n3\n4\n5\n6").MinSize().Height))
	// "with password": beside Unlock by phone, a bare "Unlock" was taken for the phone's
	u.unlock = widget.NewButton("Unlock with password", u.onUnlock)
	u.unlock.Importance = widget.HighImportance
	u.lockBtn = widget.NewButton("Lock", u.onLock)
	// Enter: Unlock, or - not set up yet - Choose keys.
	u.pass.OnSubmitted = func(string) {
		if s, seen, _ := u.snapshot(); seen && !canUnlock(s) && canChoose(s) {
			u.onChooseKeys()
			return
		}
		u.onUnlock()
	}
	// Always shown (owner): the configuration's address greyed out, or the
	// one to list keys from.
	u.addr = widget.NewEntry()
	u.addr.SetPlaceHolder("HEM address: https://...")
	u.keysBtn = widget.NewButton("Choose keys...", u.onChooseKeys)
	u.phoneBtn = widget.NewButton("Unlock by phone", u.onUnlockPhone)
	u.win.SetContent(container.NewVBox(infoBox, u.addr, u.pass, u.remember, hint,
		container.NewGridWithColumns(2, u.lockBtn, u.unlock),
		container.NewGridWithColumns(2, u.phoneBtn, u.keysBtn)))
	u.win.SetFixedSize(true) // a small dialog: no maximise, no resize
	u.win.Resize(fyne.NewSize(400, 0))
	u.win.SetCloseIntercept(u.closeWindow)
}

// savedKeepFor: the remember choice from the preferences; the old check box
// (until Lock) when there is none yet.
func (u *ui) savedKeepFor() time.Duration {
	p := u.app.Preferences()
	if s := p.IntWithFallback(prefKeepFor, -2); s != -2 {
		return time.Duration(s) * time.Second
	}
	if p.BoolWithFallback(prefRemember, false) {
		return keepUntilLock
	}
	return 0
}

func keepFor(label string) time.Duration {
	for _, c := range keepChoices {
		if c.label == label {
			return c.d
		}
	}
	return 0
}

func keepLabel(d time.Duration) string {
	for _, c := range keepChoices {
		if c.d == d {
			return c.label
		}
	}
	return keepChoices[0].label
}

func (u *ui) present() {
	if u.noGL {
		u.notify("No window", noWindowHelp)
		return
	}
	if u.win == nil {
		// Made only now: Fyne applies a settings change (any Fyne app's first
		// start touches its settings directory) to every window, and on
		// Windows a window that was never shown crashes it (setDarkMode on a
		// nil native window).
		u.build()
	}
	u.message = ""
	u.renderWindow()
	// Centred - otherwise left to the window manager. A no-op on native
	// Wayland, where the window cannot place or raise itself (gui/README.md).
	u.win.CenterOnScreen()
	u.win.Show()
	u.win.RequestFocus()
	u.win.Canvas().Focus(u.pass)
}

// do runs f on the UI goroutine; directly when there is no UI (the live test).
func (u *ui) do(f func()) {
	if u.app == nil {
		f()
		return
	}
	fyne.Do(f)
}

// follow keeps a watch on the agent, reconnecting while it is not running,
// and starts it the first time it is found not running.
func (u *ui) follow() {
	for {
		err := watch(context.Background(), u.control, func(s Status) { u.do(func() { u.apply(s) }) })
		msg := "the agent is not running"
		var ar *agentRefused
		if errors.As(err, &ar) && ar.kind == "build" {
			log.Printf("hem-ssh-agent-gui: watch: %v", err)
			msg = "the window and the agent are different versions - update both"
		} else if err != nil && !isDialError(err) {
			log.Printf("hem-ssh-agent-gui: watch: %v", err)
			msg = "the connection to the agent was lost"
		} else if u.agentArgs != nil {
			u.mu.Lock()
			first := !u.started
			u.started = true
			u.mu.Unlock()
			if first {
				u.startAgent()
				time.Sleep(time.Second)
				continue
			}
		}
		u.do(func() { u.lost(msg) })
		time.Sleep(3 * time.Second)
	}
}

func isDialError(err error) bool {
	s := err.Error()
	return strings.Contains(s, "cannot find the file") || strings.Contains(s, "no such file") ||
		strings.Contains(s, "connection refused") || errors.Is(err, context.DeadlineExceeded)
}

// startAgent starts the agent detached; it outlives this window. An agent
// that stops at once (a bad configuration) says why in its log.
func (u *ui) startAgent() {
	cmd, err := agentCommand(u.agentArgs)
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		log.Printf("hem-ssh-agent-gui: starting the agent: %v", err)
		u.do(func() {
			u.notify("The agent did not start", "The agent program could not be started - is it installed next to this window?")
		})
		return
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	go func() {
		select {
		case err := <-done:
			if err != nil {
				log.Printf("hem-ssh-agent-gui: the agent stopped: %v", err)
				u.do(func() { u.notify("The agent stopped", "It stopped at once - Show log says why.") })
			}
		case <-time.After(5 * time.Second):
		}
	}()
}

func (u *ui) onStartAgent() {
	if u.agentArgs == nil {
		return
	}
	go u.startAgent()
}

func (u *ui) lost(why string) {
	u.mu.Lock()
	changed := u.down != why
	u.down, u.seen = why, false
	u.mu.Unlock()
	if changed {
		u.renderMenu()
		u.renderWindow()
	}
}

// apply takes a snapshot and says what changed that a person should know.
func (u *ui) apply(s Status) {
	u.mu.Lock()
	prev, had := u.last, u.seen
	u.last, u.seen, u.down = s, true, ""
	u.mu.Unlock()

	remembering := u.keepUp(prev, had, s)
	if had {
		switch {
		case s.Pending != nil && (prev.Pending == nil || prev.Pending.Since != s.Pending.Since):
			if s.Auth == "remote+password" {
				u.notify("Approve on your phone", s.Pending.Note+"\nNo phone at hand: Use password in the tray menu.")
			} else {
				u.notify("Approve on your phone", s.Pending.Note)
			}
		case s.Last != nil && (prev.Last == nil || *prev.Last != *s.Last):
			u.notifyResult(*s.Last, prev.Pending)
		case prev.State != "locked" && s.State == "locked" && s.Auth == "password" && !remembering:
			u.notify("Locked", "The token has expired or the agent was locked. Unlock to sign again.")
		}
	}
	u.watchExpiry(s.ExpiresAt)
	u.renderMenu()
	u.renderWindow()
}

// watchExpiry: one redraw just after the token's expiry (UI goroutine).
func (u *ui) watchExpiry(at int64) {
	if u.expiry != nil {
		u.expiry.Stop()
		u.expiry = nil
	}
	if at <= 0 {
		return
	}
	u.expiry = time.AfterFunc(max(0, time.Until(time.Unix(at, 0)))+time.Second, func() {
		u.do(func() {
			u.renderMenu()
			u.renderWindow()
		})
	})
}

// current: the snapshot as it stands now - a token past its expiry is gone
// (the agent sends no snapshot when it runs out).
func current(s Status) Status {
	if s.ExpiresAt > 0 && time.Now().Unix() >= s.ExpiresAt {
		s.ExpiresAt, s.Source = 0, ""
		if s.Auth == "password" && s.State == "ready" {
			s.State = "locked"
		}
	}
	return s
}

// keepUp keeps the agent unlocked while the password is remembered: a
// renewal before each token expires, at once after an expiry or an agent
// restart. A lock before the token ran out (ssh-add -x, another window) is
// taken as meant: the session secret is dropped. Reports whether it is still
// remembered.
func (u *ui) keepUp(prev Status, had bool, s Status) bool {
	if !u.remembering() {
		return false
	}
	if !passwordAllowed(s) {
		u.forget()
		return false
	}
	// No token: "locked" in password mode; with the phone first the state
	// stays "ready" (or "waiting": the phone is being asked) without one.
	switch {
	case s.ExpiresAt > 0 && s.State != "locked":
		u.scheduleRenew(s.ExpiresAt - renewMargin(s.TTL))
	case s.State == "locked" || s.Auth == "remote+password":
		if had && prev.ExpiresAt > 0 && time.Now().Unix() < prev.ExpiresAt-5 {
			u.forget()
			u.notify("Locked", "The agent was locked; the remembered password is forgotten. Unlock to sign again.")
			return false
		}
		u.scheduleRenew(time.Now().Unix())
	}
	return true
}

// renewMargin: how long before the token's expiry a new one is handed over -
// a fifth of the lifetime, between 10 s and a minute.
func renewMargin(ttl int) int64 {
	m := int64(ttl / 5)
	return max(10, min(60, m))
}

func (u *ui) remembering() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.keep != nil
}

func (u *ui) scheduleRenew(at int64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.keep == nil || u.renewAt == at {
		return
	}
	if !u.keepUntil.IsZero() && !time.Unix(at, 0).Before(u.keepUntil) {
		return // the remembered time ends first (keepTimer)
	}
	u.renewAt = at
	if u.timer != nil {
		u.timer.Stop()
	}
	u.timer = time.AfterFunc(max(0, time.Until(time.Unix(at, 0))), u.renew)
}

// renew mints a token with the remembered key and hands it over. A failure
// says so once and tries again every 30 s; a HEM that wants the password
// again (another device, a restarted window) ends the remembering.
func (u *ui) renew() {
	u.mu.Lock()
	c, s := u.keep, u.last
	u.mu.Unlock()
	if c == nil {
		return
	}
	_, err := u.handOverToken(c, s, nil)
	var he *hem.HemError
	switch {
	case err == nil:
		u.mu.Lock()
		u.failing = false
		u.mu.Unlock()
	case errors.As(err, &he) && he.Code == "auth_password_required":
		u.forget()
		u.do(func() {
			u.notify("Unlock again", "The HEM needs the password again.")
			u.renderMenu()
			u.renderWindow()
		})
	case errors.Is(err, errForgotten):
	default:
		u.mu.Lock()
		first := !u.failing
		u.failing = true
		if u.keep == c {
			u.renewAt = 0
			u.timer = time.AfterFunc(30*time.Second, u.renew)
		}
		u.mu.Unlock()
		if first {
			msg := humanError(err)
			u.do(func() { u.notify("Token not renewed", msg+"\nTrying again every 30 s.") })
		}
	}
}

// forget drops the remembered key and stops renewing.
func (u *ui) forget() {
	u.mu.Lock()
	c := u.keep
	u.keep, u.renewAt, u.failing, u.keepUntil = nil, 0, false, time.Time{}
	if u.timer != nil {
		u.timer.Stop()
		u.timer = nil
	}
	if u.keepTimer != nil {
		u.keepTimer.Stop()
		u.keepTimer = nil
	}
	u.mu.Unlock()
	if c != nil {
		c.ClearKeys()
	}
}

func (u *ui) notifyResult(l Last, waited *Pending) {
	// Failures always; a success only when the phone was asked, so a git
	// fetch with a live token does not raise a notification.
	switch {
	case l.Result == "unlocked":
		u.notify("Unlocked by phone", l.Note)
	case l.Result == "signed":
		if waited != nil && !waited.Password {
			u.notify("Approved", l.Note)
		}
	case l.Result == "denied":
		u.notify("Refused on the phone", l.Note)
	case l.Result == "timeout" && waited != nil && waited.Password:
		u.notify("No password given in time", l.Note)
	case l.Result == "timeout":
		u.notify("No answer from the phone", l.Note)
	case l.Result == "locked":
		u.notify("Locked - not signed", l.Note+"\nUnlock from the tray icon.")
	default:
		u.notify("Not signed", l.Note)
	}
}

func (u *ui) notify(title, body string) {
	if u.app == nil {
		return
	}
	u.app.SendNotification(fyne.NewNotification(windowTitle+": "+title, body))
}

func (u *ui) snapshot() (Status, bool, string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return current(u.last), u.seen, u.down
}

func (u *ui) stateLine() string {
	s, seen, down := u.snapshot()
	switch {
	case down != "":
		return "Agent: " + down
	case !seen:
		return "Agent: connecting..."
	case s.State == "unconfigured" && s.URL == "":
		return "Not set up - enter the HEM's address and choose its keys"
	case s.State == "unconfigured":
		return "Not set up - choose the HEM's keys"
	case s.State == "waiting" && s.Pending != nil && s.Pending.Password:
		return "Waiting for the password"
	case s.State == "waiting":
		return "Waiting for the phone"
	case s.State == "locked":
		return "Locked"
	case s.ExpiresAt > 0 && u.remembering():
		// Renewed by this window: only the end of the remembering counts.
		return "Ready " + u.rememberedUntil() + " (password)"
	case s.ExpiresAt > 0:
		return "Ready until " + time.Unix(s.ExpiresAt, 0).Format("15:04") + u.tokenOrigin(s)
	case s.Kept:
		return "Ready - the password is kept until Lock"
	case u.remembering():
		return "Ready - the password is remembered " + u.rememberedUntil()
	case s.Auth == "remote" || s.Auth == "remote+password":
		return "Ready - the phone approves"
	default:
		return "Ready"
	}
}

// tokenOrigin: where the token came from and what comes after it, for the
// state line.
func (u *ui) tokenOrigin(s Status) string {
	switch {
	case s.Kept:
		return " (password, kept until Lock)"
	case s.Source != "":
		return " (" + s.Source + ")"
	}
	return ""
}

// rememberedUntil: "until Lock" or "until 15:04", the end of the remembering.
func (u *ui) rememberedUntil() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.keepUntil.IsZero() {
		return "until Lock"
	}
	return "until " + u.keepUntil.Format("15:04")
}

// canLock: Lock does something now - a token, a wait for the phone or the
// password, a session secret the agent keeps, or a password this window
// remembers. In the phone modes the agent is "ready" without any of them.
func (u *ui) canLock(s Status, seen bool) bool {
	return seen && (s.ExpiresAt > 0 || s.Pending != nil || s.Kept || u.remembering())
}

func (u *ui) renderMenu() {
	if u.desk == nil {
		return
	}
	s, seen, down := u.snapshot()
	state := fyne.NewMenuItem(u.stateLine(), nil)
	state.Disabled = true
	items := []*fyne.MenuItem{state, fyne.NewMenuItemSeparator()}
	if down != "" && u.agentArgs != nil {
		items = append(items, fyne.NewMenuItem("Start the agent", u.onStartAgent))
	}
	if seen && s.Auth == "remote+password" && s.Pending != nil && !s.Pending.Password {
		// No phone at hand: stop asking it, unlock with the password instead.
		items = append(items, fyne.NewMenuItem("Use password...", u.onUsePassword))
	}
	// One item that follows the state (owner): Lock while there is something
	// to lock - a token, a wait (it cancels), a kept or remembered secret -
	// otherwise Unlock... when that does something.
	switch {
	case seen && s.State == "unconfigured" && canChoose(s):
		items = append(items, fyne.NewMenuItem("Choose keys...", u.present))
	case u.canLock(s, seen):
		items = append(items, fyne.NewMenuItem("Lock", u.onLock))
	case seen && canUnlock(s):
		items = append(items, fyne.NewMenuItem("Unlock...", u.present))
	}
	// Show: the window at any time, also while unlocked (state, Lock).
	items = append(items, fyne.NewMenuItem("Show", u.present), fyne.NewMenuItem("Show log", u.onLog))
	// Fyne adds Quit only to the first tray menu it renders, not to the ones
	// set later: so here, every time.
	quit := fyne.NewMenuItem("Quit", u.app.Quit)
	quit.IsQuit = true
	items = append(items, fyne.NewMenuItemSeparator(), quit)
	if u.menu == nil {
		u.menu = fyne.NewMenu(windowTitle)
	}
	u.menu.Items = items
	u.desk.SetSystemTrayMenu(u.menu)
}

func (u *ui) renderWindow() {
	if u.info == nil {
		return
	}
	s, seen, _ := u.snapshot()
	text := u.stateLine()
	if seen && s.URL != "" {
		text += "\n" + s.URL
	}
	for _, k := range s.Keys {
		text += "\n• " + k.Comment
	}
	if u.message != "" {
		text += "\n\n" + u.message
	}
	u.info.SetText(text)
	// The address: the agent's, unless the person has typed another one.
	if u.addr.Text == u.addrShown && s.URL != u.addrShown {
		u.addr.SetText(s.URL)
		u.addrShown = s.URL
	}
	enable(u.addr, seen && !s.URLFixed && canChoose(s) && !u.busy)
	enable(u.unlock, seen && canUnlock(s))
	enable(u.remember, seen && canUnlock(s))
	// The password also lists the keys (Choose keys), so not only to unlock.
	enable(u.pass, seen && passwordAllowed(s) && (canUnlock(s) || canChoose(s)))
	enable(u.lockBtn, u.canLock(s, seen))
	enable(u.keysBtn, seen && canChoose(s) && !u.busy)
	enable(u.phoneBtn, seen && canUnlockPhone(s))
}

func enable(w fyne.Disableable, on bool) {
	if on {
		w.Enable()
	} else {
		w.Disable()
	}
}

func (u *ui) onUnlock() {
	s, seen, _ := u.snapshot()
	if !seen || !passwordAllowed(s) || !canUnlock(s) {
		return // the button is disabled then
	}
	if u.pass.Text == "" {
		u.message = humanError(errNoPassword)
		u.renderWindow()
		return
	}
	pass := []byte(u.pass.Text)
	keep := keepFor(u.remember.Selected)
	u.pass.SetText("")
	u.unlock.Disable()
	u.message = ""
	u.info.SetText("Logging in to the HEM...")
	go func() {
		exp, err := u.login(s, pass, keep)
		fyne.Do(func() {
			if err != nil {
				u.message = "Not unlocked: " + humanError(err)
				u.renderWindow()
				return
			}
			u.win.Hide()
			if keep != 0 {
				u.notify("Unlocked", "Signing "+u.rememberedUntil()+"; the token is renewed by this window.")
			} else {
				u.notify("Unlocked", "Signing until "+exp.Format("15:04"))
			}
		})
	}()
}

// login gets a token for every key the agent serves and hands it over. With
// keep 0 the session secret is dropped at once and nothing here can mint
// another; otherwise it is kept for keep (keepUntilLock: until Lock) and the
// token renewed meanwhile. When that time is up the window forgets it and
// stops renewing: the last token runs out, then the agent asks again (the
// phone, or the password).
func (u *ui) login(s Status, pass []byte, keep time.Duration) (time.Time, error) {
	defer clear(pass)
	if s.URL == "" || len(s.Keys) == 0 {
		return time.Time{}, errors.New("the agent did not say which HEM or keys")
	}
	// No token cache: every renewal is a fresh token from the HEM.
	c := hem.NewClient(s.URL, hem.Config{DisableTokenCache: true})
	u.forget() // a new login replaces whatever was remembered
	exp, err := u.handOverToken(c, s, pass)
	if err != nil || keep == 0 {
		c.ClearKeys()
		return exp, err
	}
	u.mu.Lock()
	u.keep = c
	if keep > 0 {
		u.keepUntil = time.Now().Add(keep)
		u.keepTimer = time.AfterFunc(keep, func() { u.keepEnded(c) })
	}
	u.mu.Unlock()
	u.scheduleRenew(exp.Unix() - renewMargin(s.TTL))
	return exp, nil
}

// keepEnded: the remembered time is up - forget the password (the token
// handed over last runs out by itself).
func (u *ui) keepEnded(c *hem.Client) {
	u.mu.Lock()
	still := u.keep == c
	u.mu.Unlock()
	if !still {
		return
	}
	u.forget()
	u.do(func() {
		u.notify("Password forgotten", "The remembered time is over. When the current token runs out the agent asks again.")
		u.renderMenu()
		u.renderWindow()
	})
}

var errForgotten = errors.New("the remembered password was forgotten meanwhile")

// handOverToken: check-in, a token for the agent's keys (pass nil: from the
// remembered key), and the hand-over.
func (u *ui) handOverToken(c *hem.Client, s Status, pass []byte) (time.Time, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// Check-in first, it sets the HEM clock; a HEM behind an air gap works without it.
	_ = c.Checkin(ctx)
	scopes := make([]string, len(s.Keys))
	for i, k := range s.Keys {
		scopes[i] = "keymgmt:use:" + k.Kid
	}
	ttl := s.TTL
	if ttl <= 0 {
		ttl = 300
	}
	tok, err := c.AuthPasswordScopes(ctx, pass, scopes, ttl)
	if err != nil {
		return time.Time{}, err
	}
	u.handOver.Lock()
	defer u.handOver.Unlock()
	if pass == nil {
		// A renewal: not after a Lock that came in meanwhile.
		u.mu.Lock()
		still := u.keep == c
		u.mu.Unlock()
		if !still {
			return time.Time{}, errForgotten
		}
	}
	if _, err := ask(ctx, u.control, Request{Op: "token", Build: currentBuild(), Token: tok}); err != nil {
		return time.Time{}, fmt.Errorf("handing the token to the agent: %w", err)
	}
	return hem.TokenExpiry(tok), nil
}

// onUsePassword: the phone is not at hand. The agent stops asking it (the
// request is withdrawn) and the waiting sign takes the token this window
// hands over after Unlock.
func (u *ui) onUsePassword() {
	u.present()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := ask(ctx, u.control, Request{Op: "use_password"}); err != nil {
			msg := humanError(err)
			u.do(func() { u.notify("The phone is still asked", msg) })
		}
	}()
}

// onUnlockPhone: the agent asks the phone for a token now, so that the next
// ssh does not wait for it (remote modes).
func (u *ui) onUnlockPhone() {
	u.phoneBtn.Disable()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := ask(ctx, u.control, Request{Op: "unlock_phone"})
		u.do(func() {
			if err != nil {
				u.message = "Not asked: " + humanError(err)
			} else {
				u.message = "Approve on your phone."
			}
			u.renderWindow()
		})
	}()
}

// onChooseKeys finds the HEM's SSH keys - without a login when the HEM
// allows it, otherwise with the password typed or approved on the phone -
// and lets the person pick the ones to serve.
func (u *ui) onChooseKeys() {
	s, seen, _ := u.snapshot()
	if !seen || !canChoose(s) || u.busy {
		return
	}
	addr := strings.TrimSpace(u.addr.Text)
	if s.URLFixed {
		addr = s.URL
	}
	if !isHTTPS(addr) {
		u.message = "The HEM address must start with https://"
		u.renderWindow()
		return
	}
	var pass []byte
	if passwordAllowed(s) && u.pass.Text != "" {
		pass = []byte(u.pass.Text)
	}
	u.pass.SetText("")
	ks := newKeySession(addr, pass, s.Auth == "remote" || s.Auth == "remote+password")
	u.busy = true
	u.message = ""
	u.renderWindow()
	u.info.SetText("Looking for the HEM's SSH keys...")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		keys, err := ks.search(ctx)
		fyne.Do(func() {
			if err != nil {
				ks.close()
				u.busy = false
				u.message = "Keys not listed: " + keysError(err)
				u.renderWindow()
				return
			}
			u.pickKeys(ks, addr, s, keys)
		})
	}()
}

// keysError: humanError, plus what only Choose keys runs into.
func keysError(err error) string {
	switch {
	case errors.Is(err, errNoSSHKeys):
		return "The HEM has no SSH keys for this agent."
	case errors.Is(err, errPasswordNeeded):
		return "The HEM wants a login - type the HEM password and choose again."
	}
	return humanError(err)
}

// pickKeys: the list, at most maxKeys ticked; the keys served now are ticked
// to start with when they are from this HEM. ks is closed when it ends.
func (u *ui) pickKeys(ks *keySession, addr string, s Status, keys []hemKey) {
	byLabel := make(map[string]hemKey, len(keys))
	labels := make([]string, len(keys))
	served := map[string]bool{}
	if addr == s.URL {
		for _, k := range s.Keys {
			served[k.Kid] = true
		}
	}
	var ticked []string
	for i, k := range keys {
		labels[i] = choiceLabel(k)
		byLabel[labels[i]] = k
		if served[k.KID] {
			ticked = append(ticked, labels[i])
		}
	}
	list := widget.NewCheckGroup(labels, nil)
	list.SetSelected(ticked)
	note := widget.NewLabel(fmt.Sprintf("Up to %d keys; ssh and git offer them in this order.", maxKeys))
	note.Wrapping = fyne.TextWrapWord
	note.Importance = widget.LowImportance
	content := container.NewBorder(note, nil, nil, nil, container.NewVScroll(list))
	d := dialog.NewCustomConfirm("Choose keys", "Use these", "Cancel", content, func(ok bool) {
		var picked []hemKey
		for _, l := range labels { // the list's order, not the order of the ticks
			for _, t := range list.Selected {
				if t == l {
					picked = append(picked, byLabel[l])
				}
			}
		}
		switch {
		case !ok:
			u.message = ""
		case len(picked) == 0:
			u.message = "No key chosen - nothing changed."
		case len(picked) > maxKeys:
			u.message = fmt.Sprintf("At most %d keys - nothing changed.", maxKeys)
		default:
			u.saveChoice(ks, s.Chosen, addr, picked)
			return
		}
		ks.close()
		u.busy = false
		u.renderWindow()
	}, u.win)
	// Inside the window, which keeps its size.
	cs := u.win.Canvas().Size()
	d.Resize(fyne.NewSize(cs.Width-24, cs.Height-24))
	d.Show()
}

// saveChoice reads the public keys the search left out (a login for the keys
// picked), writes chosen.toml and has the agent read it.
func (u *ui) saveChoice(ks *keySession, path, addr string, keys []hemKey) {
	u.info.SetText("Reading the chosen keys...")
	go func() {
		defer ks.close()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		msg := ""
		if tok, err := ks.complete(ctx, keys); err != nil {
			msg = "Keys not read: " + keysError(err)
		} else if err := writeChosen(path, addr, keys); err != nil {
			log.Printf("hem-ssh-agent-gui: writing %s: %v", path, err)
			msg = "The choice could not be saved."
		} else if _, err := ask(ctx, u.control, Request{Op: "reload"}); err != nil {
			msg = "Saved, but the agent did not take it: " + humanError(err)
		} else {
			msg = fmt.Sprintf("%d key(s) chosen - the agent serves them now.", len(keys))
			// The login that read the keys holds the scopes the agent signs
			// with: handed over, the first ssh needs no second approval.
			// Refused (expired, keys fixed in the configuration): the agent
			// stays locked, as before.
			if tok != "" {
				if _, err := ask(ctx, u.control, Request{Op: "token", Build: currentBuild(), Token: tok, Source: ks.source()}); err != nil {
					log.Printf("hem-ssh-agent-gui: the keys' token not handed over: %v", err)
				} else {
					msg += " Unlocked."
				}
			}
		}
		u.do(func() {
			u.busy = false
			u.message = msg
			u.renderWindow()
		})
	}()
}

// closeWindow: hidden, not closed (the tray keeps the application); without a
// tray (yet) the window is the application and closing it quits. Closed
// while a sign waits for the password: that sign ends unsigned at once, as
// with Lock, instead of waiting out its time.
func (u *ui) closeWindow() {
	if !u.trayUp {
		u.app.Quit()
		return
	}
	u.win.Hide()
	if s, seen, _ := u.snapshot(); seen && s.Pending != nil && s.Pending.Password {
		u.onLock()
	}
}

// onLock locks the agent and forgets a remembered password.
func (u *ui) onLock() {
	go func() {
		u.handOver.Lock()
		defer u.handOver.Unlock()
		u.forget()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := ask(ctx, u.control, Request{Op: "lock"}); err != nil {
			msg := humanError(err)
			u.do(func() { u.notify("Not locked", msg) })
		}
		u.do(func() {
			u.renderMenu()
			u.renderWindow()
		})
	}()
}

func (u *ui) onLog() {
	p := filepath.ToSlash(agentLog())
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if err := u.app.OpenURL(&url.URL{Scheme: "file", Path: p}); err != nil {
		u.notify("Log", agentLog())
	}
}
