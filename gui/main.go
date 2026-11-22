// hem-ssh-agent-gui: the tray window for hem-ssh-agent.
//
// The agent (Rust, src/) holds no password and asks nobody anything; this
// window shows its state, tells the person when the phone is asking, and in
// password mode logs in to the HEM itself and hands the agent only a token.
// By default it keeps nothing: when the token expires new signs fail until it
// is unlocked again. "Remember the password" is the person's choice: the
// window then keeps the key derived from the password (never the password)
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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"

	hem "github.com/encedo/hem-sdk-go"
)

const (
	appID        = "com.encedo.hem-ssh-agent"
	windowTitle  = "HEM SSH agent"
	prefRemember = "remember"
)

//go:embed icon.svg
var iconSVG []byte

type ui struct {
	app     fyne.App
	desk    desktop.App
	win     fyne.Window
	control string
	// agentArgs start the agent (`run` and what it needs); nil: never start it.
	agentArgs []string

	mu      sync.Mutex
	last    Status // the latest snapshot
	seen    bool   // a snapshot has arrived on this connection
	down    string // why the agent cannot be reached, "" when it can
	started bool   // this window has tried to start the agent

	// Remember the password: the client holding the derived key, and the
	// renewal timer. keep is nil unless the person chose it.
	keep     *hem.Client
	renewAt  int64
	timer    *time.Timer
	failing  bool
	handOver sync.Mutex // a token hand-over and Lock never interleave

	pass     *widget.Entry
	remember *widget.Check
	info     *widget.Label
	unlock   *widget.Button
	lockBtn  *widget.Button
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

	a := app.NewWithID(appID)
	a.Settings().SetTheme(th)
	icon := fyne.NewStaticResource("icon.svg", iconSVG)
	a.SetIcon(icon)
	u := &ui{app: a, control: *control}
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

	tray := false
	if desk, ok := a.(desktop.App); ok && trayAvailable() {
		u.desk, tray = desk, true
	}
	u.build(tray)
	if tray {
		u.desk.SetSystemTrayIcon(icon)
		u.renderMenu()
	} else {
		u.present() // no tray: the window is the only way in
	}
	go u.follow()
	a.Run()
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
// hidden, not closed, so the application keeps running; without one it is
// the application.
func (u *ui) build(tray bool) {
	u.win = u.app.NewWindow(windowTitle)
	u.pass = widget.NewPasswordEntry()
	u.pass.SetPlaceHolder("HEM password")
	u.remember = widget.NewCheck("Remember the password until Lock", func(on bool) {
		u.app.Preferences().SetBool(prefRemember, on)
	})
	u.remember.SetChecked(u.app.Preferences().BoolWithFallback(prefRemember, false))
	hint := widget.NewLabel("Keeps the key derived from it in this window and renews the agent's token by itself. Off: unlock again when the token expires.")
	hint.Wrapping = fyne.TextWrapWord
	hint.Importance = widget.LowImportance
	u.info = widget.NewLabel("")
	u.info.Wrapping = fyne.TextWrapWord
	u.unlock = widget.NewButton("Unlock", u.onUnlock)
	u.unlock.Importance = widget.HighImportance
	u.lockBtn = widget.NewButton("Lock", u.onLock)
	u.pass.OnSubmitted = func(string) { u.onUnlock() }
	u.win.SetContent(container.NewVBox(u.info, u.pass, u.remember, hint,
		container.NewGridWithColumns(2, u.lockBtn, u.unlock)))
	u.win.Resize(fyne.NewSize(400, 0))
	if tray {
		u.win.SetCloseIntercept(u.win.Hide)
	} else {
		u.win.SetMaster()
	}
}

func (u *ui) present() {
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
		if err != nil && !isDialError(err) {
			msg = err.Error()
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
		u.do(func() { u.notify("The agent did not start", err.Error()) })
		return
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	go func() {
		select {
		case err := <-done:
			if err != nil {
				u.do(func() { u.notify("The agent stopped", err.Error()+"\nShow log says why.") })
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
			u.notify("Approve on your phone", s.Pending.Note)
		case s.Last != nil && (prev.Last == nil || *prev.Last != *s.Last):
			u.notifyResult(*s.Last, prev.Pending != nil)
		case prev.State != "locked" && s.State == "locked" && s.Auth == "password" && !remembering:
			u.notify("Locked", "The token has expired or the agent was locked. Unlock to sign again.")
		}
	}
	u.renderMenu()
	u.renderWindow()
}

// keepUp keeps the agent unlocked while the password is remembered: a
// renewal before each token expires, at once after an expiry or an agent
// restart. A lock before the token ran out (ssh-add -x, another window) is
// taken as meant: the derived key is dropped. Reports whether it is still
// remembered.
func (u *ui) keepUp(prev Status, had bool, s Status) bool {
	if !u.remembering() {
		return false
	}
	if s.Auth != "password" {
		u.forget()
		return false
	}
	switch s.State {
	case "ready":
		if s.ExpiresAt > 0 {
			u.scheduleRenew(s.ExpiresAt - renewMargin(s.TTL))
		}
	case "locked":
		if had && prev.State == "ready" && prev.ExpiresAt > 0 && time.Now().Unix() < prev.ExpiresAt-5 {
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
		u.do(func() { u.notify("Unlock again", "The HEM needs the password again.") })
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
			u.do(func() { u.notify("Token not renewed", err.Error()+"\nTrying again every 30 s.") })
		}
	}
}

// forget drops the remembered key and stops renewing.
func (u *ui) forget() {
	u.mu.Lock()
	c := u.keep
	u.keep, u.renewAt, u.failing = nil, 0, false
	if u.timer != nil {
		u.timer.Stop()
		u.timer = nil
	}
	u.mu.Unlock()
	if c != nil {
		c.ClearKeys()
	}
}

func (u *ui) notifyResult(l Last, afterPhone bool) {
	// Failures always; a success only when the phone was asked, so a git
	// fetch with a live token does not raise a notification.
	switch l.Result {
	case "signed":
		if afterPhone {
			u.notify("Approved", l.Note)
		}
	case "denied":
		u.notify("Refused on the phone", l.Note)
	case "timeout":
		u.notify("No answer from the phone", l.Note)
	case "locked":
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
	return u.last, u.seen, u.down
}

func (u *ui) stateLine() string {
	s, seen, down := u.snapshot()
	switch {
	case down != "":
		return "Agent: " + down
	case !seen:
		return "Agent: connecting..."
	case s.State == "waiting":
		return "Waiting for the phone"
	case s.State == "locked":
		return "Locked"
	case s.ExpiresAt > 0 && u.remembering():
		return "Ready - the password is remembered"
	case s.ExpiresAt > 0:
		return "Ready until " + time.Unix(s.ExpiresAt, 0).Format("15:04")
	case s.Auth == "remote":
		return "Ready - the phone approves"
	default:
		return "Ready"
	}
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
	unlock := fyne.NewMenuItem("Unlock...", u.present)
	// Like Lock, only when it does something: not while unlocked.
	unlock.Disabled = !seen || s.Auth != "password" || s.State == "ready"
	lock := fyne.NewMenuItem("Lock", u.onLock)
	lock.Disabled = !seen || (s.State == "locked" && !u.remembering())
	items = append(items, unlock, lock, fyne.NewMenuItem("Show log", u.onLog))
	// Fyne adds Quit to a tray menu itself.
	u.desk.SetSystemTrayMenu(fyne.NewMenu(windowTitle, items...))
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
	u.info.SetText(text)
	if seen && s.Auth == "password" && s.State != "ready" {
		u.unlock.Enable()
		u.pass.Enable()
		u.remember.Enable()
	} else {
		u.unlock.Disable()
		u.pass.Disable()
		u.remember.Disable()
	}
	if seen && (s.State != "locked" || u.remembering()) {
		u.lockBtn.Enable()
	} else {
		u.lockBtn.Disable()
	}
}

func (u *ui) onUnlock() {
	s, seen, _ := u.snapshot()
	if !seen || s.Auth != "password" || u.pass.Text == "" {
		return
	}
	pass := []byte(u.pass.Text)
	remember := u.remember.Checked
	u.pass.SetText("")
	u.unlock.Disable()
	u.info.SetText("Logging in to the HEM...")
	go func() {
		exp, err := u.login(s, pass, remember)
		fyne.Do(func() {
			if err != nil {
				u.renderWindow()
				u.info.SetText(u.info.Text + "\n\nNot unlocked: " + err.Error())
				return
			}
			u.win.Hide()
			if remember {
				u.notify("Unlocked", "Signing until Lock; the token is renewed by this window.")
			} else {
				u.notify("Unlocked", "Signing until "+exp.Format("15:04"))
			}
		})
	}()
}

// login gets a token for every key the agent serves and hands it over. Unless
// remember is set the derived key is dropped at once and nothing here can
// mint another.
func (u *ui) login(s Status, pass []byte, remember bool) (time.Time, error) {
	defer clear(pass)
	if s.URL == "" || len(s.Keys) == 0 {
		return time.Time{}, errors.New("the agent did not say which HEM or keys")
	}
	// No token cache: every renewal is a fresh token from the HEM.
	c := hem.NewClient(s.URL, hem.Config{DisableTokenCache: true})
	u.forget() // a new login replaces whatever was remembered
	exp, err := u.handOverToken(c, s, pass)
	if err != nil || !remember {
		c.ClearKeys()
		return exp, err
	}
	u.mu.Lock()
	u.keep = c
	u.mu.Unlock()
	u.scheduleRenew(exp.Unix() - renewMargin(s.TTL))
	return exp, nil
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
	r, err := ask(ctx, u.control, Request{Op: "token", Build: currentBuild(), Token: tok})
	if err != nil {
		return time.Time{}, fmt.Errorf("handing the token to the agent: %w", err)
	}
	if !r.OK {
		return time.Time{}, fmt.Errorf("the agent refused the token: %s", r.Err)
	}
	return hem.TokenExpiry(tok), nil
}

// onLock locks the agent and forgets a remembered password.
func (u *ui) onLock() {
	go func() {
		u.handOver.Lock()
		defer u.handOver.Unlock()
		u.forget()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		r, err := ask(ctx, u.control, Request{Op: "lock"})
		if err != nil || !r.OK {
			u.do(func() { u.notify("Not locked", fmt.Sprint(err, r.Err)) })
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
