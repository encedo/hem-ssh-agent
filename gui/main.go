// hem-ssh-agent-gui: the tray window for hem-ssh-agent.
//
// The agent (Rust, src/) holds no password and asks nobody anything; this
// window shows its state, tells the person when the phone is asking, and in
// password mode logs in to the HEM itself and hands the agent only a token.
// When that token expires new signs fail until it is unlocked again - the
// window keeps nothing to renew it with (docs/DESIGN.md, control channel).
//
// Built on encedo-wg-hsm's gui (MIT, same author): Fyne, the tray, the
// single-instance doorbell, the pipe dial.
package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"net/url"
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
	appID       = "com.encedo.hem-ssh-agent"
	windowTitle = "HEM SSH agent"
)

//go:embed icon.svg
var iconSVG []byte

type ui struct {
	app     fyne.App
	desk    desktop.App
	win     fyne.Window
	control string

	mu   sync.Mutex
	last Status // the latest snapshot
	seen bool   // a snapshot has arrived on this connection
	down string // why the agent cannot be reached, "" when it can

	pass   *widget.Entry
	info   *widget.Label
	unlock *widget.Button
}

func main() {
	control := flag.String("control", defaultControl, "the agent's control channel (pipe or socket)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}

	a := app.NewWithID(appID)
	icon := fyne.NewStaticResource("icon.svg", iconSVG)
	a.SetIcon(icon)
	u := &ui{app: a, control: *control}

	if dir, err := instanceDir(); err == nil {
		ln, handedOver, err := claimInstance(dir)
		if handedOver {
			return // the running window shows itself
		}
		if err == nil {
			go serveInstance(ln, func() { fyne.Do(u.present) })
		}
	}

	u.build()
	if desk, ok := a.(desktop.App); ok {
		u.desk = desk
		desk.SetSystemTrayIcon(icon)
		u.renderMenu()
	} else {
		u.present() // no tray: the window is the only way in
	}
	go u.follow()
	a.Run()
}

// build makes the unlock window. It is shown from the tray and hidden, not
// closed, so the application keeps running.
func (u *ui) build() {
	u.win = u.app.NewWindow(windowTitle)
	u.pass = widget.NewPasswordEntry()
	u.pass.SetPlaceHolder("HEM password")
	u.info = widget.NewLabel("")
	u.info.Wrapping = fyne.TextWrapWord
	u.unlock = widget.NewButton("Unlock", u.onUnlock)
	u.unlock.Importance = widget.HighImportance
	u.pass.OnSubmitted = func(string) { u.onUnlock() }
	u.win.SetContent(container.NewVBox(u.info, u.pass, u.unlock))
	u.win.Resize(fyne.NewSize(380, 0))
	u.win.SetCloseIntercept(u.win.Hide)
}

func (u *ui) present() {
	u.renderWindow()
	u.win.Show()
	u.win.RequestFocus()
	u.win.Canvas().Focus(u.pass)
}

// follow keeps a watch on the agent, reconnecting while it is not running.
func (u *ui) follow() {
	for {
		err := watch(context.Background(), u.control, func(s Status) { fyne.Do(func() { u.apply(s) }) })
		msg := "the agent is not running"
		if err != nil && !isDialError(err) {
			msg = err.Error()
		}
		fyne.Do(func() { u.lost(msg) })
		time.Sleep(3 * time.Second)
	}
}

func isDialError(err error) bool {
	s := err.Error()
	return strings.Contains(s, "cannot find the file") || strings.Contains(s, "no such file") ||
		strings.Contains(s, "connection refused") || errors.Is(err, context.DeadlineExceeded)
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

	if had {
		switch {
		case s.Pending != nil && (prev.Pending == nil || prev.Pending.Since != s.Pending.Since):
			u.notify("Approve on your phone", s.Pending.Note)
		case s.Last != nil && (prev.Last == nil || *prev.Last != *s.Last):
			u.notifyResult(*s.Last, prev.Pending != nil)
		case prev.State != "locked" && s.State == "locked" && s.Auth == "password":
			u.notify("Locked", "The token has expired or the agent was locked. Unlock to sign again.")
		}
	}
	u.renderMenu()
	u.renderWindow()
}

// notifyResult: failures always; a success only when the phone was asked,
// so a git fetch with a live token does not raise a notification.
func (u *ui) notifyResult(l Last, afterPhone bool) {
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
	s, seen, _ := u.snapshot()
	state := fyne.NewMenuItem(u.stateLine(), nil)
	state.Disabled = true
	unlock := fyne.NewMenuItem("Unlock...", u.present)
	unlock.Disabled = !seen || s.Auth != "password"
	lock := fyne.NewMenuItem("Lock", u.onLock)
	lock.Disabled = !seen || (s.State == "locked")
	items := []*fyne.MenuItem{state, fyne.NewMenuItemSeparator(), unlock, lock,
		fyne.NewMenuItem("Show log", u.onLog)}
	// Fyne adds Quit to a tray menu itself.
	u.desk.SetSystemTrayMenu(fyne.NewMenu(windowTitle, items...))
}

func (u *ui) renderWindow() {
	s, seen, _ := u.snapshot()
	text := u.stateLine()
	if seen && s.URL != "" {
		text += "\n" + s.URL
	}
	for _, k := range s.Keys {
		text += "\n• " + k.Comment
	}
	u.info.SetText(text)
	if seen && s.Auth == "password" {
		u.unlock.Enable()
		u.pass.Enable()
	} else {
		u.unlock.Disable()
		u.pass.Disable()
	}
}

func (u *ui) onUnlock() {
	s, seen, _ := u.snapshot()
	if !seen || s.Auth != "password" || u.pass.Text == "" {
		return
	}
	pass := []byte(u.pass.Text)
	u.pass.SetText("")
	u.unlock.Disable()
	u.info.SetText("Logging in to the HEM...")
	go func() {
		exp, err := u.login(s, pass)
		fyne.Do(func() {
			if err != nil {
				u.renderWindow()
				u.info.SetText(u.info.Text + "\n\nNot unlocked: " + err.Error())
				return
			}
			u.win.Hide()
			u.notify("Unlocked", "Signing until "+exp.Format("15:04"))
		})
	}()
}

// login gets a token for every key the agent serves and hands it over. The
// derived key is dropped at once: nothing here can mint another.
func (u *ui) login(s Status, pass []byte) (time.Time, error) {
	defer clear(pass)
	if s.URL == "" || len(s.Keys) == 0 {
		return time.Time{}, errors.New("the agent did not say which HEM or keys")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c := hem.NewClient(s.URL, hem.Config{})
	defer c.ClearKeys()
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
	r, err := ask(ctx, u.control, Request{Op: "token", Build: currentBuild(), Token: tok})
	if err != nil {
		return time.Time{}, fmt.Errorf("handing the token to the agent: %w", err)
	}
	if !r.OK {
		return time.Time{}, fmt.Errorf("the agent refused the token: %s", r.Err)
	}
	return hem.TokenExpiry(tok), nil
}

func (u *ui) onLock() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if r, err := ask(ctx, u.control, Request{Op: "lock"}); err != nil || !r.OK {
			fyne.Do(func() { u.notify("Not locked", fmt.Sprint(err, r.Err)) })
		}
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
