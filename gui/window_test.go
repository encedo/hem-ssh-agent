package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2/test"

	hem "github.com/encedo/hem-sdk-go"
)

// The window keeps one size in every state, with the longest message too
// (owner, 2026-11-24): a fixed-size window that has to grow puts its canvas
// out of step with itself on Windows - a blank band, clicks landing elsewhere.
func TestWindowKeepsOneSize(t *testing.T) {
	u := &ui{app: test.NewApp()}
	u.build()
	base := u.win.Content().MinSize()
	if base.Width > 400 {
		t.Fatalf("content %v wider than the window", base)
	}
	keys := make([]KeyInfo, 8)
	for i := range keys {
		keys[i] = KeyInfo{Kid: fmt.Sprintf("%032x", i), Comment: "a key with a fairly long comment " + strings.Repeat("x", 20)}
	}
	long := "https://" + strings.Repeat("a-very-long-host-name.", 6) + "ence.do"
	states := []Status{
		{State: "locked", Auth: "password"},
		{State: "ready", Auth: "remote+password", URL: long, Keys: keys, ExpiresAt: time.Now().Unix() + 300, Source: "phone"},
		{State: "waiting", Auth: "remote+password", URL: long, Keys: keys, Pending: &Pending{Note: "sign", Since: 1}},
	}
	for i, s := range states {
		u.last, u.seen = s, true
		for _, msg := range []string{"", "Not unlocked: " + humanError(&hem.HemError{Status: 401}), strings.Repeat("a long message ", 30)} {
			u.message = msg
			u.renderWindow()
			if got := u.win.Content().MinSize(); got != base {
				t.Errorf("state %d, message %q: content %v, want %v", i, msg, got, base)
			}
		}
	}
}

func TestCurrentDropsAnExpiredToken(t *testing.T) {
	past := Status{State: "ready", Auth: "password", ExpiresAt: time.Now().Unix() - 1, Source: "password"}
	if got := current(past); got.ExpiresAt != 0 || got.Source != "" || got.State != "locked" {
		t.Errorf("expired password token: %+v", got)
	}
	remote := Status{State: "ready", Auth: "remote", ExpiresAt: time.Now().Unix() - 1, Source: "phone"}
	if got := current(remote); got.ExpiresAt != 0 || got.State != "ready" {
		t.Errorf("expired phone token: %+v", got)
	}
	live := Status{State: "ready", Auth: "password", ExpiresAt: time.Now().Unix() + 60}
	if got := current(live); got.ExpiresAt != live.ExpiresAt || got.State != "ready" {
		t.Errorf("a live token changed: %+v", got)
	}
}

func TestHumanErrorSaysNoHTTP(t *testing.T) {
	cases := map[string]error{
		"Wrong password - check it and try again.":                       fmt.Errorf("x: %w", &hem.HemError{Message: "HEM POST https://h/api/auth/token -> HTTP 401", Code: "http_401", Status: 401}),
		"The HEM did not answer. Check the network and the address.":     &hem.HemError{Message: "POST https://h: dial tcp", Code: "network"},
		"The HEM needs the password again.":                              &hem.HemError{Code: "auth_password_required"},
		"The HEM refused the request.":                                   &hem.HemError{Message: "HEM GET https://h -> HTTP 500", Code: "http_500", Status: 500},
		"The agent is not running.":                                      fmt.Errorf("handing the token to the agent: %w", &controlError{errors.New("pipe")}),
		"The window and the agent are different versions - update both.": &agentRefused{kind: "build", msg: "build mismatch"},
		"Type the HEM password.":                                         errNoPassword,
	}
	for want, err := range cases {
		got := humanError(err)
		if got != want {
			t.Errorf("humanError(%v) = %q, want %q", err, got, want)
		}
		if strings.Contains(got, "HTTP") || strings.Contains(got, "://") {
			t.Errorf("%q shows the protocol", got)
		}
	}
}
