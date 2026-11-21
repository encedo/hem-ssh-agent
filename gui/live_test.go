package main

// Against a running agent in password mode (no Fyne window): the code behind
// the Unlock button - log in to the HEM, hand the token over - and the
// snapshots it causes. Skipped unless HEM_CONTROL and HEM_PASSWORD are set:
//
//	HEM_CONTROL='\\.\pipe\...-control' HEM_PASSWORD=... go test -run Live -v

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestLiveUnlockAndLock(t *testing.T) {
	control, pass := os.Getenv("HEM_CONTROL"), os.Getenv("HEM_PASSWORD")
	if control == "" || pass == "" {
		t.Skip("HEM_CONTROL and HEM_PASSWORD not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	r, err := ask(ctx, control, Request{Op: "whoami"})
	if err != nil || !r.OK || r.Build == nil || r.Build.Release != version {
		t.Fatalf("whoami: %v %+v", err, r)
	}
	t.Logf("agent %s, caller %s", r.Build.Release, r.Who)

	snaps := make(chan Status, 16)
	go func() { _ = watch(ctx, control, func(s Status) { snaps <- s }) }()
	next := func() Status {
		select {
		case s := <-snaps:
			return s
		case <-ctx.Done():
			t.Fatal("no snapshot")
			return Status{}
		}
	}

	first := next()
	if first.Auth != "password" || first.URL == "" || len(first.Keys) == 0 {
		t.Fatalf("snapshot: %+v", first)
	}
	if first.State != "locked" {
		// A previous run left it unlocked; start from locked.
		if r, err := ask(ctx, control, Request{Op: "lock"}); err != nil || !r.OK {
			t.Fatalf("lock: %v %+v", err, r)
		}
		if s := next(); s.State != "locked" {
			t.Fatalf("after lock: %+v", s)
		}
	}

	// A token of a different build is refused, naming the agent's.
	r, err = ask(ctx, control, Request{Op: "token", Build: &Build{Release: "0.0.0+other"}, Token: "x.y.z"})
	if err != nil || r.OK || r.Kind != "build" {
		t.Fatalf("other build: %v %+v", err, r)
	}

	u := &ui{control: control}
	exp, err := u.login(first, []byte(pass))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	s := next()
	if s.State != "ready" || s.ExpiresAt == 0 || s.ExpiresAt != exp.Unix() {
		t.Fatalf("after unlock: %+v (token exp %v)", s, exp)
	}
	t.Logf("ready until %s (ttl %d s)", exp.Format(time.TimeOnly), first.TTL)

	if r, err := ask(ctx, control, Request{Op: "lock"}); err != nil || !r.OK {
		t.Fatalf("lock: %v %+v", err, r)
	}
	if s := next(); s.State != "locked" || s.ExpiresAt != 0 {
		t.Fatalf("after lock: %+v", s)
	}
}
