package main

// The control channel to the agent: the Go side of src/control.rs.
//
// Framing and message shape come from encedo-wg-hsm internal/ipc (MIT, same
// author): a four-byte big-endian length, then JSON, at most 64 KiB. What the
// window sends is a token and nothing else - no passphrase, no session secret; the
// agent refuses any field it does not know.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"
)

const maxMessage = 64 << 10

type Build struct {
	Release string `json:"release"`
}

type Request struct {
	Op    string `json:"op"`
	Build *Build `json:"build,omitempty"`
	Token string `json:"token,omitempty"`
	// Source: op token only - "password" (absent) or "phone".
	Source string `json:"source,omitempty"`
}

type Msg struct {
	Type  string  `json:"type"`
	Reply *Reply  `json:"reply,omitempty"`
	Event *Status `json:"event,omitempty"`
}

type Reply struct {
	OK    bool   `json:"ok"`
	Err   string `json:"err,omitempty"`
	Kind  string `json:"kind,omitempty"`
	Build *Build `json:"build,omitempty"`
	Who   string `json:"who,omitempty"`
}

// Status is the agent's whole state, sent on every change.
type Status struct {
	State     string    `json:"state"` // unconfigured | locked | ready | waiting
	Auth      string    `json:"auth"`  // password | remote | remote+password
	URL       string    `json:"url,omitempty"`
	TTL       int       `json:"ttl,omitempty"`
	Keys      []KeyInfo `json:"keys"`
	ExpiresAt int64     `json:"expires_at,omitempty"`
	// Where the current token came from: phone | password (with ExpiresAt).
	Source string `json:"source,omitempty"`
	// The agent keeps the session secret (ssh-add -X): tokens without the phone
	// until Lock.
	Kept    bool     `json:"kept,omitempty"`
	Pending *Pending `json:"pending,omitempty"`
	Last    *Last    `json:"last,omitempty"`
	// The configuration names the address / the keys: shown, not changed.
	URLFixed  bool `json:"url_fixed,omitempty"`
	KeysFixed bool `json:"keys_fixed,omitempty"`
	// Where Choose keys writes (chosen.toml); empty when both are fixed.
	Chosen string `json:"chosen,omitempty"`
}

// canChoose: Choose keys does something - the configuration leaves the
// keys open.
func canChoose(s Status) bool {
	return !s.KeysFixed && s.Chosen != ""
}

// canUnlockPhone: Unlock by phone does something - a phone mode, set up, no
// token, the phone not asked yet.
func canUnlockPhone(s Status) bool {
	return (s.Auth == "remote" || s.Auth == "remote+password") && s.State != "unconfigured" &&
		s.ExpiresAt == 0 && s.Pending == nil
}

type KeyInfo struct {
	Kid     string `json:"kid"`
	Comment string `json:"comment"`
}

type Pending struct {
	Note  string `json:"note"`
	Since int64  `json:"since"`
	// Use password was chosen: the phone is no longer asked, the sign waits
	// for this window's token.
	Password bool `json:"password,omitempty"`
}

// passwordAllowed: the HEM password unlocks (password mode, or remote mode
// with the password as the fallback).
func passwordAllowed(s Status) bool {
	return s.Auth == "password" || s.Auth == "remote+password"
}

// canUnlock: Unlock... does something now - password mode while locked; with
// the phone first, while there is no token (the phone would be asked).
func canUnlock(s Status) bool {
	if s.State == "unconfigured" {
		return false // no keys to unlock yet: Choose keys first
	}
	switch s.Auth {
	case "password":
		return s.State != "ready"
	case "remote+password":
		return s.ExpiresAt == 0
	}
	return false
}

type Last struct {
	Note   string `json:"note"`
	Result string `json:"result"` // signed | unlocked | denied | timeout | locked | failed
	At     int64  `json:"at"`
}

// version must equal the agent's build (src/control.rs Build::current) for a
// token to be accepted; build.sh / the packaging stamp both the same way.
var version = "0.1.0"

func currentBuild() *Build { return &Build{Release: version} }

func writeMsg(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > maxMessage {
		return fmt.Errorf("message of %d bytes exceeds the limit", len(b))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func readMsg(r io.Reader) (Msg, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Msg{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxMessage {
		return Msg{}, fmt.Errorf("message of %d bytes exceeds the limit", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return Msg{}, err
	}
	var m Msg
	return m, json.Unmarshal(b, &m)
}

// ask sends one request on its own connection and returns the reply; a
// channel failure is a *controlError, an ok false answer an *agentRefused.
func ask(ctx context.Context, path string, req Request) (Reply, error) {
	c, err := dialControl(ctx, path)
	if err != nil {
		return Reply{}, &controlError{err}
	}
	defer c.Close()
	r, err := roundTrip(c, req)
	if err != nil {
		return Reply{}, &controlError{err}
	}
	if !r.OK {
		return r, &agentRefused{kind: r.Kind, msg: r.Err}
	}
	return r, nil
}

func roundTrip(c net.Conn, req Request) (Reply, error) {
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	defer c.SetDeadline(time.Time{})
	if err := writeMsg(c, req); err != nil {
		return Reply{}, err
	}
	for {
		m, err := readMsg(c)
		if err != nil {
			return Reply{}, err
		}
		if m.Type == "reply" && m.Reply != nil {
			return *m.Reply, nil
		}
	}
}

// watch subscribes and calls fn with every snapshot until the connection ends.
func watch(ctx context.Context, path string, fn func(Status)) error {
	c, err := dialControl(ctx, path)
	if err != nil {
		return err
	}
	defer c.Close()
	go func() { <-ctx.Done(); c.Close() }()
	r, err := roundTrip(c, Request{Op: "watch"})
	if err != nil {
		return err
	}
	if !r.OK {
		return fmt.Errorf("watch refused: %s", r.Err)
	}
	if r.Build != nil && r.Build.Release != version {
		return &agentRefused{kind: "build", msg: fmt.Sprintf("the agent is build %s, this window %s", r.Build.Release, version)}
	}
	for {
		m, err := readMsg(c)
		if err != nil {
			return err
		}
		if m.Type == "event" && m.Event != nil {
			fn(*m.Event)
		}
	}
}
