package main

// What a person reads (owner, 2026-11-24): the window and the notifications
// say what happened in words, never an HTTP status or a URL - after
// encedo-wg-hsm's humanError. The raw error goes to stderr, for whoever runs
// the window from a terminal.

import (
	"errors"
	"log"

	hem "github.com/encedo/hem-sdk-go"
)

// errNoPassword: Unlock with an empty password field.
var errNoPassword = errors.New("no password typed")

// controlError: the control channel could not be used - no agent listening,
// or the connection broke.
type controlError struct{ err error }

func (e *controlError) Error() string { return "control channel: " + e.err.Error() }
func (e *controlError) Unwrap() error { return e.err }

// agentRefused: the agent answered ok false (Reply.Kind, Reply.Err), or is
// another build (kind "build").
type agentRefused struct{ kind, msg string }

func (e *agentRefused) Error() string { return "the agent refused: " + e.msg }

func humanError(err error) string {
	log.Printf("hem-ssh-agent-gui: %v", err)
	var he *hem.HemError
	var ar *agentRefused
	var ce *controlError
	switch {
	case errors.Is(err, errNoPassword):
		return "Type the HEM password."
	case errors.As(err, &ar) && ar.kind == "build":
		return "The window and the agent are different versions - update both."
	case errors.As(err, &ar) && ar.kind == "auth_password_required":
		return "The HEM needs the password again."
	case errors.As(err, &ar):
		return "The agent did not do it."
	case errors.As(err, &ce):
		return "The agent is not running."
	case errors.As(err, &he):
		switch {
		case he.Code == "auth_password_required":
			return "The HEM needs the password again."
		case he.Status == 401:
			return "Wrong password - check it and try again."
		case he.Code == "network" || he.Code == "timeout" || he.Code == "aborted":
			return "The HEM did not answer. Check the network and the address."
		}
		return "The HEM refused the request."
	}
	return err.Error()
}
