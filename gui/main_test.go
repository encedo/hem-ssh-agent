package main

import (
	"reflect"
	"testing"
)

func TestRenewMargin(t *testing.T) {
	for ttl, want := range map[int]int64{0: 10, 20: 10, 120: 24, 300: 60, 3600: 60} {
		if got := renewMargin(ttl); got != want {
			t.Errorf("renewMargin(%d) = %d, want %d", ttl, got, want)
		}
	}
}

func TestAgentArgs(t *testing.T) {
	// -control not given on the command line: the agent keeps its own.
	if got := agentArgs("", defaultControl); !reflect.DeepEqual(got, []string{"run"}) {
		t.Errorf("no config: %q", got)
	}
	got := agentArgs("cfg.toml", defaultControl)
	if len(got) != 3 || got[0] != "--config" || got[2] != "run" || got[1] == "cfg.toml" {
		t.Errorf("config not passed as an absolute path before run: %q", got)
	}
}

func TestThemeFor(t *testing.T) {
	for _, name := range []string{"", "auto", "System", "dark", " light "} {
		if _, err := themeFor(name); err != nil {
			t.Errorf("themeFor(%q): %v", name, err)
		}
	}
	if _, err := themeFor("dsrk"); err == nil {
		t.Error("an unknown theme was accepted")
	}
}

func TestForgetWithoutRememberingIsHarmless(t *testing.T) {
	u := &ui{}
	u.forget()
	u.renew() // nothing remembered: no hand-over, no panic
	if u.remembering() {
		t.Fatal("remembering after forget")
	}
}
