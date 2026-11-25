package main

// Choose keys: the HEM's SSH keys (Ed25519, description prefix
// sshDescrPrefix) are listed, the person picks up to 8,
// and the choice goes to chosen.toml beside the agent's configuration - the
// same url / [[key]] shape as the configuration (src/config.rs Chosen). The
// agent reads it on `reload`; what the configuration names always wins. Only
// the address, the kids and the public keys are written: nothing secret.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"golang.org/x/crypto/ssh"

	hem "github.com/encedo/hem-sdk-go"
)

// maxKeys: one token holds up to 8 scopes, one keymgmt:use:<kid> per key.
const maxKeys = 8

// sshDescrPrefix: the HEM keys meant for SSH carry this at the start of their
// description (owner, 2026-11-24). Six bytes: the least the device searches
// for without a token (allow_keysearch), and a whole number of base64 groups,
// so the prefix anchor holds on the base64 form the search compares.
const sshDescrPrefix = "ETSSSH"

type hemKey struct {
	KID    string
	Label  string
	PubKey []byte // 32 bytes, Ed25519; nil until read (an anonymous search has none)
}

var (
	errNoSSHKeys      = errors.New("the HEM has no SSH keys")
	errPasswordNeeded = errors.New("the HEM wants a login and no password was typed")
)

// keySession: one Choose keys, from the search to the public keys of the
// keys picked. The password (when typed) is kept only until close.
type keySession struct {
	c     *hem.Client
	pass  []byte
	phone bool // the phone may approve (a remote mode)
}

func newKeySession(url string, pass []byte, phone bool) *keySession {
	return &keySession{c: hem.NewClient(url, hem.Config{DisableTokenCache: true}), pass: pass, phone: phone}
}

func (k *keySession) close() {
	k.c.ClearKeys()
	clear(k.pass)
}

// token: with the password when one was typed, otherwise approved on the
// phone. Check-in first: it sets the HEM clock - required for the phone (the
// broker is needed anyway), tried with the password (an air gap).
func (k *keySession) token(ctx context.Context, scopes []string) (string, error) {
	err := k.c.Checkin(ctx)
	switch {
	case len(k.pass) > 0:
		return k.c.AuthPasswordScopes(ctx, k.pass, scopes, 120)
	case !k.phone:
		return "", errPasswordNeeded
	case err != nil:
		return "", err
	}
	return k.c.AuthRemoteScopes(ctx, scopes, hem.RemoteOpts{PollTimeout: 90 * time.Second})
}

// search finds the HEM's SSH keys: without a token first (the device answers
// a 6-byte prefix search when allow_keysearch is on); refused, with a
// keymgmt:search token. Ed25519 with the private half in the HEM only (PKEY:
// an imported public key cannot sign), by label - as `hem-ssh-agent keys`.
func (k *keySession) search(ctx context.Context) ([]hemKey, error) {
	prefix := []byte(sshDescrPrefix)
	opts := hem.SearchOpts{Match: hem.MatchPrefix, Type: "ED25519"}
	entries, err := k.c.SearchKeysAll(ctx, "", prefix, opts)
	var he *hem.HemError
	if errors.As(err, &he) && (he.Status == 401 || he.Status == 403) {
		var tok string
		if tok, err = k.token(ctx, []string{"keymgmt:search"}); err != nil {
			return nil, err
		}
		opts.ReturnPubkey = true
		entries, err = k.c.SearchKeysAll(ctx, tok, prefix, opts)
	}
	if err != nil {
		return nil, err
	}
	var keys []hemKey
	for _, e := range entries {
		if e.Type != "ED25519" || !slices.Contains(e.Flags, "PKEY") {
			continue
		}
		var pk []byte
		if len(e.PubKey) == ed25519.PublicKeySize {
			pk = e.PubKey
		}
		keys = append(keys, hemKey{KID: strings.ToLower(e.KID), Label: e.Label, PubKey: pk})
	}
	if len(keys) == 0 {
		return nil, errNoSSHKeys
	}
	sort.SliceStable(keys, func(i, j int) bool { return keys[i].Label < keys[j].Label })
	return keys, nil
}

// complete reads the public keys the search left out, with one token for
// the keys picked (keymgmt:use:<kid> reads that key's public half) - the
// scopes the agent's own tokens carry, so the token is returned for the
// agent to sign with ("" when the search gave every public key).
func (k *keySession) complete(ctx context.Context, keys []hemKey) (string, error) {
	var scopes []string
	for _, key := range keys {
		if key.PubKey == nil {
			scopes = append(scopes, "keymgmt:use:"+key.KID)
		}
	}
	if len(scopes) == 0 {
		return "", nil
	}
	tok, err := k.token(ctx, scopes)
	if err != nil {
		return "", err
	}
	for i := range keys {
		if keys[i].PubKey != nil {
			continue
		}
		info, err := k.c.GetPubKey(ctx, tok, keys[i].KID)
		if err != nil {
			return "", err
		}
		if len(info.PubKey) != ed25519.PublicKeySize {
			return "", fmt.Errorf("key %s: no 32-byte public key", keys[i].KID)
		}
		keys[i].PubKey = info.PubKey
	}
	return tok, nil
}

// source: how this session's tokens were obtained, as the agent reports it.
func (k *keySession) source() string {
	if len(k.pass) > 0 {
		return "password"
	}
	return "phone"
}

// choiceLabel: what the list shows for a key - its label and the start of
// its kid (two keys may share a label).
func choiceLabel(k hemKey) string {
	label := oneLine(k.Label)
	if label == "" {
		label = "(no label)"
	}
	return label + "  ·  " + k.KID[:min(8, len(k.KID))]
}

// opensshLine: the key as an OpenSSH public key line with its label as the
// comment - what `hem-ssh-agent pubkey` prints.
func opensshLine(k hemKey) (string, error) {
	pub, err := ssh.NewPublicKey(ed25519.PublicKey(k.PubKey))
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if c := strings.TrimSpace(oneLine(k.Label)); c != "" {
		line += " " + c
	}
	return line, nil
}

// oneLine: control characters replaced, as the agent does for the phone.
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}

type chosenFile struct {
	URL  string      `toml:"url"`
	Keys []chosenKey `toml:"key"`
}

type chosenKey struct {
	KID    string `toml:"kid"`
	PubKey string `toml:"pubkey"`
}

const chosenHeader = "# Written by the HEM SSH agent window (Choose keys): the HEM and the keys\n" +
	"# the agent serves where its configuration file does not name them.\n\n"

// writeChosen replaces chosen.toml at path in one step (a reader never sees
// half a file).
func writeChosen(path, url string, keys []hemKey) error {
	f := chosenFile{URL: url}
	for _, k := range keys {
		line, err := opensshLine(k)
		if err != nil {
			return err
		}
		f.Keys = append(f.Keys, chosenKey{KID: k.KID, PubKey: line})
	}
	var b bytes.Buffer
	b.WriteString(chosenHeader)
	if err := toml.NewEncoder(&b).Encode(f); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b.Bytes(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// isHTTPS: the agent takes the HEM over https only (DEV-532).
func isHTTPS(url string) bool {
	return len(url) > 8 && strings.EqualFold(url[:8], "https://")
}
