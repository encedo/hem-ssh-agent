package main

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"golang.org/x/crypto/ssh"
)

func testKey(label string, seed byte) hemKey {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	return hemKey{KID: strings.Repeat(string('a'+rune(seed%6)), 32), Label: label, PubKey: priv.Public().(ed25519.PublicKey)}
}

// chosen.toml: the shape the agent reads (src/config.rs Chosen: url and
// [[key]] kid / pubkey, nothing else), and lines ssh itself parses back.
func TestWriteChosen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "chosen.toml")
	keys := []hemKey{testKey("laptop key", 1), testKey("with \"quotes\" and\nnewline", 2)}
	if err := writeChosen(path, "https://my.ence.do", keys); err != nil {
		t.Fatal(err)
	}
	var got chosenFile
	md, err := toml.DecodeFile(path, &got)
	if err != nil {
		t.Fatal(err)
	}
	if u := md.Undecoded(); len(u) != 0 {
		t.Fatalf("fields the agent would refuse: %v", u)
	}
	if got.URL != "https://my.ence.do" || len(got.Keys) != 2 {
		t.Fatalf("read back %+v", got)
	}
	for i, k := range got.Keys {
		if k.KID != keys[i].KID {
			t.Errorf("key %d kid %q", i, k.KID)
		}
		pub, comment, _, rest, err := ssh.ParseAuthorizedKey([]byte(k.PubKey))
		if err != nil || len(rest) != 0 {
			t.Fatalf("key %d line %q: %v", i, k.PubKey, err)
		}
		if pub.Type() != ssh.KeyAlgoED25519 || !bytes.Equal(pub.(ssh.CryptoPublicKey).CryptoPublicKey().(ed25519.PublicKey), keys[i].PubKey) {
			t.Errorf("key %d: another public key", i)
		}
		if strings.ContainsAny(comment, "\n\r") {
			t.Errorf("key %d comment spans lines: %q", i, comment)
		}
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("the temporary file was left")
	}
}

func TestChoiceLabelAndAddress(t *testing.T) {
	k := testKey("", 3)
	if got := choiceLabel(k); !strings.HasPrefix(got, "(no label)") || !strings.HasSuffix(got, k.KID[:8]) {
		t.Errorf("choiceLabel = %q", got)
	}
	for url, want := range map[string]bool{"https://my.ence.do": true, "HTTPS://x": true, "http://192.168.7.1": false, "https://": false, "": false} {
		if isHTTPS(url) != want {
			t.Errorf("isHTTPS(%q) != %v", url, want)
		}
	}
}
