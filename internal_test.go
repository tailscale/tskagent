// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tskagent

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	_ "embed"
)

var _ agent.Agent = &Server{}

// The test data key is a throwaway generated for testing, and is not used
// anywhere else.  To generate a new test key, run:
//
//    ssh-keygen -C "Dummy key for testing" -t ed25519 -f testdata/test.key

//go:embed testdata/test.key
var testPrivKey []byte

func TestKeyParse(t *testing.T) {
	key, err := parseStoredKey("foo", 1, testPrivKey)
	if err != nil {
		t.Fatalf("Parsing stored key: %v", err)
	}

	const wantComment = "Dummy key for testing"
	if key.Comment != wantComment {
		t.Errorf("Comment: got %q, want %q", key.Comment, wantComment)
	}
	if got, want := key.Signer.PublicKey().Type(), "ssh-ed25519"; got != want {
		t.Errorf("Key type: got %q, want %q", got, want)
	}
}

func TestParseComment(t *testing.T) {
	type genKeyFunc func(t *testing.T) crypto.PrivateKey

	runTest := func(t *testing.T, genKey genKeyFunc, comment string) {
		priv := genKey(t)

		privPem, err := ssh.MarshalPrivateKey(priv, comment)
		if err != nil {
			t.Fatalf("MarshalPrivateKey: %v", err)
		}

		pemText := pem.EncodeToMemory(privPem)

		// We expect exactly empty or "comment-here", nothing else.
		switch got := parseComment(pemText); got {
		case "":
			//t.Logf("got empty comment")
		case "comment-here":
			//t.Logf("got comment: %q", got)
		default:
			t.Fatalf("got unexpected comment: %q", got)
		}
	}

	const iterations = 1_000

	tests := []struct {
		name   string
		genKey genKeyFunc
	}{
		{
			name: "ed25519",
			genKey: func(t *testing.T) crypto.PrivateKey {
				_, priv, err := ed25519.GenerateKey(nil)
				if err != nil {
					t.Fatal(err)
				}
				return priv
			},
		},
		{
			name: "rsa",
			genKey: func(t *testing.T) crypto.PrivateKey {
				key, err := rsa.GenerateKey(rand.Reader, 2048)
				if err != nil {
					t.Fatal(err)
				}
				return key
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name+"_no_comment", func(t *testing.T) {
			for i := 0; i < iterations; i++ {
				runTest(t, tt.genKey, "")
			}
		})
		t.Run(tt.name+"_comment", func(t *testing.T) {
			for i := 0; i < iterations; i++ {
				runTest(t, tt.genKey, "comment-here")
			}
		})
	}
}
