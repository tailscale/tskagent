// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tskagent

import (
	"testing"

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
