// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tskagent

import (
	"crypto"
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var _ agent.Agent = &Server{}

func TestKeyParse(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		comment string
		keyType string
	}{
		{
			name:    "ED2559/Comment",
			input:   mustGenerateKey(t, genED25519, "elliptic justice"),
			comment: "elliptic justice",
			keyType: "ssh-ed25519",
		},
		{
			name:    "ED2559/NoComment",
			input:   mustGenerateKey(t, genED25519, ""),
			comment: "",
			keyType: "ssh-ed25519",
		},
		{
			name:    "RSA/Comment",
			input:   mustGenerateKey(t, genRSA, "what year is it"),
			comment: "what year is it",
			keyType: "ssh-rsa",
		},
		{
			name:    "RSA/NoComment",
			input:   mustGenerateKey(t, genRSA, ""),
			comment: "",
			keyType: "ssh-rsa",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := parseStoredKey(tc.name, 1, tc.input)
			if err != nil {
				t.Fatalf("parsing stored key: %v", err)
			}
			if key.Comment != tc.comment {
				t.Errorf("Comment: got %q, want %q", key.Comment, tc.comment)
			}
			if got := key.Signer.PublicKey().Type(); got != tc.keyType {
				t.Errorf("Key type: got %q, want %q", got, tc.keyType)
			}
		})
	}
}

func mustGenerateKey(t *testing.T, gen func() (crypto.PrivateKey, error), comment string) []byte {
	t.Helper()
	key, err := gen()
	if err != nil {
		t.Fatalf("Generating key: %v", err)
	}
	enc, err := ssh.MarshalPrivateKey(key, comment)
	if err != nil {
		t.Fatalf("Marshaling key: %v", err)
	}
	return pem.EncodeToMemory(enc)
}

func genED25519() (crypto.PrivateKey, error) {
	_, key, err := ed25519.GenerateKey(crand.Reader)
	return key, err
}

func genRSA() (crypto.PrivateKey, error) {
	return rsa.GenerateKey(crand.Reader, 1024)
}
