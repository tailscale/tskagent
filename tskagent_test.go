// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tskagent_test

import (
	"context"
	"crypto/ed25519"
	"net"
	"net/http/httptest"
	"testing"

	"github.com/creachadair/taskgroup"
	"github.com/google/go-cmp/cmp"
	"github.com/tailscale/setec/client/setec"
	"github.com/tailscale/setec/setectest"
	"github.com/tailscale/tskagent"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	_ "embed"
)

//go:embed testdata/test.key
var testPrivKey string

//go:embed testdata/test.key.pub
var testPubKey []byte

func TestAgent(t *testing.T) {
	const testSecret = "test/ssh-agent/key"

	// Set up a fake setec server containing the test private key.
	db := setectest.NewDB(t, nil)
	db.MustPut(db.Superuser, testSecret, testPrivKey)
	ss := setectest.NewServer(t, db, nil)
	hs := httptest.NewServer(ss.Mux)
	defer hs.Close()

	// Set up an agent communicating with the fake setec.
	ts := tskagent.NewServer(tskagent.Config{
		Client: setec.Client{Server: hs.URL, DoHTTP: hs.Client().Do},
		Prefix: "test/ssh-agent",
		Logf:   t.Logf,
	})
	if err := ts.Update(context.Background()); err != nil {
		t.Fatalf("Initial update failed: %v", err)
	}

	// Parse the public key to offer.
	pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(testPubKey)
	if err != nil {
		t.Fatalf("Parse authorized key: %v", err)
	} else if len(rest) != 0 {
		t.Error("Extra data after authorized key")
	}

	// Run the agent over a pipe and make sure client calls do what they should.
	cconn, sconn := net.Pipe()
	cli := taskgroup.Run(func() { agent.ServeAgent(ts, sconn) })
	defer func() { cconn.Close(); cli.Wait() }()

	ac := agent.NewClient(cconn)

	t.Run("AddDoesNotWork", func(t *testing.T) {
		pk := ed25519.NewKeyFromSeed([]byte("00000000000000000000000000000000")) // throwaway
		err := ac.Add(agent.AddedKey{
			PrivateKey: pk,
			Comment:    "Nothing to see here",
		})
		if err == nil {
			t.Errorf("Add key %v: did not get expected error", pk)
		}
	})

	t.Run("Locking", func(t *testing.T) {
		const pp = "foo"
		if err := ac.Lock([]byte(pp)); err != nil {
			t.Fatalf("Lock: unexpected error: %v", err)
		}
		if err := ac.Lock([]byte(pp)); err == nil {
			t.Error("Re-lock: did not get expected error")
		}
		if err := ac.Unlock([]byte("wrong")); err == nil {
			t.Error("Unlock wrong: did not get expected error")
		}
		if err := ac.Unlock([]byte(pp)); err != nil {
			t.Fatalf("Unlock: unexpected error: %v", err)
		}
		if err := ac.Unlock([]byte(pp)); err == nil {
			t.Error("Re-unlock: did not get expected error")
		}
	})

	t.Run("List", func(t *testing.T) {
		lst, err := ac.List()
		if err != nil {
			t.Fatalf("List: unexpected error: %v", err)
		}
		if diff := cmp.Diff(lst, []*agent.Key{{
			Format:  "ssh-ed25519",
			Blob:    pubKey.Marshal(),
			Comment: "Dummy key for testing",
		}}); diff != "" {
			t.Errorf("Wrong keys (-got, +want):\n%s", diff)
		}
	})

	t.Run("Signers", func(t *testing.T) {
		lst, err := ac.Signers()
		if err != nil {
			t.Fatalf("Signers: unexpected error: %v", err)
		}
		if len(lst) != 1 {
			t.Fatalf("Got %d signers, want 1", len(lst))
		}
		if diff := cmp.Diff(lst[0].PublicKey().Marshal(), pubKey.Marshal()); diff != "" {
			t.Errorf("Wrong signer (-got, +want):\n%s", diff)
		}
	})

	// TODO: Test Sign, Remove, RemoveAll.
}
