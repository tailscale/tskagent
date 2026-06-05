// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package tskagent implements an SSH key agent backed by the [setec] service.
//
// A [Server] implements an [agent.Agent] that serves SSH keys stored in the
// specified setec server. Each secret whose name matches a designated prefix
// and contains an SSH private key in OpenSSH PEM format is offered by the
// agent to callers on the local system.
//
// [setec]: https://github.com/tailscale/setec
package tskagent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/creachadair/taskgroup"
	"github.com/tailscale/setec/client/setec"
	"github.com/tailscale/setec/types/api"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Config carries the settings for a [Server].
type Config struct {
	// Client is the client for the secrets service. It must be set.
	Client setec.Client

	// Prefix is the secret name prefix to be served.  It must be non-empty.
	Prefix string

	// Logf, if set, is used to write logs. If nil, logs are discarded.
	Logf func(string, ...any)
}

// NewServer constructs a new [Server] that fetches SSH keys matching the
// specified configuration in [setec].
//
// The caller must call [Server.Update] at least once to initialize the list of
// keys available to the agent.  Thereafter, the caller may call Update again
// as often as desired to update the list. The server does not automatically
// perform updates.
func NewServer(config Config) *Server {
	if config.Prefix == "" {
		panic("empty scret name prefix")
	}
	if !strings.HasSuffix(config.Prefix, "/") {
		config.Prefix += "/"
	}
	return &Server{prefix: config.Prefix, setecClient: config.Client, logf: config.Logf}
}

// Server implements the SSH key agent server protocol.  The caller must call
// [agent.ServeAgent] to expose the server to clients.
type Server struct {
	prefix      string // includes trailing "/"
	setecClient setec.Client
	logf        func(string, ...any)

	μ          sync.Mutex
	locked     bool
	passphrase string
	keys       map[string]*sshKey
}

// Serve accepts connections from lst and serve the agent to each in its own
// goroutine. It runs until lst closes or ctx ends.
func (s *Server) Serve(ctx context.Context, lst net.Listener) {
	var g taskgroup.Group
	g.Run(func() {
		<-ctx.Done()
		s.logPrintf("Signal received; closing listener")
		lst.Close()
	})
	for {
		conn, err := lst.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				s.logPrintf("Listener stopped: %v", err)
			}
			break
		}
		g.Go(func() error { return s.ServeOne(conn) })
	}
	g.Wait()
}

// ServeOne serves the agent to the specified connection.  It is safe to call
// ServeOne concurrently from multiple goroutines with separate connections,
// including while Serve is running.
func (s *Server) ServeOne(conn io.ReadWriter) error {
	return agent.ServeAgent(s, conn)
}

// List implements part of the [agent.Agent] interface.
func (s *Server) List() ([]*agent.Key, error) {
	s.μ.Lock()
	defer s.μ.Unlock()
	if s.locked || len(s.keys) == 0 {
		return nil, nil // locked agents return an empty list
	}
	keys := make([]*agent.Key, 0, len(s.keys))
	for _, key := range s.keys {
		keys = append(keys, &agent.Key{
			Format:  key.Signer.PublicKey().Type(),
			Blob:    key.Signer.PublicKey().Marshal(),
			Comment: key.Comment,
		})
	}
	return keys, nil
}

// Sign implements part of the [agent.Agent] interface.
func (s *Server) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	s.μ.Lock()
	defer s.μ.Unlock()
	sk, ok := s.keys[publicKeyID(key)]
	if !ok {
		return nil, errors.New("key not found")
	}
	return sk.Signer.Sign(rand.Reader, data)
}

// Add implements part of the [agent.Agent] interface.
// This implementation does not support adding keys.
func (s *Server) Add(key agent.AddedKey) error {
	return errors.New("agent: adding keys is not supported")
}

// Remove implements part of the [agent.Agent] interface.
//
// This implementation only removes the key from the local list, it does not
// affect what is stored on the secrets server.
func (s *Server) Remove(key ssh.PublicKey) error {
	s.μ.Lock()
	defer s.μ.Unlock()
	id := publicKeyID(key)
	if _, ok := s.keys[id]; !ok {
		return errors.New("agent: key not found")
	}
	delete(s.keys, id)
	return nil
}

// RemoveAll implements part of the [agent.Agent] interface.
//
// This implementation only removes keys from the local list, it does not
// affect what is stored on the secrets server.
func (s *Server) RemoveAll() error {
	s.μ.Lock()
	defer s.μ.Unlock()
	clear(s.keys)
	return nil
}

// Lock implements part of the [agent.Agent] interface.
func (s *Server) Lock(passphrase []byte) error {
	s.μ.Lock()
	defer s.μ.Unlock()
	if s.locked {
		return errors.New("agent: already locked")
	}
	s.locked = true
	s.passphrase = string(passphrase)
	s.logPrintf("Agent is now locked")
	return nil
}

// Unlock implements part of the [agent.Agent] interface.
func (s *Server) Unlock(passphrase []byte) error {
	s.μ.Lock()
	defer s.μ.Unlock()
	if !s.locked {
		return errors.New("agent: not locked")
	} else if subtle.ConstantTimeCompare(passphrase, []byte(s.passphrase)) == 0 {
		return errors.New("agent: incorrect passphrase")
	}
	s.locked = false
	s.passphrase = ""
	s.logPrintf("Agent is now unlocked")
	return nil
}

// Signers implements part of the [agent.Agent] interface.
func (s *Server) Signers() ([]ssh.Signer, error) {
	s.μ.Lock()
	defer s.μ.Unlock()
	out := make([]ssh.Signer, 0, len(s.keys))
	for _, key := range s.keys {
		out = append(out, key.Signer)
	}
	return out, nil
}

// Update attempts to update the list of keys from the secrets service.
// It is safe to call Update concurrently with client access.
// In case of error, the existing list of keys is not modified.
func (s *Server) Update(ctx context.Context) error {
	ss, err := s.setecClient.List(ctx)
	if err != nil {
		return err
	}
	found := make(map[string]api.SecretVersion)
	for _, sec := range ss {
		if !strings.HasPrefix(sec.Name, s.prefix) {
			continue // wrong prefix, skip this one
		}
		found[sec.Name] = sec.ActiveVersion
	}

	have := s.fillKnown(found)
	for name := range found {
		sec, err := s.setecClient.Get(ctx, name)
		if err != nil {
			return fmt.Errorf("get %q: %w", name, err)
		}
		s.logPrintf("[update] fetched %q version %d", name, sec.Version)
		key, err := parseStoredKey(name, sec.Version, sec.Value)
		if err != nil {
			s.logPrintf("[update] WARNING: skipped invalid key %q (%v)", name, err)
			continue
		}
		have[key.mapID()] = key
	}

	s.μ.Lock()
	defer s.μ.Unlock()
	s.keys = have
	return nil
}

// fillKnown returns a map of those secrets listed in found that are already
// resident in the local cache with the same version. The secrets reported in
// the result are removed from found.
func (s *Server) fillKnown(found map[string]api.SecretVersion) map[string]*sshKey {
	s.μ.Lock()
	defer s.μ.Unlock()
	out := make(map[string]*sshKey)
	for id, key := range s.keys {
		if v, ok := found[key.Name]; ok && v == key.Version {
			out[id] = key
			delete(found, key.Name)
			s.logPrintf("[update] keep %q version %d", key.Name, key.Version)
		}
	}
	return out
}

func (s *Server) logPrintf(msg string, args ...any) {
	if s.logf != nil {
		s.logf(msg, args...)
	}
}

type sshKey struct {
	Name    string            // secret name in setec
	Version api.SecretVersion // latest version
	Signer  ssh.Signer        // the private (signing) key
	Comment string            // if provided, the public key comment
}

func publicKeyID(key ssh.PublicKey) string {
	h := sha256.Sum256(key.Marshal())
	return fmt.Sprintf("%x", h[:])
}

func (s *sshKey) mapID() string {
	return publicKeyID(s.Signer.PublicKey())
}

// parseStoredKey parses the stored version of a secret from data.
// The contents must be a PEM formatted OpenSSH private key in one of
// the supported key formats (RSA, ED25519, DSA, etc.).
func parseStoredKey(name string, version api.SecretVersion, data []byte) (*sshKey, error) {
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, err
	}

	// Now we know data was a valid PEM-formatted key, grobble around for the comment.
	return &sshKey{
		Name:    name,
		Version: version,
		Signer:  signer,
		Comment: parseComment(data),
	}, nil
}

// parseComment extracts the public key comment field from the PEM-encoded key.
// It returns "" if no comment could be found.
func parseComment(key []byte) string {
	blk, _ := pem.Decode(key)

	// See: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
	s := newScanner(blk.Bytes)

	// Check magic format header.
	if err := s.scanLiteral("openssh-key-v1\x00"); err != nil {
		return "" // not a key file, or some antique version
	}
	cipher, err := s.scanString()
	if err != nil || string(cipher) != "none" {
		return "" // encrypted contents, we can't read them
	}
	// Skip kdfname, kdfoptions, which we don't care about.
	if err := s.skipStrings(2); err != nil {
		return ""
	}
	// The next field is the number of keys. This could in theory be any value,
	// but OpenSSH hardcodes it to 1.
	if nk, err := s.scanUint32(); err != nil || nk != 1 {
		return ""
	}
	// Skip the public keys, as the comment (if any) is with the private key.
	if err := s.skipStrings(1); err != nil {
		return ""
	}

	// The rest of the packet should be a bundle of private keys.
	// Because we know cipher is "none", it is plaintext, but there may
	// be some padding at the end.
	pkeys, err := s.scanString()
	if err != nil {
		return ""
	}

	pk := newScanner(pkeys)
	// Skip the two 32-bit validity nonces.
	if err := pk.skipBytes(8); err != nil {
		return ""
	}
	// The rest of the bundle depends on what type of key this is, but
	// the last string field will be the comment (if any).
	var last string
	for !pk.atEOF() {
		s, err := pk.scanString()
		if err != nil {
			break
		}
		last = string(s)
	}
	return last
}

// A scanner is a minimal scanner for a slice of bytes representing an OpenSSH
// key file. The methods of this type alias (but do not modify) the input.
type scanner struct {
	buf []byte
}

func newScanner(data []byte) *scanner {
	return &scanner{buf: data}
}

// atEOF reports whether s has any further contents.
func (s *scanner) atEOF() bool { return len(s.buf) == 0 }

// skipBytes advances past the first n bytes of the input.
func (s *scanner) skipBytes(n int) error {
	if len(s.buf) < n {
		return fmt.Errorf("got %d bytes, want %d", len(s.buf), n)
	}
	s.buf = s.buf[n:]
	return nil
}

// skipStrings advances past the next n length-prefixed strings.
func (s *scanner) skipStrings(n int) error {
	for n > 0 {
		if _, err := s.scanString(); err != nil {
			return err
		}
		n--
	}
	return nil
}

// scanLiteral advances past the specified prefix of the input.
func (s *scanner) scanLiteral(want string) error {
	rest, ok := bytes.CutPrefix(s.buf, []byte(want))
	if !ok {
		return fmt.Errorf("missing %q", want)
	}
	s.buf = rest
	return nil
}

// scanString consumes and returns a length-prefixed string.
func (s *scanner) scanString() ([]byte, error) {
	n32, err := s.scanUint32()
	if err != nil {
		return nil, err
	}
	n := int(n32)
	if n > len(s.buf) {
		return nil, fmt.Errorf("got %d bytes, want %d", len(s.buf), n)
	}
	out := s.buf[:n]
	s.buf = s.buf[n:]
	return out, nil
}

// scanUint32 consumes and returns a big-endian 32-bit integer.
func (s *scanner) scanUint32() (uint32, error) {
	if len(s.buf) < 4 {
		return 0, fmt.Errorf("got %d bytes, want 4", len(s.buf))
	}
	out := binary.BigEndian.Uint32(s.buf)
	s.buf = s.buf[4:]
	return out, nil
}
