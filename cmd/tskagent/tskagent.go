// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Program tskagent implements an SSH key agent that runs on a tailnet.
// This documentation needs more detail.
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	"github.com/tailscale/setec/client/setec"
	"github.com/tailscale/tskagent"
)

var flags struct {
	Server string        `flag:"server,Secret server address (required)"`
	Socket string        `flag:"socket,Agent socket path (required)"`
	Prefix string        `flag:"prefix,Secret name prefix (required)"`
	Update time.Duration `flag:"update,Automatic update interval (0 means no updates)"`
}

func main() {
	root := &command.C{
		Name:     command.ProgramName(),
		Help:     "Serve an SSH key agent on the specified socket.",
		SetFlags: command.Flags(flax.MustBind, &flags),
		Run:      command.Adapt(run),
		Commands: []*command.C{
			command.HelpCommand(nil),
			command.VersionCommand(),
		},
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	command.RunOrFail(root.NewEnv(nil).SetContext(ctx), os.Args[1:])
}

func run(env *command.Env) error {
	switch {
	case flags.Server == "":
		return env.Usagef("a secret --server address is required")
	case flags.Socket == "":
		return env.Usagef("an agent --socket path is required")
	case flags.Prefix == "":
		return env.Usagef("a secret name --prefix is required")
	}
	cli := setec.Client{Server: flags.Server}
	lst, err := net.Listen("unix", flags.Socket)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer os.Remove(flags.Socket) // best-effort

	srv := tskagent.NewServer(tskagent.Config{
		Client: cli,
		Prefix: flags.Prefix,
		Logf:   log.Printf,
	})
	if err := srv.Update(env.Context()); err != nil {
		return fmt.Errorf("initialize agent: %w", err)
	}
	if flags.Update > 0 {
		go func() {
			for range time.NewTicker(flags.Update).C {
				if err := srv.Update(env.Context()); err != nil {
					log.Printf("WARNING: Update failed: %v", err)
				}
			}
		}()
		log.Printf("Enabled periodic updates (%v)", flags.Update)
	}
	srv.Serve(env.Context(), lst)
	return nil
}
