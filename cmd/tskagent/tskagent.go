// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Program tskagent implements an SSH key agent that runs on a tailnet.
// This documentation needs more detail.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	"github.com/creachadair/taskgroup"
	"github.com/tailscale/setec/client/setec"
	"github.com/tailscale/tskagent"
	"golang.org/x/crypto/ssh/agent"
)

var flags struct {
	Server string `flag:"server,Secret server address (required)"`
	Socket string `flag:"socket,Agent socket path (required)"`
	Prefix string `flag:"prefix,Secret name prefix (required)"`
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

	var g taskgroup.Group
	g.Run(func() {
		<-env.Context().Done()
		log.Printf("Signal received; closing listener")
		lst.Close()
	})
	for {
		conn, err := lst.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("Listener stopped: %v", err)
			}
			break
		}
		g.Go(func() error {
			return agent.ServeAgent(srv, conn)
		})
	}
	g.Wait()
	return nil
}