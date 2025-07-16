# tskagent

[![GoDoc](https://img.shields.io/static/v1?label=godoc&message=reference&color=orchid)](https://pkg.go.dev/github.com/tailscale/tskagent)
[![CI](https://github.com/tailscale/tskagent/actions/workflows/go-presubmit.yml/badge.svg?event=push&branch=main)](https://github.com/tailscale/tskagent/actions/workflows/go-presubmit.yml)

This repository provides a `tskagent` ((T)ailscale (S)SH (K)ey Agent) library
and program that implements the SSH key agent protocol hosting keys stored in
[setec][setec].

To install the agent binary:

```shell
go install github.com/tailscale/tskagent/cmd/tskagent@latest
```

To run the agent, you must provide:

1. The URL of a setec server instance,
2. A non-empty secret name prefix to serve from, and
3. A path to a local socket to serve the agent protocol.

For example:

```shell
tskagent --server https://setec.example.com \
         --prefix prod/example/ssh-keys/ \
         --socket $HOME/.ssh/tskagent.sock
```

Once this is running, you can access the agent using the standard tools, for
example you can list the available secrets by running:

```shell
export SSH_AUTH_SOCK="$HOME/.ssh/tskagent.sock"
ssh-add -L
```

The agent loads all the secrets matching the specified name prefix once at
startup.  The value of each secret must be a PEM-formatted private key. The
agent logs and ignores any secrets that do not have this format.

By default, keys are loaded from setec only once when the agent starts up.
Use `--update` to make it poll at the specified interval for new secret
versions.
The agent does not allow the client to add new secrets. It does allow the
client to "delete" the local copy of a secret from the agent (`ssh-add -d`),
but note that this only affects the agent's copy, it does not remove the key
from setec.

[setec]: https://github.com/tailscale/setec
