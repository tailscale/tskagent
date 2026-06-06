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

> [!NOTE]
> Because `tskagent` gets its keys from setec, and does not have any way to
> prompt a user for a passphrase, the keys stored in setec must not have a
> passphrase set.  If you are generating a key with `ssh-keygen`, for example,
> use `-N ''` to specify that no passphrase should be required, or enter an
> empty line when prompted.

By default, keys are loaded from setec only once when the agent starts up.
Use `--update` to make it poll at the specified interval for new secret
versions.
The agent does not allow the client to add new secrets. It does allow the
client to "delete" the local copy of a secret from the agent (`ssh-add -d`),
but note that this only affects the agent's copy, it does not remove the key
from setec.

[setec]: https://github.com/tailscale/setec

### Example: Generate and Install a Key

Here is an example of how to generate and upload a private key using
`ssh-keygen` and the `setec` command-line tool:

```shell
# Note: Use -N '' to specify an empty passphrase.
% ssh-keygen -N '' -C 'Deploy production services' -t ed25519 -f deploy-access.key

% setec put prod/example/ssh-keys/deploy-access --from-file deploy-access.key --verbatim
```
