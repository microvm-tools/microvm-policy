# microvm-policy

Egress and filesystem containment for microVMs, as a reusable policy
layer. Any [microvm.nix](https://github.com/microvm-nix/microvm.nix) consumer
can run the same tied-down scheme: default-deny egress through a
credential-holding host proxy, and a workspace that the guest cannot write
through to the host.

It knows nothing about any particular VM or what runs in it: a JSON config
goes into the proxy, a JSONL audit log comes out, and the guest modules take
their layout from the `microvmPolicy.*` options. The host-side glue — how the
VM is launched, how the netdev is sealed, which endpoints a given workload
needs — stays in the consumer.

## What's here

- **`proxy/`** — the egress proxy (Go, standard library only). An opaque
  `CONNECT` forward proxy with a host\:port allowlist, a reverse-proxy leg for
  LLM endpoints that strips client-supplied credentials and injects the key
  held on the host (path-allowlisted: a grant covers its subtree, or with a
  trailing `$` only the exact path; no TLS interception) — from an
  environment variable, or from a file a refresher renews (`keyFile`, with an
  `expires_at`; a missing or expired file refuses the request), upstream-proxy
  chaining, and a one-line-per-decision JSONL audit log. Modes: `enforce`
  (deny off-allowlist) and `log` (allow but audit as `would_deny` — the
  "shadow" rung). Per endpoint, an optional session budget (see below).
- **`egress-report.sh`** — host-side pcap summariser and live allowlist
  matcher, for observe-only monitoring, and a verdict over the proxy's audit
  log for sealed runs (`packages.egress-report`).
- **`modules/egress.nix`** — guest module for the sealed modes: static
  resolver emptied under seal, a boot-time seal self-test, ssh routed
  through the proxy, and the proxy env handed to system services that need
  the network (`microvmPolicy.proxyEnv.services`, default `nix-daemon`, so
  substitutes and fixed-output fetches work while sealed).
- **`modules/workspace.nix`** — the workspace write-guard (read-only binds
  over host-executing config paths) and ephemeral overlay mode, plus
  `vm-work-diff`.
- **`modules/policy.nix`** — the `microvmPolicy.*` options that decouple the
  modules from any one VM's layout.
- **`allowlists/common.txt`** — generic development-infrastructure allowlist
  (registries, caches, source hosting). Workload-specific host lists belong to
  the consumer.

## Using it

```nix
{
  # pin a release: github:nix-gizmos/microvm-policy/vX.Y.Z
  inputs.microvm-policy.url = "github:nix-gizmos/microvm-policy";
  # in a nixosSystem:
  imports = [ microvm-policy.nixosModules.default ];
  # launcher glue uses:
  #   microvm-policy.packages.${system}.egress-proxy
  #   microvm-policy.packages.${system}.egress-report
  #   ${microvm-policy}/allowlists/common.txt
}
```

Set `microvmPolicy.stateFile` / `workspaceDir` / `agentHome` / `agentUser` if
your layout differs from the defaults (`/home/agent/.microvm-env`, `/work`,
`/home/agent`, `agent`).

### Without QEMU's user-mode netdev (KubeVirt and other platforms)

The defaults describe a microvm.nix guest: the launcher writes the state file
into a share, seals slirp with `restrict=on` + one `guestfwd`, and slirp's
resolver is `10.0.2.3`. Where the platform owns the hypervisor — a KubeVirt
VM on a pod network, say — the seal is a default-deny network policy for the
VM whose only egress is the proxy, and the guest is told so with:

```nix
microvmPolicy = {
  stateFile = "/etc/vdesk/policy.env";     # written by cloud-init write_files
  stateAfter = [ "cloud-init.service" ];   # order the readers after its writer
  egress = {
    nameservers = null;          # keep the platform's DHCP resolver (open modes)
    proxyAddress = "10.96.0.31:3128"; # fallback if the file has no EGRESS_PROXY_ADDR
    proxyEnvironment = true;     # export HTTP(S)_PROXY/NO_PROXY under seal
    # The seal self-test's negative control: reachable without the seal.
    sealProbes = [ "10.96.0.1:443" "10.96.0.10:53" ]; # API server, DNS
  };
};
```

The workspace guard has an opt-out shape for guests that are less trusted
than the machines their workspace reaches:

```nix
microvmPolicy.workspaceGuard = {
  defaultOn = true;                 # WORKSPACE_GUARD=0 opts out
  repoDepth = 3;                    # boot-time binds in every repo found
  apparmor = {                      # + a kernel rule for repos made later
    enable = true;
    units = [ "user@" "sshd" ];     # what the workload runs under
  };
};
```

`tests/workspace-guard.nix` runs it: existing and cloned-after-boot
repositories, submodules (their git dirs under `.git/modules`, and under
`.git/worktrees/<wt>/modules` for a linked worktree; their hooks also when
initialised after boot), per-worktree config,
a submodule named `objects`, a workspace root that is itself a linked worktree,
names with spaces and glob characters, guarded and opted out, and the two documented
limits.

The state file's keys are the same either way. The boot-time seal self-test needs
two controls: the proxy must answer (positive), and every seal probe — an
address reachable only while the seal is absent, from `sealProbes` or
`EGRESS_SEAL_PROBE` in the state file — must be refused (negative). A failed
or inconclusive test fails `egress-seal.service` and leaves
`/run/egress-seal-failed`. `tests/guest-pod-network.nix`
runs this shape, with nftables standing in for the platform's policy.

For a complete consumer, see
[claude-microvm](https://github.com/nix-gizmos/agent-vm): its
`flake.nix` imports the modules, builds the per-agent allowlists on top of
`common.txt`, and its launcher seals the VM's netdev and runs `egress-proxy`
and `egress-report` on the host.

### Session budget for a model-API endpoint

An endpoint can cap what one proxy process — one session — spends on it, and
report what it spent:

```json
{
  "usageFile": "/run/…/usage.json",
  "endpoints": [{
    "prefix": "/anthropic", "upstream": "https://api.anthropic.com",
    "keyEnv": "ANTHROPIC_API_KEY", "header": "x-api-key",
    "allowedPaths": ["/v1/messages"],
    "usage": "anthropic",
    "budget": {"maxRequests": 5000, "maxTokens": 20000000}
  }]
}
```

- `usage` names how to read token usage out of responses: `"anthropic"` (the
  Messages API, streamed or not). It meters `/v1/messages`; token counting
  (`/v1/messages/count_tokens`) is free. The proxy drops the client's
  `Accept-Encoding` (and `Range`) on a metered path so the body it reads is
  plain text; the transport still negotiates gzip upstream. Without `usage`,
  tokens are not counted.
- `budget.maxRequests` counts requests sent upstream; `budget.maxTokens`
  counts input, cache creation, cache reads and output, summed, and needs
  `usage`. Either may be 0 (no limit on that axis), not both.
- Once either limit is reached, further requests on the endpoint are refused
  with **403** — not 429, which API clients retry — and audited as
  `over_budget`, in both modes: a budget is a spending limit, not an egress
  rule the shadow rung relaxes. A denied path, a request refused for want of a
  credential, and one whose connection to the upstream was never made spend
  nothing.
- **Under `maxTokens` the meter fails closed.** A successful response on a
  metered path whose usage cannot be read — none in it, a body past 32 MiB, an
  encoding the transport did not undo, a stream cut before its first event —
  counts as `unknownUsage`, and with a token limit the endpoint is spent from
  then on: what the session spent is no longer known. A path the proxy cannot
  meter at all — under a `/v1/messages` grant, the batches, billed later — is
  refused (`over_budget`) while a token limit is set. Without one, both pass
  and are only counted.
- The check is made before a request goes upstream, so a request already in
  flight finishes: a session can overshoot `maxTokens` by what its concurrent
  requests return. A stream cut short is charged what it reported by then —
  its input in full, its output only as of the last count the API sent.
- `usageFile`, when set, is written as the config loads — the proxy does not
  start without it — and replaced (whole, atomically) after each response and
  refusal: per endpoint `requests`, `refused`, `tokens` (`input`,
  `cacheCreation`, `cacheRead`, `output`; null when not metered),
  `unknownUsage`, `budget`, and `exhausted`.

### Judging a run: `egress-report verdict`

```sh
egress-report verdict <audit.jsonl>
```

reads the proxy's audit log from a sealed run and answers one question: did
anything other than the model API leave the VM, or try to? A run is clean
when every decision in the log is an allowed request to a reverse-proxied
endpoint (`kind: api`, `decision: allow`). An allowed tunnel counts against
it as much as a denied one — the point is that nothing else was reached —
and so do a denied API path, a shadow-mode `would_deny`, and a request
refused past its budget (`over_budget`): the run did not finish within what it
was given.

| Exit | Meaning | Output |
|------|---------|--------|
| 0 | clean (an empty log too: the proxy saw nothing) | one line: `egress verdict: clean — N model-API request(s), no other egress` |
| 2 | not clean | `egress verdict: NOT CLEAN — …`, then each other decision, counted: `decision kind host:port` (`host/path` for an API one) |
| 65 | a line is not a proxy decision — truncated, blank, foreign | `egress verdict: INVALID — …` with the first such line's number |
| 66 | no log at the path | error on stderr |

A log that cannot be read is never clean: an audit run should treat 65 and
66 the way it treats 2.

## Checks

`nix flake check` runs the proxy's Go unit tests, the `egress-report`
summariser against a synthesised capture and its verdict against synthesised
audit logs, a multi-node `nixosTest` (`egress-integration`) that drives the
real proxy — reverse-proxy strip/inject, path allowlist, `CONNECT` allow/deny
with port grants, upstream-proxy chaining, a session budget, and `verdict` on
its real log —
across four VMs, and one (`guest-pod-network`) that
runs the guest module without slirp: policy as instance data, the proxy
environment exported by the guest, direct egress refused.

## Development

```sh
nix develop          # pinned Go (go-overlay), golangci-lint, gofumpt, release tooling
make hooks           # once per clone: lint on commit
make lint test build # the Go gates CI runs; `make test` enforces 80% coverage
make check           # nix flake check, including the nixosTests (needs KVM)
make diff-closures   # what a flake.lock bump actually changes
```

Commits follow [Conventional Commits](https://www.conventionalcommits.org/):
the type decides the next version and the release-notes section.

## Releasing

```sh
make release-tag-preview   # the version gsemver would cut
make release-tag           # write VERSION, commit, signed tag, push
```

The tag push runs CI's `release` job: `make release` renders the notes with
git-cliff (`cliff.toml`) and publishes the GitHub release. `make
release-notes` previews them. `VERSION` is the single source of truth; the
flake reads it for the package version and stamps it into `egress-proxy
-version`.

## Design

The rationale for each mechanism is in the header comment of the file that
implements it (`modules/*.nix`, `proxy/*.go`).
