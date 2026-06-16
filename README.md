# door-keeper — the git-signing capability door

`door-keeper` is **keeperd** packaged as a standalone, pinned OCI image. keeperd holds the box's
Ed25519 signing key and turns reviewed in-box edits into **signed commits/refs** — the box itself
holds no keys and never writes the host's `.git` directly. It's the write half of the
[claude-box](https://github.com/bounded-systems/claude-box) door model (read half: scoutd; egress:
netd; resolution: concierged).

## Build / run

```sh
nix build .#keeperd-image && podman load -i result
podman run -v doors:/run/doors -v keys:/keys -v repo:/work keeperd
```

`run-keeperd.sh` wraps the macOS/podman-machine TCP bring-up (sockets can't cross the host→VM
boundary). `tests/keeperd.test.ts` covers signing + SLSA attestation.

## Pinned dependencies (vendored mirrors)

keeperd imports the shared substrate; each is a PINNED input and a generated mirror, kept honest
by the `*-mirror` checks (`nix flake check`) — the same pattern as claude-box:

| Dir | Pinned input | Bump |
|---|---|---|
| `contract/` | [`ocap-provenance`](https://github.com/bounded-systems/ocap-provenance) `@28c7a85` | `nix flake update ocap-provenance` + `nix run .#sync-ocap-provenance` |
| `lib/` | [`door-kit`](https://github.com/bounded-systems/door-kit) `@a3ae40e` | `nix flake update door-kit` + `nix run .#sync-door-kit` |
| `guest-room/` | [`guest-room`](https://github.com/bounded-systems/guest-room) `@5bc85b6` | `nix flake update guest-room` + `nix run .#sync-guest-room` |

Keep the `guest-room` rev in lockstep with `door-kit`'s.

_Extracted from claude-box `keeperd.ts` — decomposition epic `prx-ii01`, card 2 (the door template)._
