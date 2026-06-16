# The capability-aware provenance chain (L1 → L2 → L3)

**SLSA Provenance v1** format with OCAP extensions, three levels, linked by digest.
Each level is an in-toto Statement v1 with a SLSA Provenance v1 predicate. The
OCAP capability surface (doors granted/denied) lives in `externalParameters.capabilities`;
chain back-references live in the `ocap_links` extension field. A verifier walks
`ocap_links` up the chain.

```
  L1  image                  L2  launch                   L3  git write
  ───────────                ─────────────                ──────────────
  subject: the               subject: a launch id         subject: a git object
   box image digest           (image digest + nonce)       (commit / tree sha)
  buildType: ocap-image      buildType: ocap-launch       buildType: ocap-write
  builder: nix flake         builder: launcherd           builder: keeperd
  externalParameters:        externalParameters:          externalParameters:
   capabilities: none          capabilities: the OCAP       capabilities: same
   (build-time)                 manifest (doors/denied)       manifest digest
  resolvedDependencies:      ocap_links: → L1 image       ocap_links: → L2 launch
   flake.lock inputs         signed by: launcher key      signed by: keeper key
  signed by: builder

        ▲                            ▲                            ▲
        └──────── ocap_links ────────┴──────── ocap_links ────────┘
     "this commit was produced by a launch of THIS image holding EXACTLY
      these doors, built reproducibly from THIS flake."
```

## L1 — image provenance  *(lives in claude-box: `flake.nix` / CI)*

- **subject:** the `claude-personal:dev` OCI image digest.
- **buildType:** `https://claude.ai/buildTypes/ocap-image/v1`
- **builder:** `https://claude.ai/builders/nix-flake/v1` with version = flake rev
- **resolvedDependencies:** the `flake.lock` inputs (nixpkgs rev, prx release).
- **externalParameters.capabilities:** *empty* — a freshly built image holds no
  granted doors; authority is only ever added at launch.
- **signed by:** the build identity (cosign keyless / a CI OIDC identity).

This is the plain "signed artifact" win: anyone can verify the image they run is
the one nix built from the pinned flake.

> **Implemented** (in claude-box): `nix run .#provenance -- --image-digest
> sha256:<hex>` emits this statement (`provenance.ts`), pulling materials from
> `flake.lock` + `flake.nix`. Sign the emitted statement downstream, e.g.
> `cosign attest --predicate <stmt> --type slsaprovenance1 <image-ref>`.

## L2 — launch attestation  *(launcherd signs)*

- **subject:** a launch id = `image digest + nonce` (one per `claude-box … run`).
- **buildType:** `https://claude.ai/buildTypes/ocap-launch/v1`
- **externalParameters.capabilities:** the exact manifest the launcher computed —
  `manifestDigest` = sha256 of the `$CLAUDE_BOX_CAPABILITIES` JSON, plus the
  granted `doors[]` and `denied[]`. This is the OCAP surface, attested.
- **ocap_links:** → the L1 image digest (so the launch is tied to a known image).
- **signed by:** the **launcherd key**.

## L3 — git-write attestation  *(lives in keeperd)*

- **subject:** the git object keeperd just produced (commit / pushed ref sha).
- **buildType:** `https://claude.ai/buildTypes/ocap-write/v1`
- **externalParameters.capabilities.manifestDigest:** the *same* digest as L2 —
  this is the binding. The signed commit carries proof of the authority context
  that requested it.
- **ocap_links:** → the L2 launch digest (→ which links → the L1 image).
- **signed by:** the keeper key.

## Verification (what a consumer checks)

1. L1: image digest matches a SLSA Provenance v1 statement whose builder is
   the expected flake rev, resolvedDependencies match `flake.lock`, signature valid.
2. L3: the commit has a statement linking (via `ocap_links`) to an L2 launch
   that links to that L1 image; signatures valid at L2 and L3.
3. Policy: the attested `capabilities` (in `externalParameters`) are within what
   the commit's target should have required (e.g. a write to `main` came from a
   box that actually held `--keeper`, and held nothing it shouldn't have).

The result: a single verifiable line from **reproducible image → the authority a
launch held → the signed commit** — provenance that includes *capability
context*, not just build lineage. And it's SLSA tooling compatible.
