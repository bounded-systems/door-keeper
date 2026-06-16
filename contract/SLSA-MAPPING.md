# Mapping CapabilityProvenance to SLSA Provenance v1

CapabilityProvenance can be expressed as a **SLSA Provenance v1** predicate with
structured extensions, gaining interoperability with SLSA tooling while retaining
the novel OCAP semantics.

## Predicate Type

```
https://slsa.dev/provenance/v1
```

(Standard SLSA, not custom — tooling compatibility.)

## Field Mapping

| CapabilityProvenance/v0.1 | SLSA Provenance v1 | Notes |
|---------------------------|--------------------| ------|
| `level` | `buildDefinition.buildType` | URI like `https://claude.ai/buildTypes/ocap-image/v1` |
| `producer` | `runDetails.builder` | `{ id: "...", version: {...} }` |
| `capabilities` | `buildDefinition.externalParameters.capabilities` | The OCAP surface |
| `materials` | `buildDefinition.resolvedDependencies` | Direct 1:1 mapping |
| `links` | `runDetails.ocap_links` | Extension field (chain back-refs) |
| `metadata` | `runDetails.metadata` | Direct 1:1 mapping |
| `image` | `subject` + `buildDefinition.externalParameters.image` | Subject is the digest |

## buildType URIs (one per level)

```
https://claude.ai/buildTypes/ocap-image/v1    # L1: nix-built image
https://claude.ai/buildTypes/ocap-launch/v1   # L2: container launch
https://claude.ai/buildTypes/ocap-write/v1    # L3: git write
```

The `buildType` tells verifiers which schema to expect for `externalParameters`.

## Example: L2 Launch Attestation (SLSA format)

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [{ "digest": { "sha256": "<launch-id-digest>" } }],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://claude.ai/buildTypes/ocap-launch/v1",
      "externalParameters": {
        "capabilities": {
          "workcell": "claude-box",
          "manifestDigest": { "sha256": "<manifest-hash>" },
          "doors": [
            { "name": "keeper", "socket": "/run/keeperd.sock", "grants": "signed git writes" }
          ],
          "denied": [
            { "name": "beads" }
          ]
        },
        "image": { "digest": { "sha256": "<image-digest>" } }
      },
      "internalParameters": {},
      "resolvedDependencies": []
    },
    "runDetails": {
      "builder": {
        "id": "https://claude.ai/launcherd/v0.1",
        "version": { "launcherd": "0.1.0" }
      },
      "metadata": {
        "invocationId": "box-abc123",
        "startedOn": "2024-01-15T10:30:00Z"
      },
      "ocap_links": [
        { "level": "image", "digest": { "sha256": "<L1-image-digest>" } }
      ]
    }
  }
}
```

## Why This Works

1. **`externalParameters.capabilities`** — "What the caller requested" is exactly
   what OCAP capabilities are: the authority granted to this invocation.

2. **`buildType`** as discriminator — SLSA's `buildType` URI tells verifiers which
   schema applies to `externalParameters`. Our three levels become three buildTypes.

3. **`ocap_links`** extension — SLSA allows vendor extensions (`<vendor>_<field>`).
   The chain back-references don't fit a standard field, so we add `ocap_links`.

4. **Standard envelope** — `in-toto Statement v1` + `slsa/provenance/v1` means
   existing SLSA verification tooling can parse and validate signatures without
   knowing about OCAP specifics.

## Migration Path

1. Keep `CapabilityProvenance/v0.1` as the canonical internal format (simpler).
2. Add a `toSLSA()` function that converts to SLSA Provenance v1.
3. Emit both formats, or let consumers choose via content negotiation.

This gives us SLSA ecosystem compatibility without losing the OCAP semantics.
