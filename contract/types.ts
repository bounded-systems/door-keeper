/**
 * CapabilityProvenance — TypeScript mirror of capability-provenance.v0.1.schema.json.
 *
 * The shared contract both claude-box (producer) and keeperd (signer/verifier)
 * pin. Keep this in lockstep with the JSON Schema; the schema is authoritative.
 * No imports — this file is copied verbatim when the contract is extracted to
 * its own repo (github.com/bounded-systems/ocap-provenance).
 */

export const PREDICATE_TYPE =
  "https://github.com/bounded-systems/ocap-provenance/predicate/CapabilityProvenance/v0.1" as const;

export const IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1" as const;

/** Algorithm -> lowercase hex digest (in-toto DigestSet). */
export type DigestSet = { sha256?: string } & Record<string, string>;

export type ResourceDigest = { name?: string; digest: DigestSet };

export type ChainLevel = "image" | "launch" | "write";

export type Door = { name: string; socket?: string; env?: string; grants?: string };

/** The OCAP surface the actor held — empty at level "image". */
export type Capabilities = {
  workcell?: string;
  /** sha256 of the $CLAUDE_BOX_CAPABILITIES JSON — the value bound launch -> write. */
  manifestDigest?: DigestSet;
  doors?: Door[];
  denied?: { name: string }[];
};

export type Material = { uri: string; digest?: DigestSet };

export type ChainLink = { level: ChainLevel; digest: DigestSet };

export type CapabilityProvenance = {
  level: ChainLevel;
  producer: { kind: "nix-flake" | "keeperd"; id: string };
  image?: ResourceDigest;
  capabilities?: Capabilities;
  materials?: Material[];
  links?: ChainLink[];
  metadata?: { invocationId?: string; startedOn?: string; finishedOn?: string };
};

/** The in-toto Statement envelope carrying a CapabilityProvenance predicate. */
export type CapabilityProvenanceStatement = {
  _type: typeof IN_TOTO_STATEMENT_TYPE;
  subject: ResourceDigest[];
  predicateType: typeof PREDICATE_TYPE;
  predicate: CapabilityProvenance;
};

/** Build the envelope around a predicate + its subject(s). */
export function statement(
  subject: ResourceDigest[],
  predicate: CapabilityProvenance,
): CapabilityProvenanceStatement {
  return {
    _type: IN_TOTO_STATEMENT_TYPE,
    subject,
    predicateType: PREDICATE_TYPE,
    predicate,
  };
}
