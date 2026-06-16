/**
 * slsa.ts — Convert CapabilityProvenance to SLSA Provenance v1 format.
 *
 * This provides interoperability with SLSA tooling while preserving OCAP semantics.
 * See SLSA-MAPPING.md for the mapping rationale.
 */

import type {
  CapabilityProvenanceStatement,
  CapabilityProvenance,
  ChainLevel,
  DigestSet,
  ResourceDigest,
  Capabilities,
  ChainLink,
  Material,
} from "./types";
import { IN_TOTO_STATEMENT_TYPE } from "./types";

// ── SLSA Provenance v1 types ────────────────────────────────────────────────

export const SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1" as const;

/** SLSA buildType URIs for each OCAP level */
export const BUILD_TYPES = {
  image: "https://claude.ai/buildTypes/ocap-image/v1",
  launch: "https://claude.ai/buildTypes/ocap-launch/v1",
  write: "https://claude.ai/buildTypes/ocap-write/v1",
} as const;

export type SLSADigestSet = Record<string, string>;

export type SLSAResourceDescriptor = {
  uri?: string;
  digest?: SLSADigestSet;
  name?: string;
  downloadLocation?: string;
  mediaType?: string;
  content?: string; // base64
};

export type SLSABuilder = {
  id: string;
  version?: Record<string, string>;
  builderDependencies?: SLSAResourceDescriptor[];
};

export type SLSAMetadata = {
  invocationId?: string;
  startedOn?: string;
  finishedOn?: string;
};

export type SLSABuildDefinition = {
  buildType: string;
  externalParameters: Record<string, unknown>;
  internalParameters?: Record<string, unknown>;
  resolvedDependencies?: SLSAResourceDescriptor[];
};

export type SLSARunDetails = {
  builder: SLSABuilder;
  metadata?: SLSAMetadata;
  byproducts?: SLSAResourceDescriptor[];
  // Extension field for OCAP chain links
  ocap_links?: ChainLink[];
};

export type SLSAProvenanceV1 = {
  buildDefinition: SLSABuildDefinition;
  runDetails: SLSARunDetails;
};

export type SLSAStatement = {
  _type: typeof IN_TOTO_STATEMENT_TYPE;
  subject: SLSAResourceDescriptor[];
  predicateType: typeof SLSA_PROVENANCE_V1;
  predicate: SLSAProvenanceV1;
};

// ── Conversion functions ────────────────────────────────────────────────────

/** Map CapabilityProvenance producer to SLSA builder */
function toBuilder(producer: CapabilityProvenance["producer"]): SLSABuilder {
  const kindToId: Record<string, string> = {
    "nix-flake": "https://claude.ai/builders/nix-flake/v1",
    keeperd: "https://claude.ai/builders/keeperd/v1",
  };

  return {
    id: kindToId[producer.kind] ?? `https://claude.ai/builders/${producer.kind}/v1`,
    version: { ref: producer.id },
  };
}

/** Convert materials to SLSA resolvedDependencies */
function toResolvedDependencies(materials?: Material[]): SLSAResourceDescriptor[] | undefined {
  if (!materials?.length) return undefined;

  return materials.map((m) => ({
    uri: m.uri,
    digest: m.digest as SLSADigestSet | undefined,
  }));
}

/** Convert ResourceDigest to SLSA subject format */
function toSubject(subject: ResourceDigest[]): SLSAResourceDescriptor[] {
  return subject.map((s) => ({
    name: s.name,
    digest: s.digest as SLSADigestSet,
  }));
}

/**
 * Convert a CapabilityProvenanceStatement to SLSA Provenance v1 format.
 *
 * The OCAP-specific fields are placed in:
 * - `buildDefinition.externalParameters.capabilities` — the OCAP surface
 * - `buildDefinition.externalParameters.image` — the box image (if present)
 * - `runDetails.ocap_links` — chain back-references (extension field)
 */
export function toSLSA(stmt: CapabilityProvenanceStatement): SLSAStatement {
  const pred = stmt.predicate;

  const externalParameters: Record<string, unknown> = {};

  // OCAP capabilities go in externalParameters (what the caller requested)
  if (pred.capabilities) {
    externalParameters.capabilities = pred.capabilities;
  }

  // Image reference (for launch/write levels)
  if (pred.image) {
    externalParameters.image = pred.image;
  }

  const slsaPredicate: SLSAProvenanceV1 = {
    buildDefinition: {
      buildType: BUILD_TYPES[pred.level],
      externalParameters,
      internalParameters: {},
      resolvedDependencies: toResolvedDependencies(pred.materials),
    },
    runDetails: {
      builder: toBuilder(pred.producer),
      metadata: pred.metadata,
      // Extension field for chain links
      ocap_links: pred.links,
    },
  };

  return {
    _type: IN_TOTO_STATEMENT_TYPE,
    subject: toSubject(stmt.subject),
    predicateType: SLSA_PROVENANCE_V1,
    predicate: slsaPredicate,
  };
}

/**
 * Convert SLSA Provenance v1 back to CapabilityProvenanceStatement.
 *
 * This is the inverse of toSLSA() — useful for verifiers that receive
 * SLSA-formatted attestations but want to work with the OCAP types.
 */
export function fromSLSA(slsa: SLSAStatement): CapabilityProvenanceStatement {
  const pred = slsa.predicate;
  const buildType = pred.buildDefinition.buildType;

  // Determine level from buildType
  let level: ChainLevel = "image";
  if (buildType === BUILD_TYPES.launch) level = "launch";
  else if (buildType === BUILD_TYPES.write) level = "write";

  // Extract producer from builder
  const builderId = pred.runDetails.builder.id;
  let kind: "nix-flake" | "keeperd" = "keeperd";
  if (builderId.includes("nix-flake")) kind = "nix-flake";

  const producerId = pred.runDetails.builder.version?.ref ?? builderId;

  // Extract capabilities and image from externalParameters
  const extParams = pred.buildDefinition.externalParameters;
  const capabilities = extParams.capabilities as Capabilities | undefined;
  const image = extParams.image as ResourceDigest | undefined;

  // Convert resolvedDependencies back to materials
  const materials: Material[] | undefined = pred.buildDefinition.resolvedDependencies?.map((d) => ({
    uri: d.uri ?? "",
    digest: d.digest as DigestSet | undefined,
  }));

  // Subject conversion
  const subject: ResourceDigest[] = slsa.subject.map((s) => ({
    name: s.name,
    digest: s.digest as DigestSet,
  }));

  return {
    _type: IN_TOTO_STATEMENT_TYPE,
    subject,
    predicateType: "https://github.com/bounded-systems/ocap-provenance/predicate/CapabilityProvenance/v0.1",
    predicate: {
      level,
      producer: { kind, id: producerId },
      image,
      capabilities,
      materials: materials?.length ? materials : undefined,
      links: pred.runDetails.ocap_links,
      metadata: pred.runDetails.metadata,
    },
  };
}
