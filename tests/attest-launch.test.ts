// L2 launch attestation: a guest's signer door attests that a room was launched
// holding exactly these doors (its manifest). Same signer-door mechanism as L3;
// the level differs. Verifies signature + that an L3 can link back by digest.
import { describe, test, expect, beforeAll } from "bun:test";
import { tmpdir } from "node:os";
import { mkdtempSync } from "node:fs";
import { join } from "node:path";

import { handleRequest, loadOrCreateKey, verifySignature, canonicalJson, sha256 } from "../keeperd";
import type { L3Attestation } from "../keeperd";

describe("attest-launch (L2 launch attestation)", () => {
  beforeAll(() => {
    loadOrCreateKey(join(mkdtempSync(join(tmpdir(), "kd-l2-")), "key.pem"));
  });

  // The manifest = the room's resolved doors (authority = held references).
  const manifest = {
    room: "claude-box",
    doors: [
      { name: "keeper", grants: "signed git writes" },
      { name: "beads", grants: "task reads" },
    ],
  };

  test("signs an L2 over the room + its held doors; verifiable + linkable", async () => {
    const resp = await handleRequest(
      JSON.stringify({ id: "1", method: "attest-launch", params: { subject: "box-abc", manifest } }),
    );
    expect(resp.ok).toBe(true);
    const r = resp.result as {
      subject: string;
      manifestDigest: string;
      l2LaunchDigest: string;
      attestation: L3Attestation;
    };

    expect(r.subject).toBe("box-abc");
    // The digest binds the actual held doors.
    expect(r.manifestDigest).toBe(sha256(canonicalJson(manifest)));
    // The signature verifies under the daemon's (launching guest's) key.
    expect(verifySignature(canonicalJson(r.attestation.statement), r.attestation.signature)).toBe(true);
    // The subject of the statement is the launched room, digested by its manifest.
    const stmt = r.attestation.statement as { subject: Array<{ digest: { sha256?: string } }> };
    expect(stmt.subject[0].digest.sha256).toBe(r.manifestDigest);
    // l2LaunchDigest is the content-address an L3 write links back to.
    expect(r.l2LaunchDigest).toBe(sha256(canonicalJson(r.attestation.statement)));
  });

  test("a different door set yields a different manifest digest", async () => {
    const a = await handleRequest(
      JSON.stringify({ id: "2", method: "attest-launch", params: { subject: "b", manifest: { doors: ["keeper"] } } }),
    );
    const b = await handleRequest(
      JSON.stringify({ id: "3", method: "attest-launch", params: { subject: "b", manifest: { doors: ["keeper", "beads"] } } }),
    );
    expect((a.result as { manifestDigest: string }).manifestDigest).not.toBe(
      (b.result as { manifestDigest: string }).manifestDigest,
    );
  });

  test("rejects a missing manifest (fail closed)", async () => {
    const resp = await handleRequest(
      JSON.stringify({ id: "4", method: "attest-launch", params: { subject: "x" } }),
    );
    expect(resp.ok).toBe(false);
    expect(resp.error?.code).toBe("INVALID_PARAMS");
  });
});
