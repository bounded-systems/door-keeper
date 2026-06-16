/**
 * keeperd tests — pure unit tests (no daemon needed).
 *
 * Tests request handling, signing, verification, and L3 attestation.
 */

import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { tmpdir } from "node:os";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createPublicKey, verify } from "node:crypto";
import {
  handleRequest,
  loadOrCreateKey,
  signData,
  verifySignature,
  sha256,
  buildL3Attestation,
  gitExec,
  VERSION,
} from "../keeperd";
import type { SigningKey, L3Attestation } from "../keeperd";
import { IN_TOTO_STATEMENT_TYPE } from "../contract/types";
import { SLSA_PROVENANCE_V1, BUILD_TYPES } from "../contract/slsa";

describe("keeperd", () => {
  describe("protocol", () => {
    test("rejects invalid JSON", async () => {
      const resp = await handleRequest("not json");
      expect(resp.ok).toBe(false);
      expect(resp.error?.code).toBe("PARSE_ERROR");
    });

    test("rejects missing id", async () => {
      const resp = await handleRequest(JSON.stringify({ method: "status" }));
      expect(resp.ok).toBe(false);
      expect(resp.error?.code).toBe("INVALID_REQUEST");
    });

    test("rejects missing method", async () => {
      const resp = await handleRequest(JSON.stringify({ id: "1" }));
      expect(resp.ok).toBe(false);
      expect(resp.error?.code).toBe("INVALID_REQUEST");
    });

    test("rejects unknown method", async () => {
      const resp = await handleRequest(JSON.stringify({ id: "1", method: "bogus" }));
      expect(resp.ok).toBe(false);
      expect(resp.error?.code).toBe("UNKNOWN_METHOD");
    });

    test("status returns daemon info", async () => {
      const resp = await handleRequest(JSON.stringify({ id: "1", method: "status" }));
      expect(resp.ok).toBe(true);
      expect(resp.id).toBe("1");

      const result = resp.result as Record<string, unknown>;
      expect(result.version).toBe(VERSION);
      expect(typeof result.uptime).toBe("number");
    });

    test("response echoes request id", async () => {
      const id = `test-${Date.now()}`;
      const resp = await handleRequest(JSON.stringify({ id, method: "status" }));
      expect(resp.id).toBe(id);
    });
  });

  describe("signing", () => {
    let tempDir: string;
    let keyPath: string;
    let key: SigningKey;

    beforeAll(() => {
      tempDir = mkdtempSync(join(tmpdir(), "keeperd-test-"));
      keyPath = join(tempDir, "test.key");
      key = loadOrCreateKey(keyPath);
    });

    afterAll(() => {
      rmSync(tempDir, { recursive: true, force: true });
    });

    test("loadOrCreateKey generates key if not exists", () => {
      expect(key.privateKey).toBeDefined();
      expect(key.publicKeyPem).toBeDefined();
      expect(key.keyId).toBeDefined();
      expect(key.keyId.length).toBe(16);
    });

    test("loadOrCreateKey loads existing key", () => {
      const key2 = loadOrCreateKey(keyPath);
      expect(key2.keyId).toBe(key.keyId);
      expect(key2.publicKeyPem).toBe(key.publicKeyPem);
    });

    test("signData produces base64 signature", () => {
      const sig = signData("hello world");
      expect(/^[A-Za-z0-9+/]+=*$/.test(sig)).toBe(true);
    });

    test("verifySignature validates correct signature", () => {
      const data = "test data";
      const sig = signData(data);
      expect(verifySignature(data, sig)).toBe(true);
    });

    test("verifySignature rejects wrong data", () => {
      const sig = signData("original data");
      expect(verifySignature("wrong data", sig)).toBe(false);
    });

    test("verifySignature rejects wrong signature", () => {
      const data = "test data";
      const wrongSig = Buffer.from("wrong").toString("base64");
      expect(verifySignature(data, wrongSig)).toBe(false);
    });

    test("sign method via protocol", async () => {
      const data = Buffer.from("test data").toString("base64");
      const resp = await handleRequest(
        JSON.stringify({ id: "1", method: "sign", params: { data } })
      );

      expect(resp.ok).toBe(true);
      const result = resp.result as { signature: string; keyId: string };
      expect(result.signature).toBeDefined();
      expect(result.keyId).toBe(key.keyId);
    });

    test("verify method via protocol", async () => {
      const original = "test data";
      const data = Buffer.from(original).toString("base64");
      const sig = signData(original);

      const resp = await handleRequest(
        JSON.stringify({ id: "1", method: "verify", params: { data, signature: sig } })
      );

      expect(resp.ok).toBe(true);
      const result = resp.result as { valid: boolean; keyId?: string };
      expect(result.valid).toBe(true);
    });

    test("getPublicKey returns key info", async () => {
      const resp = await handleRequest(JSON.stringify({ id: "1", method: "getPublicKey" }));

      expect(resp.ok).toBe(true);
      const result = resp.result as { publicKey: string; keyId: string };
      expect(result.publicKey).toBe(key.publicKeyPem);
      expect(result.keyId).toBe(key.keyId);
    });
  });

  describe("sha256", () => {
    test("produces 64-char hex digest", () => {
      const digest = sha256("hello world");
      expect(digest.length).toBe(64);
      expect(/^[a-f0-9]{64}$/.test(digest)).toBe(true);
    });

    test("is deterministic", () => {
      const a = sha256("test data");
      const b = sha256("test data");
      expect(a).toBe(b);
    });

    test("different inputs produce different digests", () => {
      const a = sha256("input a");
      const b = sha256("input b");
      expect(a).not.toBe(b);
    });
  });

  describe("L3 attestation", () => {
    let tempDir: string;
    let keyPath: string;

    beforeAll(() => {
      tempDir = mkdtempSync(join(tmpdir(), "keeperd-l3-test-"));
      keyPath = join(tempDir, "test.key");
      loadOrCreateKey(keyPath);
    });

    afterAll(() => {
      rmSync(tempDir, { recursive: true, force: true });
    });

    const commitSha = "abc123def456abc123def456abc123def456abc1";
    const repo = "/work";
    const ref = "refs/heads/main";
    const manifestDigest = "manifest123";

    test("produces SLSA Provenance v1 statement", () => {
      const attestation = buildL3Attestation(commitSha, repo, ref, manifestDigest);

      expect(attestation.statement._type).toBe(IN_TOTO_STATEMENT_TYPE);
      expect(attestation.statement.predicateType).toBe(SLSA_PROVENANCE_V1);
    });

    test("uses ocap-write buildType", () => {
      const attestation = buildL3Attestation(commitSha, repo, ref, manifestDigest);

      expect(attestation.statement.predicate.buildDefinition.buildType).toBe(
        BUILD_TYPES.write
      );
    });

    test("subject is the git commit", () => {
      const attestation = buildL3Attestation(commitSha, repo, ref, manifestDigest);

      expect(attestation.statement.subject).toHaveLength(1);
      expect(attestation.statement.subject[0].name).toBe(commitSha);
      expect(attestation.statement.subject[0].digest?.gitCommit).toBe(commitSha);
    });

    test("includes manifestDigest in capabilities", () => {
      const attestation = buildL3Attestation(commitSha, repo, ref, manifestDigest);
      const caps = attestation.statement.predicate.buildDefinition.externalParameters
        .capabilities as Record<string, unknown>;

      expect((caps.manifestDigest as { sha256: string }).sha256).toBe(manifestDigest);
    });

    test("includes repo and ref in externalParameters", () => {
      const attestation = buildL3Attestation(commitSha, repo, ref, manifestDigest);
      const params = attestation.statement.predicate.buildDefinition.externalParameters;

      expect(params.repo).toBe(repo);
      expect(params.ref).toBe(ref);
    });

    test("links to L2 launch when provided", () => {
      const l2Digest = "launch456";
      const attestation = buildL3Attestation(commitSha, repo, ref, manifestDigest, l2Digest);
      const links = attestation.statement.predicate.runDetails.ocap_links;

      expect(links).toHaveLength(1);
      expect(links![0].level).toBe("launch");
      expect(links![0].digest.sha256).toBe(l2Digest);
    });

    test("signature is valid", () => {
      const attestation = buildL3Attestation(commitSha, repo, ref, manifestDigest);
      const stmtJson = JSON.stringify(attestation.statement);

      expect(verifySignature(stmtJson, attestation.signature)).toBe(true);
    });

    test("statementDigest matches statement", () => {
      const attestation = buildL3Attestation(commitSha, repo, ref, manifestDigest);
      const expectedDigest = sha256(JSON.stringify(attestation.statement));

      expect(attestation.statementDigest).toBe(expectedDigest);
    });
  });

  describe("commit validation", () => {
    test("commit fails without repo", async () => {
      const resp = await handleRequest(
        JSON.stringify({ id: "1", method: "commit", params: { message: "test" } })
      );

      expect(resp.ok).toBe(false);
      expect(resp.error?.code).toBe("INVALID_PARAMS");
    });

    test("commit fails without message (unless amending)", async () => {
      const resp = await handleRequest(
        JSON.stringify({ id: "1", method: "commit", params: { repo: "/tmp" } })
      );

      expect(resp.ok).toBe(false);
      expect(resp.error?.code).toBe("INVALID_PARAMS");
    });

    test("commit fails for nonexistent repo", async () => {
      const resp = await handleRequest(
        JSON.stringify({
          id: "1",
          method: "commit",
          params: { repo: "/nonexistent/repo", message: "test" }
        })
      );

      expect(resp.ok).toBe(false);
      expect(resp.error?.code).toBe("REPO_NOT_FOUND");
    });
  });

  describe("push validation", () => {
    test("push fails without repo", async () => {
      const resp = await handleRequest(
        JSON.stringify({ id: "1", method: "push", params: {} })
      );

      expect(resp.ok).toBe(false);
      expect(resp.error?.code).toBe("INVALID_PARAMS");
    });

    test("push fails for nonexistent repo", async () => {
      const resp = await handleRequest(
        JSON.stringify({ id: "1", method: "push", params: { repo: "/nonexistent/repo" } })
      );

      expect(resp.ok).toBe(false);
      expect(resp.error?.code).toBe("REPO_NOT_FOUND");
    });
  });
});

describe("gitExec", () => {
  test("runs git commands", async () => {
    const result = await gitExec(".", ["--version"]);
    expect(result.ok).toBe(true);
    expect(result.stdout).toContain("git version");
  });

  test("returns error for invalid commands", async () => {
    const result = await gitExec(".", ["invalid-command"]);
    expect(result.ok).toBe(false);
    expect(result.code).not.toBe(0);
  });
});

describe("path translation (lib/keeper.ts)", () => {
  // Import using dynamic import since lib/keeper.ts has async exports
  let translateRepoPath: (repo: string) => string;

  beforeAll(async () => {
    const keeper = await import("../lib/keeper");
    translateRepoPath = keeper.translateRepoPath;
  });

  test("returns repo unchanged when CLAUDE_BOX_HOST_REPO is not set", () => {
    const original = process.env.CLAUDE_BOX_HOST_REPO;
    delete process.env.CLAUDE_BOX_HOST_REPO;
    try {
      expect(translateRepoPath("/work")).toBe("/work");
      expect(translateRepoPath("/some/other/path")).toBe("/some/other/path");
    } finally {
      if (original) process.env.CLAUDE_BOX_HOST_REPO = original;
    }
  });

  test("translates /work to host path", () => {
    const original = process.env.CLAUDE_BOX_HOST_REPO;
    process.env.CLAUDE_BOX_HOST_REPO = "/host/project";
    try {
      expect(translateRepoPath("/work")).toBe("/host/project");
      expect(translateRepoPath("/work/")).toBe("/host/project");
    } finally {
      if (original) process.env.CLAUDE_BOX_HOST_REPO = original;
      else delete process.env.CLAUDE_BOX_HOST_REPO;
    }
  });

  test("translates /work/subdir to host path/subdir", () => {
    const original = process.env.CLAUDE_BOX_HOST_REPO;
    process.env.CLAUDE_BOX_HOST_REPO = "/host/project";
    try {
      expect(translateRepoPath("/work/src")).toBe("/host/project/src");
      expect(translateRepoPath("/work/deep/nested/path")).toBe("/host/project/deep/nested/path");
    } finally {
      if (original) process.env.CLAUDE_BOX_HOST_REPO = original;
      else delete process.env.CLAUDE_BOX_HOST_REPO;
    }
  });

  test("does not translate other paths", () => {
    const original = process.env.CLAUDE_BOX_HOST_REPO;
    process.env.CLAUDE_BOX_HOST_REPO = "/host/project";
    try {
      expect(translateRepoPath("/tmp/repo")).toBe("/tmp/repo");
      expect(translateRepoPath("/workspace")).toBe("/workspace"); // not /work
    } finally {
      if (original) process.env.CLAUDE_BOX_HOST_REPO = original;
      else delete process.env.CLAUDE_BOX_HOST_REPO;
    }
  });
});
