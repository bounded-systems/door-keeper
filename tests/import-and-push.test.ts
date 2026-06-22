// Integration test for the model-A `import-and-push` method: a host builds a
// commit + a commit-range bundle locally (keyless); keeperd imports the bundle,
// verifies the imported tip is EXACTLY the host commit (fail closed), signed-pushes
// it, and returns a verifiable L3 attestation. Exercises real git + signing.
import { describe, test, expect, beforeAll, afterAll } from "bun:test";
import { tmpdir } from "node:os";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { handleRequest, loadOrCreateKey, verifySignature, gitExec } from "../keeperd";
import type { L3Attestation } from "../keeperd";

const HEX40 = /^[0-9a-f]{40}$/;

describe("import-and-push (model A)", () => {
  let root = "";
  let remote = "";
  let host = "";
  let keeperRepo = "";
  const branch = "GH-1";
  let commitSha = "";

  beforeAll(async () => {
    root = mkdtempSync(join(tmpdir(), "kd-iap-"));
    loadOrCreateKey(join(root, "key.pem")); // sets the module signing key
    remote = join(root, "remote.git");
    await gitExec(root, ["init", "--bare", "-b", "main", remote]);

    // Host: clone, base commit on main, push (so remote + keeperd share the parent).
    host = join(root, "host");
    await gitExec(root, ["clone", remote, host]);
    await gitExec(host, ["config", "user.email", "h@example.com"]);
    await gitExec(host, ["config", "user.name", "host"]);
    writeFileSync(join(host, "a.txt"), "base\n");
    await gitExec(host, ["add", "-A"]);
    await gitExec(host, ["commit", "-m", "base"]);
    await gitExec(host, ["push", "origin", "main"]);

    // keeperd's repo clone (has the parent).
    keeperRepo = join(root, "keeperd");
    await gitExec(root, ["clone", remote, keeperRepo]);
  });

  afterAll(() => rmSync(root, { recursive: true, force: true }));

  test("imports the bundle, verifies the tip, signed-pushes, returns a valid L3", async () => {
    // Host builds the new commit on `branch` + a commit-range bundle (main..branch).
    await gitExec(host, ["checkout", "-b", branch]);
    writeFileSync(join(host, "b.txt"), "feature\n");
    await gitExec(host, ["add", "-A"]);
    await gitExec(host, ["commit", "-m", "feat"]);
    commitSha = (await gitExec(host, ["rev-parse", branch])).stdout.trim();
    expect(commitSha).toMatch(HEX40);

    const bundlePath = join(root, "range.bundle");
    expect((await gitExec(host, ["bundle", "create", bundlePath, `main..${branch}`])).ok).toBe(true);
    const bundleBase64 = readFileSync(bundlePath).toString("base64");

    const resp = await handleRequest(
      JSON.stringify({
        id: "1",
        method: "import-and-push",
        params: {
          repo: keeperRepo,
          bundleBase64,
          commitSha,
          branch,
          remote: "origin",
          manifestDigest: "d".repeat(64),
        },
      }),
    );
    expect(resp.ok).toBe(true);
    const result = resp.result as {
      status: string;
      commitSha: string;
      pushedRef: string;
      signedDerivation?: L3Attestation;
    };
    expect(result.status).toBe("ok");
    expect(result.commitSha).toBe(commitSha);
    expect(result.pushedRef).toBe(`refs/heads/${branch}`);

    // L3 attestation present, subject is the commit, signature verifies.
    expect(result.signedDerivation).toBeDefined();
    const att = result.signedDerivation!;
    expect(verifySignature(JSON.stringify(att.statement), att.signature)).toBe(true);

    // The remote actually received the branch at the host commit.
    const ls = await gitExec(root, ["ls-remote", remote, `refs/heads/${branch}`]);
    expect(ls.stdout).toContain(commitSha);
  });

  test("fails closed when the imported tip != the requested commitSha", async () => {
    const bundleBase64 = readFileSync(join(root, "range.bundle")).toString("base64");
    const resp = await handleRequest(
      JSON.stringify({
        id: "2",
        method: "import-and-push",
        params: {
          repo: keeperRepo,
          bundleBase64,
          commitSha: "f".repeat(40), // wrong — the imported tip won't match
          branch,
          remote: "origin",
        },
      }),
    );
    expect(resp.ok).toBe(false);
    expect(resp.error?.code).toBe("TIP_MISMATCH");
  });
});
