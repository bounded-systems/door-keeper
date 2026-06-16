#!/usr/bin/env bun
/**
 * keeperd — the git-signing daemon for claude-box.
 *
 * Listens on a unix socket, handles commit/push/sign/verify requests.
 * Owns: signing keys, SSH credentials, L3 attestation.
 *
 * Usage:
 *   keeperd serve                     # foreground, default socket
 *   keeperd serve --socket /path.sock # custom socket path
 *   keeperd serve --key /path/to/key  # signing key (Ed25519)
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve, join } from "node:path";
import { createHash, sign, verify, generateKeyPairSync, createPrivateKey, createPublicKey } from "node:crypto";
import type { Socket } from "bun";
import {
  statement,
  type CapabilityProvenanceStatement,
} from "./contract/types";
import {
  toSLSA,
  type SLSAStatement,
} from "./contract/slsa";

// Import shared daemon infrastructure
import {
  defaultSocketPath,
  prepareSocket,
  createLogger,
  showUsage,
  type RequestEnvelope,
  type ResponseEnvelope,
  ok,
  err,
} from "./lib/runtime";

const log = createLogger("keeperd");

// ── Config ───────────────────────────────────────────────────────────────────

const VERSION = "0.1.0";

function defaultKeyPath(): string {
  const home = process.env.HOME ?? "/tmp";
  return `${home}/.claude-box/keeper.key`;
}

function defaultSshKeyPath(): string {
  const home = process.env.HOME ?? "/tmp";
  return `${home}/.claude-box/keeper_ssh`;
}

// ── Crypto ───────────────────────────────────────────────────────────────────

function sha256(data: string): string {
  return createHash("sha256").update(data).digest("hex");
}

type SigningKey = {
  privateKey: ReturnType<typeof createPrivateKey>;
  publicKeyPem: string;
  keyId: string; // sha256 of public key (first 16 chars)
};

let signingKey: SigningKey | null = null;

function loadOrCreateKey(keyPath: string): SigningKey {
  const dir = dirname(keyPath);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  let privateKeyPem: string;
  let publicKeyPem: string;

  if (existsSync(keyPath)) {
    privateKeyPem = readFileSync(keyPath, "utf-8");
    const privateKey = createPrivateKey(privateKeyPem);
    const publicKey = createPublicKey(privateKey);
    publicKeyPem = publicKey.export({ type: "spki", format: "pem" }) as string;
  } else {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    publicKeyPem = publicKey.export({ type: "spki", format: "pem" }) as string;
    writeFileSync(keyPath, privateKeyPem, { mode: 0o600 });
    console.error(`keeperd: generated new signing key at ${keyPath}`);
  }

  const privateKey = createPrivateKey(privateKeyPem);
  const keyId = sha256(publicKeyPem).slice(0, 16);

  signingKey = { privateKey, publicKeyPem, keyId };
  return signingKey;
}

function signData(data: string): string {
  if (!signingKey) {
    throw new Error("signing key not loaded");
  }
  const sig = sign(null, Buffer.from(data), signingKey.privateKey);
  return sig.toString("base64");
}

function verifySignature(data: string, signature: string, publicKeyPem?: string): boolean {
  const keyPem = publicKeyPem ?? signingKey?.publicKeyPem;
  if (!keyPem) return false;

  try {
    const publicKey = createPublicKey(keyPem);
    return verify(null, Buffer.from(data), publicKey, Buffer.from(signature, "base64"));
  } catch {
    return false;
  }
}

// ── L3 Attestation ───────────────────────────────────────────────────────────

type L3Attestation = {
  statement: SLSAStatement;
  statementDigest: string;
  signature: string;
  keyId: string;
};

/**
 * Build and sign an L3 git-write attestation (SLSA Provenance v1 format).
 *
 * Links back to the L2 launch via manifestDigest — this is the binding that
 * proves the commit came from a box with exactly those capabilities.
 */
function buildL3Attestation(
  commitSha: string,
  repo: string,
  ref: string,
  manifestDigest: string,
  l2LaunchDigest?: string,
): L3Attestation {
  const now = new Date().toISOString();

  // Build the L3 statement per contract/CHAIN.md (OCAP format first)
  const ocapStmt = statement(
    // Subject: the git commit
    [{ name: commitSha, digest: { gitCommit: commitSha } }],
    {
      level: "write",
      producer: {
        kind: "keeperd",
        id: `keeperd:${signingKey?.keyId ?? "unknown"}`,
      },
      capabilities: {
        workcell: "claude-box",
        manifestDigest: { sha256: manifestDigest },
      },
      links: l2LaunchDigest
        ? [{ level: "launch", digest: { sha256: l2LaunchDigest } }]
        : [],
      metadata: {
        invocationId: `write-${commitSha.slice(0, 8)}`,
        finishedOn: now,
      },
    },
  );

  // Convert to SLSA Provenance v1 format
  const stmt = toSLSA(ocapStmt);

  // Add repo/ref to externalParameters
  (stmt.predicate.buildDefinition.externalParameters as Record<string, unknown>).repo = repo;
  (stmt.predicate.buildDefinition.externalParameters as Record<string, unknown>).ref = ref;

  // Canonicalize and sign
  const stmtJson = JSON.stringify(stmt);
  const stmtDigest = sha256(stmtJson);
  const signature = signData(stmtJson);

  return {
    statement: stmt,
    statementDigest: stmtDigest,
    signature,
    keyId: signingKey?.keyId ?? "unknown",
  };
}

// ── Git operations ───────────────────────────────────────────────────────────

async function gitExec(repo: string, args: string[]): Promise<{ ok: boolean; stdout: string; stderr: string; code: number }> {
  const proc = Bun.spawn(["git", "-C", repo, ...args], {
    stdout: "pipe",
    stderr: "pipe",
  });

  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ]);
  const code = await proc.exited;

  return { ok: code === 0, stdout: stdout.trim(), stderr: stderr.trim(), code };
}

async function gitCommit(params: {
  repo: string;
  message: string;
  author?: string;
  files?: string[];
  all?: boolean;
  amend?: boolean;
  sign?: boolean;
}): Promise<{ commit: string; signature?: string; attestation?: L3Attestation }> {
  const { repo, message, author, files, all, amend } = params;

  // Validate repo exists
  if (!existsSync(repo)) {
    throw { code: "REPO_NOT_FOUND", message: `repository not found: ${repo}` };
  }

  // Stage files
  if (all) {
    const addResult = await gitExec(repo, ["add", "-A"]);
    if (!addResult.ok) {
      throw { code: "GIT_ADD_FAILED", message: addResult.stderr };
    }
  } else if (files?.length) {
    const addResult = await gitExec(repo, ["add", "--", ...files]);
    if (!addResult.ok) {
      throw { code: "GIT_ADD_FAILED", message: addResult.stderr };
    }
  }

  // Check if there are staged changes
  const statusResult = await gitExec(repo, ["diff", "--cached", "--quiet"]);
  if (statusResult.ok && !amend) {
    throw { code: "NOTHING_TO_COMMIT", message: "no changes staged for commit" };
  }

  // Build commit command
  const commitArgs = ["commit"];
  if (amend) commitArgs.push("--amend");
  if (author) commitArgs.push("--author", author);
  commitArgs.push("-m", message);

  // We sign commits using our own attestation system, not git's GPG/SSH signing
  // The L3 attestation IS the signature

  const commitResult = await gitExec(repo, commitArgs);
  if (!commitResult.ok) {
    throw { code: "GIT_COMMIT_FAILED", message: commitResult.stderr };
  }

  // Get the commit SHA
  const revResult = await gitExec(repo, ["rev-parse", "HEAD"]);
  if (!revResult.ok) {
    throw { code: "GIT_REV_PARSE_FAILED", message: revResult.stderr };
  }
  const commitSha = revResult.stdout;

  // Get current branch for attestation
  const branchResult = await gitExec(repo, ["symbolic-ref", "--short", "HEAD"]);
  const branch = branchResult.ok ? branchResult.stdout : "HEAD";

  // Get manifest digest from environment (set by launcherd at L2)
  const capsEnv = process.env.CLAUDE_BOX_CAPABILITIES;
  let manifestDigest = "unknown";
  if (capsEnv) {
    manifestDigest = sha256(capsEnv);
  }

  // Build L3 attestation
  const attestation = buildL3Attestation(
    commitSha,
    repo,
    `refs/heads/${branch}`,
    manifestDigest,
  );

  return {
    commit: commitSha,
    attestation,
  };
}

async function gitPush(params: {
  repo: string;
  remote?: string;
  branch?: string;
  force?: boolean;
  setUpstream?: boolean;
}): Promise<{ pushed: string; commits: string[] }> {
  const { repo, remote = "origin", branch, force, setUpstream } = params;

  // Validate repo exists
  if (!existsSync(repo)) {
    throw { code: "REPO_NOT_FOUND", message: `repository not found: ${repo}` };
  }

  // Get current branch if not specified
  let targetBranch = branch;
  if (!targetBranch) {
    const branchResult = await gitExec(repo, ["symbolic-ref", "--short", "HEAD"]);
    if (!branchResult.ok) {
      throw { code: "NOT_ON_BRANCH", message: "not on a branch; specify branch explicitly" };
    }
    targetBranch = branchResult.stdout;
  }

  // Get commits that will be pushed
  const logResult = await gitExec(repo, [
    "log", `${remote}/${targetBranch}..HEAD`, "--format=%H", "--reverse"
  ]);
  const commits = logResult.ok ? logResult.stdout.split("\n").filter(Boolean) : [];

  // Build push command
  const pushArgs = ["push"];
  if (force) pushArgs.push("--force");
  if (setUpstream) pushArgs.push("-u");
  pushArgs.push(remote, targetBranch);

  const pushResult = await gitExec(repo, pushArgs);
  if (!pushResult.ok) {
    throw { code: "GIT_PUSH_FAILED", message: pushResult.stderr };
  }

  return {
    pushed: `${remote}/${targetBranch}`,
    commits,
  };
}

// ── Method handlers ──────────────────────────────────────────────────────────

type MethodHandler = (params: Record<string, unknown>) => Promise<unknown>;

async function handleStatus(_params: Record<string, unknown>): Promise<unknown> {
  return {
    version: VERSION,
    uptime: Math.floor((Date.now() - startedAt.getTime()) / 1000),
    signing: signingKey
      ? { enabled: true, keyId: signingKey.keyId }
      : { enabled: false },
  };
}

async function handleCommit(params: Record<string, unknown>): Promise<unknown> {
  const repo = params.repo as string;
  const message = params.message as string;
  const author = params.author as string | undefined;
  const files = params.files as string[] | undefined;
  const all = params.all as boolean | undefined;
  const amend = params.amend as boolean | undefined;

  if (!repo) {
    throw { code: "INVALID_PARAMS", message: "repo required" };
  }
  if (!message && !amend) {
    throw { code: "INVALID_PARAMS", message: "message required (unless amending)" };
  }

  return gitCommit({ repo, message, author, files, all, amend });
}

async function handlePush(params: Record<string, unknown>): Promise<unknown> {
  const repo = params.repo as string;
  const remote = params.remote as string | undefined;
  const branch = params.branch as string | undefined;
  const force = params.force as boolean | undefined;
  const setUpstream = params.setUpstream as boolean | undefined;

  if (!repo) {
    throw { code: "INVALID_PARAMS", message: "repo required" };
  }

  return gitPush({ repo, remote, branch, force, setUpstream });
}

async function handleSign(params: Record<string, unknown>): Promise<unknown> {
  const data = params.data as string;

  if (!data) {
    throw { code: "INVALID_PARAMS", message: "data required (base64 encoded)" };
  }

  const decoded = Buffer.from(data, "base64").toString("utf-8");
  const signature = signData(decoded);

  return {
    signature,
    keyId: signingKey?.keyId,
  };
}

async function handleVerify(params: Record<string, unknown>): Promise<unknown> {
  const data = params.data as string;
  const signature = params.signature as string;
  const publicKey = params.publicKey as string | undefined;

  if (!data || !signature) {
    throw { code: "INVALID_PARAMS", message: "data and signature required (base64 encoded)" };
  }

  const decoded = Buffer.from(data, "base64").toString("utf-8");
  const valid = verifySignature(decoded, signature, publicKey);

  return {
    valid,
    keyId: valid ? signingKey?.keyId : undefined,
  };
}

async function handleGetPublicKey(_params: Record<string, unknown>): Promise<unknown> {
  if (!signingKey) {
    throw { code: "NO_KEY", message: "signing key not loaded" };
  }

  return {
    publicKey: signingKey.publicKeyPem,
    keyId: signingKey.keyId,
  };
}

const METHODS: Record<string, MethodHandler> = {
  status: handleStatus,
  commit: handleCommit,
  push: handlePush,
  sign: handleSign,
  verify: handleVerify,
  getPublicKey: handleGetPublicKey,
};

// ── Request handling ─────────────────────────────────────────────────────────
// Protocol types (RequestEnvelope, ResponseEnvelope) imported from lib/runtime

async function handleRequest(line: string): Promise<ResponseEnvelope> {
  let req: RequestEnvelope;
  try {
    req = JSON.parse(line);
  } catch {
    return err("", "PARSE_ERROR", "invalid JSON");
  }

  const { id, method, params } = req;
  if (!id || !method) {
    return err(id ?? "", "INVALID_REQUEST", "id and method required");
  }

  const handler = METHODS[method];
  if (!handler) {
    return err(id, "UNKNOWN_METHOD", `unknown method: ${method}`);
  }

  try {
    const result = await handler(params ?? {});
    return ok(id, result);
  } catch (e) {
    const error = e as { code?: string; message?: string };
    return err(id, error.code ?? "INTERNAL_ERROR", error.message ?? String(e));
  }
}

// ── Socket server ────────────────────────────────────────────────────────────

const startedAt = new Date();

const socketHandler = {
  async data(socket: Socket, data: Buffer) {
    const lines = data.toString().split("\n").filter(Boolean);
    for (const line of lines) {
      const resp = await handleRequest(line);
      socket.write(JSON.stringify(resp) + "\n");
    }
  },
  open(_socket: Socket) {},
  close(_socket: Socket) {},
  error(_socket: Socket, error: Error) {
    log("ERR", `socket error: ${error}`);
  },
};

async function serveUnix(socketPath: string): Promise<void> {
  // Ensure parent directory exists
  const dir = dirname(socketPath);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  // Remove existing socket and start listening
  prepareSocket(socketPath);
  log("INFO", `listening on ${socketPath}`);

  Bun.listen({
    unix: socketPath,
    socket: socketHandler,
  });

  // Keep running
  await new Promise(() => {});
}

// Bind to 0.0.0.0 so podman machine VM can reach us via host.containers.internal
async function serveTcp(port: number, host: string = "0.0.0.0"): Promise<void> {
  log("INFO", `listening tcp ${host}:${port}`);

  Bun.listen({
    hostname: host,
    port,
    socket: socketHandler,
  });

  // Keep running
  await new Promise(() => {});
}

// ── CLI ──────────────────────────────────────────────────────────────────────

async function main(): Promise<number> {
  const args = Bun.argv.slice(2);
  const cmd = args[0];

  if (cmd === "serve") {
    let socketPath = defaultSocketPath("keeperd");
    let keyPath = defaultKeyPath();
    let port: number | undefined;

    for (let i = 1; i < args.length; i++) {
      if (args[i] === "--socket" || args[i] === "-s") {
        socketPath = args[++i]!;
      } else if (args[i] === "--key" || args[i] === "-k") {
        keyPath = args[++i]!;
      } else if (args[i] === "--port" || args[i] === "-p") {
        port = Number(args[++i]);
      }
    }

    // Load signing key
    loadOrCreateKey(keyPath);

    // TCP mode (for host→VM relay) or unix socket mode
    if (port) {
      await serveTcp(port);
    } else {
      await serveUnix(socketPath);
    }
    return 0;
  }

  console.log(`keeperd — git-signing daemon for claude-box

Usage:
  keeperd serve                     start daemon (foreground, unix socket)
  keeperd serve --port PORT         listen on TCP (for host→VM relay)
  keeperd serve --socket PATH       custom socket path
  keeperd serve --key PATH          custom signing key path

The daemon listens for NDJSON requests:
  - status      health check
  - commit      create a signed commit
  - push        push to remote
  - sign        sign arbitrary data
  - verify      verify a signature
  - getPublicKey  get the signing public key

See KEEPERD.md for protocol details.`);

  return cmd === "-h" || cmd === "--help" ? 0 : 1;
}

// ── Exports for testing ──────────────────────────────────────────────────────

export {
  handleRequest,
  handleStatus,
  handleCommit,
  handlePush,
  handleSign,
  handleVerify,
  loadOrCreateKey,
  signData,
  verifySignature,
  sha256,
  buildL3Attestation,
  gitExec,
  VERSION,
};

export type { RequestEnvelope, ResponseEnvelope, SigningKey, L3Attestation };

if (import.meta.main) {
  process.exit(await main());
}
