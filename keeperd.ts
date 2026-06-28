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

import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
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
  call,
  type RequestEnvelope,
  type ResponseEnvelope,
  ok,
  err,
} from "./lib/runtime";
// Transit-grant verification (signed grants on tcp/vsock).
import { verifyGrantWithKeys, type IssuerKeys } from "./guest-room/mod.ts";

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

/**
 * Canonical JSON for signing: recursively sort object keys, then `JSON.stringify`
 * — so the signature is independent of key insertion order AND stable across a
 * JSON round-trip (the L3 always crosses the wire / a git note before it is
 * verified, and JSON drops `undefined`-valued keys; sorting then stringifying
 * matches that exactly). Signer and verifier MUST use the identical algorithm
 * (prx mirrors this in `verify-l3.ts`).
 */
function sortDeep(value: unknown): unknown {
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(sortDeep);
  const obj = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(obj).sort()) out[k] = sortDeep(obj[k]);
  return out;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortDeep(value));
}

type SigningKey = {
  privateKey: ReturnType<typeof createPrivateKey>;
  publicKeyPem: string;
  keyId: string; // sha256 of public key (first 16 chars)
};

let signingKey: SigningKey | null = null;

// The content-address of the most recent L2 launch this daemon attested. One
// daemon serves one launched pod, so a later import-and-push (the box's write)
// auto-links it (unless the caller passes an explicit l2LaunchDigest) — closing
// the capability chain without the box having to carry the digest.
let lastLaunchDigest: string | undefined;

function loadOrCreateKey(keyPath: string): SigningKey {
  const dir = dirname(keyPath);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  let privateKeyPem: string;
  let publicKeyPem: string;

  if (existsSync(keyPath)) {
    privateKeyPem = readFileSync(keyPath, "utf-8");
    // Derive the public key from the private-key PEM directly. Passing a
    // KeyObject to createPublicKey trips the bun-types overload (it accepts a
    // PEM/DER string but not a derived KeyObject); the PEM path is equivalent.
    // (claude-box's mirror gates on tsc; keep this in sync — see claude-box#151.)
    const publicKey = createPublicKey(privateKeyPem);
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
 * AI-authorship reconciliation, recorded in the SIGNED L3 attestation.
 *
 * The CLAIM lives in the divergence: the box's in-box checkpoint hook reports
 * which files the *model* authored (its self-report), but the box is exactly
 * what might be bypassed, so that report alone proves nothing. keeperd — which
 * sees the *actual* staged diff and holds the signing key — reconciles the two
 * here, making AI authorship VERIFIABLE (signed) and a bypass DETECTABLE. See
 * GITAI-PROVENANCE.md.
 */
type Authorship = {
  model?: string;
  aiAuthored: string[]; // claimed ∩ actually-staged
  divergent: string[]; // staged but NOT claimed → bypass (human / untracked edit)
  stale: string[]; // claimed but NOT staged → never landed
};

function reconcileAuthorship(
  stagedFiles: string[],
  claimed: string[],
  model?: string,
): Authorship {
  const staged = new Set(stagedFiles);
  const claim = new Set(claimed);
  return {
    ...(model ? { model } : {}),
    aiAuthored: [...staged].filter((f) => claim.has(f)).sort(),
    divergent: [...staged].filter((f) => !claim.has(f)).sort(),
    stale: [...claim].filter((f) => !staged.has(f)).sort(),
  };
}

/**
 * Build and sign an L3 git-write attestation (SLSA Provenance v1 format).
 *
 * Links back to the L2 launch via manifestDigest — this is the binding that
 * proves the commit came from a box with exactly those capabilities. When
 * `authorship` is provided it is recorded under `predicate.authorship` BEFORE
 * signing, so the AI-vs-human reconciliation is covered by the signature.
 */
function buildL3Attestation(
  commitSha: string,
  repo: string,
  ref: string,
  manifestDigest: string,
  l2LaunchDigest?: string,
  authorship?: Authorship,
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

  // Bind AI authorship into the predicate so it is covered by the signature.
  if (authorship) {
    (stmt.predicate as Record<string, unknown>).authorship = authorship;
  }

  // Canonicalize and sign
  const stmtJson = canonicalJson(stmt);
  const stmtDigest = sha256(stmtJson);
  const signature = signData(stmtJson);

  return {
    statement: stmt,
    statementDigest: stmtDigest,
    signature,
    keyId: signingKey?.keyId ?? "unknown",
  };
}

/**
 * Build and sign an **L2 launch attestation** — the launching guest attesting
 * that a room was launched holding exactly these doors (its manifest). Same
 * signer-door mechanism as the L3 write (this daemon = a guest's signer door,
 * signing with whichever key it holds); the `level` is what differs. An L3 write
 * later links back to this L2 by `sha256(canonicalJson(statement))`.
 *
 * `subject` is the launched room/box id; `manifestDigest` is the digest of its
 * resolved door set (authority = held references).
 */
function buildLaunchAttestation(subject: string, manifestDigest: string): L3Attestation {
  const now = new Date().toISOString();
  const ocapStmt = statement(
    // Subject: the launched room, identified by its manifest digest.
    [{ name: subject, digest: { sha256: manifestDigest } }],
    {
      level: "launch",
      producer: {
        // The launching guest's signer door (whichever key this daemon holds).
        kind: "keeperd",
        id: `keeperd:${signingKey?.keyId ?? "unknown"}`,
      },
      capabilities: {
        workcell: "claude-box",
        manifestDigest: { sha256: manifestDigest },
      },
      metadata: {
        invocationId: `launch-${subject}`,
        finishedOn: now,
      },
    },
  );

  const stmt = toSLSA(ocapStmt);
  const stmtJson = canonicalJson(stmt);
  return {
    statement: stmt,
    statementDigest: sha256(stmtJson),
    signature: signData(stmtJson),
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
  authorship?: { model?: string; aiAuthored?: string[] };
}): Promise<{ commit: string; signature?: string; attestation?: L3Attestation }> {
  const { repo, message, author, files, all, amend, authorship } = params;

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

  // Capture the actually-staged files NOW (before the commit clears the index)
  // so authorship can be reconciled against what really lands in this commit.
  const stagedResult = await gitExec(repo, ["diff", "--cached", "--name-only"]);
  const stagedFiles = stagedResult.ok
    ? stagedResult.stdout.split("\n").filter(Boolean)
    : [];

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

  // Reconcile the model's claimed authorship against what actually staged —
  // the divergence (staged-but-unclaimed) is a detected bypass. Only when the
  // box supplied a claim; otherwise authorship is omitted (no false signal).
  const authorshipRecord = authorship
    ? reconcileAuthorship(stagedFiles, authorship.aiAuthored ?? [], authorship.model)
    : undefined;

  // Build L3 attestation
  const attestation = buildL3Attestation(
    commitSha,
    repo,
    `refs/heads/${branch}`,
    manifestDigest,
    undefined,
    authorshipRecord,
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
  const authorship = params.authorship as
    | { model?: string; aiAuthored?: string[] }
    | undefined;

  if (!repo) {
    throw { code: "INVALID_PARAMS", message: "repo required" };
  }
  if (!message && !amend) {
    throw { code: "INVALID_PARAMS", message: "message required (unless amending)" };
  }

  return gitCommit({ repo, message, author, files, all, amend, authorship });
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

/**
 * Model-A keeper write: the host already did the keyless commit and ships the new
 * commits as a commit-range bundle; keeperd imports them, verifies the tip is
 * EXACTLY the host-materialized commit (fail closed), then performs the signed
 * push and returns an L3 attestation over the pushed commit. The host never
 * grants keeperd commit authorship — only import + push.
 */
async function handleImportAndPush(params: Record<string, unknown>): Promise<unknown> {
  const repo = params.repo as string;
  const bundleBase64 = params.bundleBase64 as string;
  const commitSha = params.commitSha as string;
  const branch = params.branch as string;
  const remote = (params.remote as string | undefined) ?? "origin";
  const pushArgs = (params.pushArgs as string[] | undefined) ?? [];
  const manifestDigest = (params.manifestDigest as string | undefined) ?? "";
  // Opt-in: the content-address of the box's L2 launch attestation, so the L3
  // write links back to its launch (capability chain: write → launch).
  // Explicit param wins; else fall back to the launch this daemon attested.
  const l2LaunchDigest = (params.l2LaunchDigest as string | undefined) ?? lastLaunchDigest;
  // Opt-in: project the signed L3 onto the commit as a git note under
  // refs/notes/<notesRef> (e.g. "provenance") so it travels with the repo and is
  // queryable via `git notes show` / `git log --show-notes` / blame → commit → note.
  const notesRef = params.notesRef as string | undefined;

  if (!repo || !bundleBase64 || !commitSha || !branch) {
    throw { code: "INVALID_PARAMS", message: "repo, bundleBase64, commitSha, branch required" };
  }
  if (!/^[0-9a-f]{40}$/.test(commitSha)) {
    throw { code: "INVALID_PARAMS", message: "commitSha must be a 40-hex sha" };
  }
  if (!existsSync(repo)) {
    throw { code: "REPO_NOT_FOUND", message: `repository not found: ${repo}` };
  }

  const bundlePath = join(tmpdir(), `keeperd-import-${commitSha.slice(0, 12)}-${Date.now()}.bundle`);
  writeFileSync(bundlePath, Buffer.from(bundleBase64, "base64"));
  try {
    // 1. Import the host-built commit-range bundle.
    const fetchResult = await gitExec(repo, [
      "fetch",
      bundlePath,
      `+refs/heads/${branch}:refs/heads/${branch}`,
    ]);
    if (!fetchResult.ok) {
      throw { code: "BAD_BUNDLE", message: fetchResult.stderr };
    }
    // 2. Fail closed: the imported tip MUST equal the host-materialized commit,
    //    so a corrupt/wrong bundle can never be pushed.
    const tipResult = await gitExec(repo, ["rev-parse", branch]);
    const tip = tipResult.stdout.trim();
    if (!tipResult.ok || tip !== commitSha) {
      throw { code: "TIP_MISMATCH", message: `imported tip ${tip} != requested ${commitSha}` };
    }
    // 3. Signed push — keeperd holds the push credential; the host does not.
    const pushResult = await gitExec(repo, ["push", remote, `${branch}:${branch}`, ...pushArgs]);
    if (!pushResult.ok) {
      throw { code: "GIT_PUSH_FAILED", message: pushResult.stderr, exitCode: pushResult.code };
    }
  } finally {
    rmSync(bundlePath, { force: true });
  }

  // 4. L3 attestation over the pushed commit (the signed verdict consumers verify).
  const attestation = signingKey
    ? buildL3Attestation(commitSha, repo, `refs/heads/${branch}`, manifestDigest, l2LaunchDigest)
    : undefined;

  // 5. Opt-in provenance note: attach the signed L3 to the commit as a git note
  //    and push the notes ref. Best-effort — the branch (the critical effect) is
  //    already pushed, so a note failure never unwinds it; the verdict reports it.
  let note: { ref: string; written: boolean; pushed: boolean } | undefined;
  if (attestation && notesRef) {
    const noteJson = JSON.stringify(attestation);
    // `git notes add` writes a commit on the notes ref → needs a committer
    // identity; pass it via -c so it works regardless of repo/global git config.
    const add = await gitExec(repo, [
      "-c",
      "user.email=keeperd@bounded.systems",
      "-c",
      "user.name=keeperd",
      "notes",
      `--ref=${notesRef}`,
      "add",
      "-f",
      "-m",
      noteJson,
      commitSha,
    ]);
    const push = add.ok
      ? await gitExec(repo, ["push", remote, `refs/notes/${notesRef}`])
      : null;
    note = { ref: `refs/notes/${notesRef}`, written: add.ok, pushed: push?.ok ?? false };
  }

  return {
    status: "ok",
    commitSha,
    pushedRef: `refs/heads/${branch}`,
    signedDerivation: attestation,
    ...(note ? { note } : {}),
  };
}

/**
 * L2 launch attestation: a guest acting through its signer door attests that a
 * room was launched holding exactly these doors. The launch key never leaves the
 * daemon (ocap credential isolation) — the launcher acts *through* the door, the
 * same way a box does for git-writes. `subject` = the launched room id; `manifest`
 * = its resolved door set (we digest it: authority = held references).
 */
async function handleAttestLaunch(params: Record<string, unknown>): Promise<unknown> {
  const subject = params.subject as string;
  const manifest = params.manifest;

  if (!subject || manifest === undefined || manifest === null) {
    throw { code: "INVALID_PARAMS", message: "subject and manifest required" };
  }
  if (!signingKey) {
    throw { code: "NO_KEY", message: "signing key not loaded" };
  }

  const manifestDigest = sha256(canonicalJson(manifest));
  const attestation = buildLaunchAttestation(subject, manifestDigest);
  // The content-address an L3 write links back to (links[].level="launch").
  const l2LaunchDigest = sha256(canonicalJson(attestation.statement));
  // Remember it so a later import-and-push (the box's write) auto-links this launch.
  lastLaunchDigest = l2LaunchDigest;

  return { status: "ok", subject, manifestDigest, l2LaunchDigest, attestation };
}

const METHODS: Record<string, MethodHandler> = {
  status: handleStatus,
  commit: handleCommit,
  push: handlePush,
  "import-and-push": handleImportAndPush,
  "attest-launch": handleAttestLaunch,
  sign: handleSign,
  verify: handleVerify,
  getPublicKey: handleGetPublicKey,
};

// ── Request handling ─────────────────────────────────────────────────────────
// Protocol types (RequestEnvelope, ResponseEnvelope) imported from lib/runtime

// ── Transit-grant gate (tcp/vsock only) ──────────────────────────────────────
// On a unix door the held socket reference IS authority. On tcp/vsock the kernel
// gives no peer identity, so a caller must present a SIGNED grant (req.grant) the
// concierge minted; we verify it against the concierge's PUBLISHED keys (keyless,
// fetched + cached, re-fetched once on an unknown key) for THIS room and the
// "keeper" door. Set by serveTcp. (Mirrors the scoutd verifier; door-scout #6.)
let grantRequired = false;

function conciergeSocket(): string {
  if (process.env.CONCIERGE_SOCK) return process.env.CONCIERGE_SOCK;
  const runtime = process.env.XDG_RUNTIME_DIR;
  if (runtime) return `${runtime}/concierged.sock`;
  return `${process.env.HOME ?? "/tmp"}/.claude-box/concierged.sock`;
}

let issuerKeys: IssuerKeys | null = null;
async function fetchIssuerKeys(force = false): Promise<IssuerKeys> {
  if (issuerKeys && !force) return issuerKeys;
  issuerKeys = await call<IssuerKeys>(conciergeSocket(), "keys");
  return issuerKeys;
}

const grantVerifyWith = (data: string, signature: string, publicKeyPem: string): boolean =>
  verify(null, Buffer.from(data), createPublicKey(publicKeyPem), Buffer.from(signature, "base64"));

/** Gate a request on a tcp/vsock door: the presented signed grant must verify
 *  against the concierge's published keys for this room and the "keeper" door.
 *  Re-fetches keys ONCE on an unknown key (rotation). */
async function gateGrant(req: RequestEnvelope): Promise<{ ok: boolean; reason?: string }> {
  if (!grantRequired) return { ok: true }; // unix: reference is authority
  const grant = req.grant;
  if (!grant) return { ok: false, reason: "no-grant" };
  if (grant.name !== "keeper") return { ok: false, reason: "wrong-door" };
  const ctx = { audience: process.env.ROOM_ID ?? "", now: Date.now() };
  let v = verifyGrantWithKeys(grant, ctx, await fetchIssuerKeys(), grantVerifyWith);
  if (!v.ok && v.reason === "unknown-key") {
    v = verifyGrantWithKeys(grant, ctx, await fetchIssuerKeys(true), grantVerifyWith);
  }
  return v;
}

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

  // Transit-grant gate: on tcp/vsock, no valid signed grant ⇒ no handler reached.
  const gate = await gateGrant(req);
  if (!gate.ok) {
    return err(id, "UNAUTHORIZED", `signed grant rejected: ${gate.reason}`);
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
  // tcp/vsock has no kernel peer identity ⇒ require a verified signed grant.
  grantRequired = true;
  log("INFO", `listening tcp ${host}:${port} (signed-grant gate, fail-closed)`);

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
  reconcileAuthorship,
  gateGrant,
  gitExec,
  VERSION,
};

/** Test seams: drive the tcp/vsock grant gate without a live concierge. */
export function __setGrantRequired(v: boolean): void {
  grantRequired = v;
}
export function __setIssuerKeys(k: IssuerKeys | null): void {
  issuerKeys = k;
}

export type { RequestEnvelope, ResponseEnvelope, SigningKey, L3Attestation, Authorship };

if (import.meta.main) {
  process.exit(await main());
}
