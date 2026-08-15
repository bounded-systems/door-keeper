/**
 * @module
 * keeper.ts — in-box client for keeperd
 *
 * A box with the `--keeper` door can use this to make signed commits and pushes.
 * The box holds no keys — it asks keeperd to sign.
 *
 * Usage:
 *   import { commit, push, sign } from "./lib/keeper";
 *
 *   const result = await commit({
 *     repo: "/work",
 *     message: "feat: add feature X",
 *     all: true,
 *   });
 *   console.log(`Committed ${result.commit}`);
 *
 *   await push({ repo: "/work" });
 */

import { heldGrant } from "./concierge.ts";
import { call, DoorCallError } from "../guest-room/protocol.ts";

// ── Types ────────────────────────────────────────────────────────────────────

/** Options for creating a signed commit via keeperd. */
export type CommitOptions = {
  /** Repository path */
  repo: string;
  /** Commit message */
  message: string;
  /** Author string (e.g., "Name <email>") */
  author?: string;
  /** Specific files to add */
  files?: string[];
  /** Add all changes (git add -A) */
  all?: boolean;
  /** Amend the last commit */
  amend?: boolean;
  /**
   * The model's CLAIMED AI authorship for this commit — a self-report, not
   * authority. keeperd reconciles it against the files that actually stage and
   * records aiAuthored / divergent (bypass) / stale in the signed L3 attestation
   * (see door-keeper, GITAI-PROVENANCE.md). Omit it and keeperd records no
   * authorship (no false signal). `aiAuthored` is repo-relative paths.
   */
  authorship?: { model?: string; aiAuthored?: string[] };
};

/** Result of a signed commit operation via keeperd. */
export type CommitResult = {
  commit: string;
  attestation?: {
    statement: unknown;
    statementDigest: string;
    signature: string;
    keyId: string;
  };
};

/** Options for pushing to a remote repository via keeperd. */
export type PushOptions = {
  /** Repository path */
  repo: string;
  /** Remote name (default: "origin") */
  remote?: string;
  /** Branch name (default: current branch) */
  branch?: string;
  /** Force push */
  force?: boolean;
  /** Set upstream tracking */
  setUpstream?: boolean;
};

/** Result of a push operation via keeperd. */
export type PushResult = {
  pushed: string;
  commits: string[];
};

/** Options for opening a GitHub PR via keeperd. */
export type PrOptions = {
  /** The GitHub repository as `owner/name` — the REST target, NOT a filesystem
   *  path, so it is passed through verbatim (no /work translation). */
  repo: string;
  /** The head branch keeperd already pushed (via `push`/`import-and-push`). */
  head: string;
  /** The base branch to open the PR against (default: "main"). */
  base?: string;
  /** PR title. */
  title: string;
  /** PR body (optional). */
  body?: string;
};

/** Result of opening a PR via keeperd: the created PR's number and URL. */
export type PrResult = {
  number: number;
  url: string;
};

/** Result of a sign operation via keeperd. */
export type SignResult = {
  signature: string;
  keyId: string;
};

/** Result of a signature verification via keeperd. */
export type VerifyResult = {
  valid: boolean;
  keyId?: string;
};

/** Health and status information from keeperd. */
export type KeeperStatus = {
  version: string;
  uptime: number;
  signing: { enabled: boolean; keyId?: string };
};

/** Error from keeperd operations, with an error code for pattern matching. */
export class KeeperError extends Error {
  /** Machine-readable error code for pattern matching. */
  code: string;
  /** Create a KeeperError with a `code` and human-readable `message`. */
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
    this.name = "KeeperError";
  }
}

// ── Client ───────────────────────────────────────────────────────────────────

/** Get keeperd's connection endpoint — a unix path or a `host:port` TCP
 *  target (either shape parses through call()'s connectTarget). */
function keeperEndpoint(): string {
  // Back-compat: KEEPERD_HOST=host:port is still honored if set explicitly
  // (some dev docs/scripts do). claude-box itself only ever sets KEEPERD_SOCK,
  // whose value may be a unix path OR a host:port TCP endpoint (TCP mode).
  const tcpHost = process.env.KEEPERD_HOST;
  if (tcpHost) return tcpHost;

  const sockPath = process.env.KEEPERD_SOCK;
  if (sockPath) return sockPath;

  // In-box default: socket at /run/keeperd.sock
  if (Bun.file("/run/keeperd.sock").size !== undefined) return "/run/keeperd.sock";

  // Fallback for testing outside a box
  const runtime = process.env.XDG_RUNTIME_DIR;
  if (runtime) return `${runtime}/keeperd.sock`;
  const home = process.env.HOME ?? "/tmp";
  return `${home}/.claude-box/keeperd.sock`;
}

/** Send a request to keeperd and wait for response. */
async function request<T>(method: string, params: Record<string, unknown> = {}): Promise<T> {
  try {
    return await call<T>(keeperEndpoint(), method, params, { grant: heldGrant("keeper") });
  } catch (e) {
    if (e instanceof DoorCallError) throw new KeeperError(e.code, e.message);
    throw e;
  }
}

// ── Path translation ──────────────────────────────────────────────────────────
// The box sees the repo at /work, but keeperd runs on the host where the repo
// is at a different path (e.g., the host worktree root). CLAUDE_BOX_HOST_REPO
// tells us the host path so we can translate /work → the actual host path.

/**
 * Translate a repo path from in-box (/work) to host path.
 * If CLAUDE_BOX_HOST_REPO is set and repo starts with /work, translate it.
 */
export function translateRepoPath(repo: string): string {
  const hostRepo = process.env.CLAUDE_BOX_HOST_REPO;
  if (!hostRepo) return repo;

  // Translate /work or /work/... to the host path
  if (repo === "/work" || repo === "/work/") {
    return hostRepo;
  }
  if (repo.startsWith("/work/")) {
    return hostRepo + repo.slice(5); // replace /work with hostRepo
  }
  // Also handle "." when cwd is /work
  if (repo === "." && process.cwd() === "/work") {
    return hostRepo;
  }

  return repo;
}

// ── Public API ───────────────────────────────────────────────────────────────

/**
 * Create a signed commit via keeperd.
 *
 * Requires the `--keeper` door. The box holds no keys — keeperd signs.
 */
export async function commit(options: CommitOptions): Promise<CommitResult> {
  return request<CommitResult>("commit", {
    repo: translateRepoPath(options.repo),
    message: options.message,
    author: options.author,
    files: options.files,
    all: options.all ?? false,
    amend: options.amend ?? false,
    // Forwarded only when supplied — keeperd treats absent authorship as
    // "no claim" (older keeperds simply ignore the extra param).
    ...(options.authorship ? { authorship: options.authorship } : {}),
  });
}

/**
 * Push to remote via keeperd.
 *
 * Requires the `--keeper` door. The box holds no SSH keys — keeperd pushes.
 */
export async function push(options: PushOptions): Promise<PushResult> {
  return request<PushResult>("push", {
    repo: translateRepoPath(options.repo),
    remote: options.remote ?? "origin",
    branch: options.branch,
    force: options.force ?? false,
    setUpstream: options.setUpstream ?? false,
  });
}

/**
 * Open a GitHub PR via keeperd.
 *
 * Requires the `--keeper` door. The box holds **no** GitHub API token: keeperd
 * leases a scoped, short-lived one from forge-d internally, opens the PR, and
 * discards it. `repo` is a GitHub `owner/name` slug (not path-translated).
 */
export async function pr(options: PrOptions): Promise<PrResult> {
  return request<PrResult>("pr", {
    repo: options.repo,
    head: options.head,
    base: options.base ?? "main",
    title: options.title,
    ...(options.body !== undefined ? { body: options.body } : {}),
  });
}

/** Options for import-and-push: the host builds commits locally (keyless) and keeperd signs the push. */
export type ImportAndPushOptions = {
  /** The repo keeperd imports the bundle into and pushes from (the daemon-side
   *  keeper clone; path-translated like `commit`/`push` via CLAUDE_BOX_HOST_REPO).
   *  Required — the daemon has no implicit repo. */
  repo: string;
  /** Commit-range git bundle (base64) carrying the new commits the host built. */
  bundleBase64: string;
  /** The already-materialized commit the daemon imports as the tip and pushes. */
  commitSha: string;
  /** Branch to point at the imported commit and push. */
  branch: string;
  /** Push remote (e.g. `origin`). */
  remote: string;
  /** Extra `git push` args after `<remote> <branch>` (e.g. `--force-with-lease`). */
  pushArgs?: string[];
  /** Opt-in attestation: keeperd emits a signed `push/v1` derivation here. */
  ledgerRef?: string;
  /** Opt-in: project the signed attestation onto the pushed commit as a git note
   *  under `refs/notes/<notesRef>` (e.g. `"provenance"`) and push the notes ref. */
  notesRef?: string;
  /** Opt-in: the content-address of the box's L2 launch attestation, so the L3
   *  write links back to its launch (capability chain: write → launch). */
  l2LaunchDigest?: string;
};

/** Result of an import-and-push operation: either success with pushed identity or an error verdict. */
export type ImportAndPushResult =
  | {
      status: "ok";
      commitSha: string;
      pushedRef: string;
      signedDerivation?: unknown;
      note?: { ref: string; written: boolean; pushed: boolean };
    }
  | { status: "error"; code: string; message: string; exitCode?: number };

/**
 * Ask keeperd to import the host-built commit-range bundle and signed-push its
 * branch (object-transfer "model A"). Use this when the host commits locally
 * (keyless) and the daemon must hold ONLY the push credential + signing key.
 */
export async function importAndPush(
  options: ImportAndPushOptions,
): Promise<ImportAndPushResult> {
  return request<ImportAndPushResult>("import-and-push", {
    repo: translateRepoPath(options.repo),
    bundleBase64: options.bundleBase64,
    commitSha: options.commitSha,
    branch: options.branch,
    remote: options.remote,
    ...(options.pushArgs !== undefined ? { pushArgs: options.pushArgs } : {}),
    ...(options.ledgerRef !== undefined ? { ledgerRef: options.ledgerRef } : {}),
    ...(options.notesRef !== undefined ? { notesRef: options.notesRef } : {}),
    ...(options.l2LaunchDigest !== undefined ? { l2LaunchDigest: options.l2LaunchDigest } : {}),
  });
}

/** Options for attesting a room launch: captures the doors held at launch time. */
export type AttestLaunchOptions = {
  /** The launched room/box id (the subject of the launch attestation). */
  subject: string;
  /** The room's resolved door set / manifest (authority = held references). */
  manifest: unknown;
};

/** Result of a launch attestation: either a signed L2 with content address or an error. */
export type AttestLaunchResult =
  | {
      status: "ok";
      subject: string;
      manifestDigest: string;
      l2LaunchDigest: string;
      attestation: unknown;
    }
  | { status: "error"; code: string; message: string };

/**
 * Ask a signer door to produce a signed **L2 launch attestation** over a room +
 * the doors it holds. The launcher acts THROUGH the door — the signing key never
 * leaves the daemon (ocap credential isolation). The human is a guest too, so the
 * launcher is just the launching guest's own signer door.
 */
export async function attestLaunch(options: AttestLaunchOptions): Promise<AttestLaunchResult> {
  return request<AttestLaunchResult>("attest-launch", {
    subject: options.subject,
    manifest: options.manifest,
  });
}

/**
 * Sign arbitrary data via keeperd.
 *
 * The data should be base64 encoded.
 */
export async function signData(data: string): Promise<SignResult> {
  return request<SignResult>("sign", { data });
}

/**
 * Verify a signature via keeperd.
 *
 * Both data and signature should be base64 encoded.
 */
export async function verifySignature(data: string, signature: string, publicKey?: string): Promise<VerifyResult> {
  return request<VerifyResult>("verify", { data, signature, publicKey });
}

/**
 * Get keeperd status (health check).
 */
export async function status(): Promise<KeeperStatus> {
  return request<KeeperStatus>("status");
}

/**
 * Get the signing public key.
 */
export async function getPublicKey(): Promise<{ publicKey: string; keyId: string }> {
  return request<{ publicKey: string; keyId: string }>("getPublicKey");
}

/**
 * Check if keeperd is reachable.
 */
export async function isAvailable(): Promise<boolean> {
  try {
    await status();
    return true;
  } catch {
    return false;
  }
}

// ── CLI (for testing) ────────────────────────────────────────────────────────

/**
 * Read an AI-authorship CLAIM from the file named by `$KEEPER_AUTHORSHIP_SINK`
 * (newline-delimited, repo-relative paths the model edited) and truncate it.
 * The sink is a self-report channel populated out-of-band — e.g. an agent's
 * edit hook — so the CLI need not know how the claim was produced; keeperd
 * reconciles it against the real staged diff. Absent / empty / unreadable → no
 * claim (keeperd then records no authorship). `$KEEPER_AUTHORSHIP_MODEL` labels
 * the model, if set.
 */
async function readAuthorshipSink(): Promise<{ model?: string; aiAuthored: string[] } | undefined> {
  const path = process.env.KEEPER_AUTHORSHIP_SINK;
  if (!path) return undefined;
  try {
    const f = Bun.file(path);
    if (!(await f.exists())) return undefined;
    const aiAuthored = [
      ...new Set((await f.text()).split("\n").map((s) => s.trim()).filter(Boolean)),
    ].sort();
    await Bun.write(path, ""); // next commit starts fresh (best-effort)
    if (!aiAuthored.length) return undefined;
    const model = process.env.KEEPER_AUTHORSHIP_MODEL;
    return { ...(model ? { model } : {}), aiAuthored };
  } catch {
    return undefined;
  }
}

async function main(): Promise<number> {
  const [cmd, ...args] = Bun.argv.slice(2);

  switch (cmd) {
    case "status": {
      const s = await status();
      console.log(JSON.stringify(s, null, 2));
      return 0;
    }
    case "commit": {
      const repo = args[0] ?? ".";
      const message = args[1] ?? "commit via keeper";
      const authorship = await readAuthorshipSink();
      const result = await commit({
        repo,
        message,
        all: true,
        ...(authorship ? { authorship } : {}),
      });
      console.log(`committed ${result.commit}`);
      if (result.attestation) {
        console.log(`attestation: ${result.attestation.statementDigest}`);
      }
      return 0;
    }
    case "push": {
      const repo = args[0] ?? ".";
      const result = await push({ repo });
      console.log(`pushed to ${result.pushed}`);
      console.log(`commits: ${result.commits.join(", ") || "(none)"}`);
      return 0;
    }
    case "pr": {
      const [repo, head, base, title, body] = args;
      if (!repo || !head || !base || !title) {
        console.error("usage: keeper pr <repo> <head> <base> <title> [body]");
        return 1;
      }
      const result = await pr({ repo, head, base, title, ...(body ? { body } : {}) });
      console.log(`opened #${result.number}: ${result.url}`);
      return 0;
    }
    case "key": {
      const key = await getPublicKey();
      console.log(key.publicKey);
      return 0;
    }
    default:
      console.log(`keeper — in-box client for keeperd

Usage:
  keeper status              show keeperd status
  keeper commit [REPO] [MSG] create a signed commit
  keeper push [REPO]         push to remote
  keeper pr <repo> <head> <base> <title> [body]
                             open a GitHub PR (repo = owner/name)
  keeper key                 show signing public key

This command only works inside a box with the --keeper door.`);
      return cmd === "-h" || cmd === "--help" ? 0 : 1;
  }
}

if (import.meta.main) {
  try {
    process.exit(await main());
  } catch (e) {
    if (e instanceof KeeperError) {
      console.error(`error: ${e.code}: ${e.message}`);
    } else {
      console.error(`error: ${e}`);
    }
    process.exit(1);
  }
}
