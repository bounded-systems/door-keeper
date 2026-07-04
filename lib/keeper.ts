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

// Bun.connect via the global (no `import … from "bun"`) so the package resolves
// on JSR/Deno publish — the same way the guest-room protocol uses Bun globals.
// (Full Deno/Bun-agnostic abstraction is tracked separately.)
const connect = Bun.connect;

import { heldGrant } from "./concierge.ts";
import type { SignedGrant } from "../guest-room/mod.ts";

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

type KeeperTarget =
  | { type: "unix"; path: string }
  | { type: "tcp"; host: string; port: number };

/** Get keeperd connection target from environment or default. */
function getTarget(): KeeperTarget {
  // TCP mode: KEEPERD_HOST=host:port (e.g., "host.containers.internal:9999")
  const tcpHost = process.env.KEEPERD_HOST;
  if (tcpHost) {
    const [host, portStr] = tcpHost.split(":");
    return { type: "tcp", host: host || "127.0.0.1", port: Number(portStr) || 9999 };
  }

  // Unix socket mode: KEEPERD_SOCK=/path/to/socket
  const sockPath = process.env.KEEPERD_SOCK;
  if (sockPath) return { type: "unix", path: sockPath };

  // In-box default: socket at /run/keeperd.sock
  if (Bun.file("/run/keeperd.sock").size !== undefined) {
    return { type: "unix", path: "/run/keeperd.sock" };
  }

  // Fallback for testing outside a box
  const runtime = process.env.XDG_RUNTIME_DIR;
  if (runtime) return { type: "unix", path: `${runtime}/keeperd.sock` };
  const home = process.env.HOME ?? "/tmp";
  return { type: "unix", path: `${home}/.claude-box/keeperd.sock` };
}

type RequestEnvelope = {
  id: string;
  method: string;
  params?: Record<string, unknown>;
  /** The signed grant this box holds for "keeper", presented so a tcp/vsock
   *  keeperd can verify it (no-op on a unix door). */
  grant?: SignedGrant;
};

type ResponseEnvelope = {
  id: string;
  ok: boolean;
  result?: unknown;
  error?: { code: string; message: string };
};

/** Send a request to keeperd and wait for response. */
async function request<T>(method: string, params: Record<string, unknown> = {}): Promise<T> {
  const target = getTarget();
  const id = crypto.randomUUID();

  return new Promise((resolve, reject) => {
    let buffer = "";
    let resolved = false;

    const socketHandler = {
      open(sock: ReturnType<typeof connect> extends Promise<infer S> ? S : never) {
        const grant = heldGrant("keeper"); // present it iff resolved (tcp/vsock gate)
        const req: RequestEnvelope = { id, method, params, ...(grant ? { grant } : {}) };
        sock.write(JSON.stringify(req) + "\n");
      },
      data(sock: ReturnType<typeof connect> extends Promise<infer S> ? S : never, data: Buffer) {
        buffer += data.toString();
        const newline = buffer.indexOf("\n");
        if (newline >= 0 && !resolved) {
          resolved = true;
          const line = buffer.slice(0, newline);
          sock.end();
          try {
            const resp = JSON.parse(line) as ResponseEnvelope;
            if (resp.ok) {
              resolve(resp.result as T);
            } else {
              reject(new KeeperError(
                resp.error?.code ?? "UNKNOWN",
                resp.error?.message ?? "keeperd error"
              ));
            }
          } catch (e) {
            reject(new KeeperError("PARSE_ERROR", "invalid response from keeperd"));
          }
        }
      },
      error(_sock: unknown, err: Error) {
        if (!resolved) {
          resolved = true;
          reject(new KeeperError("CONNECTION_ERROR", `failed to connect to keeperd: ${err}`));
        }
      },
      close() {
        if (!resolved) {
          resolved = true;
          reject(new KeeperError("CONNECTION_CLOSED", "connection closed before response"));
        }
      },
    };

    const connectPromise = target.type === "unix"
      ? connect({ unix: target.path, socket: socketHandler })
      : connect({ hostname: target.host, port: target.port, socket: socketHandler });

    connectPromise.catch((err) => {
      if (!resolved) {
        resolved = true;
        reject(new KeeperError("CONNECTION_ERROR", `failed to connect to keeperd: ${err}`));
      }
    });
  });
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
    kind: "import-and-push",
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
