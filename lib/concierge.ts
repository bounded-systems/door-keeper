/**
 * @module
 * concierge.ts — in-box client for concierged (the --concierge door).
 *
 * Service-oriented delegation, replacing lib/spawn.ts's role: a box does not
 * launch a child that inherits its doors — it is INTRODUCED to a capability.
 * Providers `register` what they serve; consumers `resolve` a capability and get
 * back an attenuated DoorGrant they then `call()` peer-to-peer.
 *
 * The resolved grant is SIGNED by the concierge (audience/exp/nonce-bound). On a
 * tcp/vsock door the serving room verifies it (signedGrantAuthorizer, keyed by
 * `kid` against the concierge's published `keys`) before honoring a call — so a
 * reachable socket is not authority. On a unix door the held reference is the
 * authority and no per-call grant is needed (CONCIERGE.md §7 / transport-split ADR).
 *
 *   import { resolve } from "./lib/concierge";
 *   import { call } from "./guest-room/protocol.ts";
 *   const scout = await resolve("scout", ["host=github.com"]);
 *   const body  = await call(scout.guest, "fetch", { url: "https://api.github.com/…" });
 *
 * See CONCIERGE.md.
 */

import { call } from "../guest-room/protocol.ts";
import type { DoorGrant, SignedGrant, IssuerKeys } from "../guest-room/mod.ts";

// Grants the box currently holds, keyed by door name. resolve() populates this;
// the per-door clients (e.g. lib/scout) attach the held grant to their calls so
// a tcp/vsock serving room can verify it (reachability is not authority there).
const held = new Map<string, SignedGrant>();

/** The signed grant this box holds for `door`, if it has been resolved. */
export function heldGrant(door: string): SignedGrant | undefined {
  return held.get(door);
}

/** Resolve the concierge socket: $CONCIERGE_SOCK, else XDG runtime, else home. */
function conciergeSocket(): string {
  const envPath = process.env.CONCIERGE_SOCK;
  if (envPath) return envPath;
  const runtime = process.env.XDG_RUNTIME_DIR;
  if (runtime) return `${runtime}/concierged.sock`;
  const home = process.env.HOME ?? "/tmp";
  return `${home}/.claude-box/concierged.sock`;
}

/** Options for registering a capability provider with the concierge. */
export type RegisterOptions = {
  /** Logical capability name, e.g. "scout", "egress". */
  capability: string;
  /** Socket path this provider serves the capability on. */
  door: string;
  /** Env var name the consumer should bind the door to (default: <CAP>_SOCK). */
  env?: string;
  /** One-line description for the rulebook. */
  grants?: string;
  /** Ceiling caveats — the most authority this provider will ever hand out. */
  caveats?: string[];
  /** Lease TTL in seconds; re-register before expiry to stay discoverable. */
  lease?: number;
};

/** Announce a capability this box serves. Returns the granted lease TTL. */
export async function register(opts: RegisterOptions): Promise<{ ttl: number }> {
  return call<{ ttl: number }>(conciergeSocket(), "register", { ...opts });
}

/** Be introduced to a capability: the serving room's door, attenuated by `want`
 *  (only ever narrower than the provider's ceiling) and SIGNED by the concierge
 *  (audience/exp/nonce-bound). Rejects if nothing live serves it. The returned
 *  grant's `guest` transport is what you call(); it is also cached as the held
 *  grant for `capability`, so the per-door client attaches it on calls.
 *
 *  `audience` is the presenting room's id — it MUST match what the serving room
 *  verifies against, or the grant is refused. Defaults to $ROOM_ID. */
export async function resolve(
  capability: string,
  want: string[] = [],
  audience: string = process.env.ROOM_ID ?? "",
): Promise<SignedGrant> {
  const { door } = await call<{ door: SignedGrant }>(conciergeSocket(), "resolve", {
    capability,
    want,
    audience,
  });
  held.set(capability, door);
  return door;
}

/** The concierge's PUBLISHED issuer keys (keyless verification): a serving room
 *  fetches these and verifies presented grants against the key each names by
 *  `kid`. No shared secret. */
export async function keys(): Promise<IssuerKeys> {
  return call<IssuerKeys>(conciergeSocket(), "keys");
}

/** Summary of a capability currently served in the concierge registry. */
export type CapabilityRow = { capability: string; grants: string; providers: number };

/** List the capabilities currently served (discovery/introspection). */
export async function list(): Promise<CapabilityRow[]> {
  const { capabilities } = await call<{ capabilities: CapabilityRow[] }>(conciergeSocket(), "list");
  return capabilities;
}

/** Concierge daemon health/introspection. */
export type ConciergeStatus = { version: string; uptime: number; providers: number };

/** Query the concierge daemon's status (version/uptime/providers served). */
export async function status(): Promise<ConciergeStatus> {
  return call<ConciergeStatus>(conciergeSocket(), "status");
}
