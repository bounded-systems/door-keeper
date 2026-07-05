// Unit tests for the `pr` op (door-keeper#21): keeperd opens a GitHub PR by
// leasing a scoped, short-lived token from forge-d and using it for exactly one
// POST .../pulls — the box never holds a token, and keeperd never persists,
// logs, or returns the leased one. `openPr` is pure over its deps (lease + fetch)
// so these run with in-memory fakes — no live forge-d, no network.
import { describe, test, expect } from "bun:test";

import { openPr, handleRequest } from "../keeperd";
import type { PrDeps } from "../keeperd";

const TOKEN = "ghs_secret_installation_token_do_not_leak";

/** A fetch fake that records the one call and returns a canned Response. */
function fakeFetch(status: number, jsonBody: unknown, textBody = "") {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fn = ((url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} });
    const res = {
      status,
      json: async () => jsonBody,
      text: async () => textBody,
    } as unknown as Response;
    return Promise.resolve(res);
  }) as unknown as typeof fetch;
  return { fn, calls };
}

/** A lease fake that records the request and returns a canned reply. */
function fakeLease(reply: Awaited<ReturnType<PrDeps["lease"]>>) {
  const calls: Array<{ repositories: string[]; permissions: Record<string, string> }> = [];
  const lease: PrDeps["lease"] = (req) => {
    calls.push(req);
    return Promise.resolve(reply);
  };
  return { lease, calls };
}

const okLease = { status: "ok" as const, token: TOKEN, expiresAt: "2099-01-01T00:00:00Z", permissions: { pull_requests: "write" } };

describe("pr op", () => {
  test("leases a repo-scoped pull_requests:write token, opens the PR, returns {number,url}", async () => {
    const { lease, calls: leaseCalls } = fakeLease(okLease);
    const { fn: fetch, calls: fetchCalls } = fakeFetch(201, { number: 42, html_url: "https://github.com/o/r/pull/42" });

    const result = await openPr(
      { repo: "o/r", head: "feature", base: "main", title: "T", body: "B" },
      { lease, fetch },
    );

    expect(result).toEqual({ number: 42, url: "https://github.com/o/r/pull/42" });

    // Least privilege: scoped to just this repo (short name), pull_requests write.
    expect(leaseCalls).toEqual([{ repositories: ["r"], permissions: { pull_requests: "write" } }]);

    // Exactly one GitHub call, to the right URL, with the leased token + PR body.
    expect(fetchCalls).toHaveLength(1);
    expect(fetchCalls[0].url).toBe("https://api.github.com/repos/o/r/pulls");
    const headers = fetchCalls[0].init.headers as Record<string, string>;
    expect(headers.Authorization).toBe(`Bearer ${TOKEN}`);
    expect(JSON.parse(fetchCalls[0].init.body as string)).toEqual({ title: "T", head: "feature", base: "main", body: "B" });
  });

  test("the leased token never appears in the returned result", async () => {
    const { lease } = fakeLease(okLease);
    const { fn: fetch } = fakeFetch(201, { number: 1, html_url: "https://github.com/o/r/pull/1" });
    const result = await openPr({ repo: "o/r", head: "h", title: "t" }, { lease, fetch });
    expect(JSON.stringify(result)).not.toContain(TOKEN);
  });

  test("base defaults to main and body is omitted when absent", async () => {
    const { lease } = fakeLease(okLease);
    const { fn: fetch, calls } = fakeFetch(201, { number: 7, html_url: "u" });
    await openPr({ repo: "o/r", head: "h", title: "t" }, { lease, fetch });
    expect(JSON.parse(calls[0].init.body as string)).toEqual({ title: "t", head: "h", base: "main" });
  });

  test("a failed lease throws LEASE_FAILED and never calls GitHub", async () => {
    const { lease } = fakeLease({ status: "error", code: "not-configured", message: "no App key" });
    const { fn: fetch, calls } = fakeFetch(201, {});
    await expect(openPr({ repo: "o/r", head: "h", title: "t" }, { lease, fetch })).rejects.toMatchObject({
      code: "LEASE_FAILED",
    });
    expect(calls).toHaveLength(0);
  });

  test("a non-201 from GitHub throws PR_FAILED without leaking the token", async () => {
    const { lease } = fakeLease(okLease);
    const { fn: fetch } = fakeFetch(422, {}, "Validation Failed: head sha not found");
    let thrown: { code?: string; message?: string } = {};
    try {
      await openPr({ repo: "o/r", head: "h", title: "t" }, { lease, fetch });
    } catch (e) {
      thrown = e as { code?: string; message?: string };
    }
    expect(thrown.code).toBe("PR_FAILED");
    expect(thrown.message).toContain("422");
    expect(thrown.message).not.toContain(TOKEN);
  });

  test("missing required params → INVALID_PARAMS before any lease", async () => {
    const { lease, calls } = fakeLease(okLease);
    const { fn: fetch } = fakeFetch(201, {});
    await expect(openPr({ repo: "o/r", head: "h" }, { lease, fetch })).rejects.toMatchObject({ code: "INVALID_PARAMS" });
    expect(calls).toHaveLength(0);
  });

  test("repo not in owner/name form → INVALID_PARAMS", async () => {
    const { lease } = fakeLease(okLease);
    const { fn: fetch } = fakeFetch(201, {});
    for (const repo of ["justname", "/r", "o/"]) {
      await expect(openPr({ repo, head: "h", title: "t" }, { lease, fetch })).rejects.toMatchObject({
        code: "INVALID_PARAMS",
      });
    }
  });

  test("pr is registered in METHODS (dispatches through handleRequest)", async () => {
    // Empty params fail validation inside openPr *before* touching the forge-d
    // socket, so this proves registration without a live daemon.
    const resp = await handleRequest(JSON.stringify({ id: "1", method: "pr", params: {} }));
    expect(resp.ok).toBe(false);
    expect(resp.error?.code).toBe("INVALID_PARAMS");
  });
});
