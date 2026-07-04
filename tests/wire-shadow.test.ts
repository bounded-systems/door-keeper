import { expect, test } from "bun:test";
import { __setWireManifest, shadowCheckParams } from "../keeperd.ts";

test("shadowCheckParams: log-only, warns on undeclared params, allows kind", () => {
  __setWireManifest({
    methods: ["import-and-push"],
    params: { "import-and-push": ["repo", "commitSha", "ledgerRef"] },
  });
  const warns: string[] = [];
  const orig = console.warn;
  console.warn = (m?: unknown) => void warns.push(String(m));
  try {
    // all declared + the kind discriminator → no warning
    shadowCheckParams("import-and-push", {
      kind: "import-and-push",
      repo: "/w",
      commitSha: "abc",
      ledgerRef: "r",
    });
    expect(warns.length).toBe(0);

    // an undeclared param → warns, but never throws (log-only)
    shadowCheckParams("import-and-push", { repo: "/w", bogusField: 1 });
    expect(warns.some((w) => w.includes("bogusField"))).toBe(true);

    // a method not in the agreement → skipped
    shadowCheckParams("status", { anything: 1 });
  } finally {
    console.warn = orig;
    __setWireManifest(null);
  }

  // with no manifest loaded, it's a no-op (the source/test default)
  shadowCheckParams("import-and-push", { whatever: 1 });
});
