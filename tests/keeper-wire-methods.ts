/**
 * @module
 * Daemon-side wire conformance: keeperd's own METHODS dispatch table must match
 * the PUBLISHED keeper-wire agreement (@bounded-systems/keeper-wire), pinned as a
 * flake input and read as manifest.json. The agreement is the single source of
 * truth; if keeperd adds/drops a method without the contract moving, this reds.
 *
 *   deno run --no-remote --allow-read tests/keeper-wire-methods.ts \
 *     <keeperd.ts> <keeper-wire/manifest.json>
 *
 * Dependency-free (regex over source) so it runs sealed in the Nix check.
 */

const [keeperdPath, manifestPath] = Deno.args;
if (!keeperdPath || !manifestPath) {
  console.error("usage: keeper-wire-methods.ts <keeperd.ts> <manifest.json>");
  Deno.exit(2);
}

const src = Deno.readTextFileSync(keeperdPath).replace(/\/\*[\s\S]*?\*\//g, "");
const block = src.match(/const\s+METHODS[^=]*=\s*\{([\s\S]*?)\}/);
if (!block) {
  console.error("keeper-wire: could not find keeperd's METHODS table");
  Deno.exit(1);
}
const daemon = new Set(
  [...block[1].matchAll(/(?:^|,)\s*(?:"([^"]+)"|([A-Za-z_][\w-]*))\s*:/g)]
    .map((m) => m[1] ?? m[2]),
);
const want = new Set<string>(
  JSON.parse(Deno.readTextFileSync(manifestPath)).methods,
);

const missing = [...want].filter((m) => !daemon.has(m));
const extra = [...daemon].filter((m) => !want.has(m));
if (missing.length || extra.length) {
  console.error("keeper-wire: keeperd METHODS drift from the agreement:");
  if (missing.length) console.error(`  daemon missing: ${missing.join(", ")}`);
  if (extra.length) console.error(`  daemon extra:   ${extra.join(", ")}`);
  Deno.exit(1);
}
console.log("keeper-wire: keeperd METHODS match the agreement. ✓");
