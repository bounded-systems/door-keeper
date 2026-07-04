{
  # door-keeper — the git-signing capability door (keeperd) as a pinned OCI image.
  #
  # Extracted from claude-box (epic prx-ii01, card 2). keeperd holds the box's
  # Ed25519 signing key and turns reviewed in-box edits into signed commits/refs;
  # the box itself holds no keys. Image builds on both Linux arches; claude-box
  # (the integrator) pins the published image and runs the cross-door system tests.
  description = "door-keeper — the keeperd git-signing door as a pinned OCI image";

  # Same nixpkgs rev as claude-box, so bun/git/ssh match the rest of the fleet.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/9f11f828c213641c2369a9f1fa31fe31557e3156";

  # The capability engine + contract + client SDK, each a PINNED input and a
  # generated mirror (./guest-room, ./contract, ./lib) kept honest by the
  # *-mirror checks below. Keep the guest-room rev in lockstep with door-kit's.
  inputs.guest-room.url = "github:bounded-systems/guest-room/79662abe154039d1bf91f46cefa03a06204e87ef";
  inputs.guest-room.flake = false;
  inputs.ocap-provenance.url = "github:bounded-systems/ocap-provenance/28c7a8530e05edc446abf62cd2e04ab73f4f626f";
  inputs.ocap-provenance.flake = false;
  inputs.door-kit.url = "github:bounded-systems/door-kit/4b72a33d4f03c7f5869c229adf8617802656a1b5";
  inputs.door-kit.flake = false;
  # the PUBLISHED keeper-wire agreement — keeperd's own METHODS are checked
  # against it, so the contract (not this daemon) is the source of truth.
  inputs.keeper-wire.url = "github:bounded-systems/keeper-wire";
  inputs.keeper-wire.flake = false;

  outputs =
    { self, nixpkgs, guest-room, ocap-provenance, door-kit, keeper-wire }:
    let
      systems = [ "aarch64-linux" "x86_64-linux" ];
      forEach = nixpkgs.lib.genAttrs systems;
      pkgsFor = system: import nixpkgs { inherit system; };
      uid = 1000;
    in
    {
      packages = forEach (system:
        let pkgs = pkgsFor system;
        in {
          # keeperd-image — the git-signing daemon as a container.
          #   nix build .#keeperd-image && podman load -i result
          #   podman run -v doors:/run/doors -v keys:/keys -v repo:/work keeperd
          keeperd-image =
            let
              keeperdTools = with pkgs; [ bun git openssh cacert coreutils bashInteractive ];

              keeperdEnv = pkgs.buildEnv {
                name = "keeperd-image-root";
                paths = keeperdTools;
                pathsToLink = [ "/bin" "/etc" "/share" "/lib" ];
              };

              # Bundle keeperd.ts + its deps (the vendored mirrors).
              keeperdSrc = pkgs.runCommand "keeperd-src" { } ''
                mkdir -p $out/app/lib $out/app/guest-room
                cp ${./keeperd.ts} $out/app/keeperd.ts
                cp -r ${./contract} $out/app/contract
                cp ${./lib/keeper.ts} $out/app/lib/keeper.ts
                cp ${./lib/runtime.ts} $out/app/lib/runtime.ts
                cp ${./lib/concierge.ts} $out/app/lib/concierge.ts
                cp ${./guest-room/daemon.ts} $out/app/guest-room/daemon.ts
                cp ${./guest-room/mod.ts} $out/app/guest-room/mod.ts
                cp ${./guest-room/protocol.ts} $out/app/guest-room/protocol.ts
              '';

              keeperdEntrypoint = pkgs.writeShellScript "keeperd-entrypoint" ''
                exec bun /app/keeperd.ts serve \
                  --socket /run/doors/keeperd.sock \
                  --key /keys/keeper.key \
                  "$@"
              '';
            in
            pkgs.dockerTools.buildLayeredImage {
              name = "keeperd";
              tag = "dev";

              contents = [ keeperdEnv keeperdSrc ];

              extraCommands = ''
                mkdir -p etc tmp run/doors keys work
                chmod 1777 tmp
                cat > etc/passwd <<EOF
                root:x:0:0:root:/root:/bin/bash
                keeper:x:${toString uid}:${toString uid}:keeper:/app:/bin/bash
                EOF
                cat > etc/group <<EOF
                root:x:0:
                keeper:x:${toString uid}:
                EOF
              '';

              fakeRootCommands = ''
                chown -R ${toString uid}:${toString uid} run/doors keys work
              '';

              config = {
                Entrypoint = [ "${keeperdEntrypoint}" ];
                WorkingDir = "/app";
                User = "keeper";
                Env = [
                  "HOME=/app"
                  "PATH=/bin"
                  "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
                  "GIT_SSL_CAINFO=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
                  "LANG=C.UTF-8"
                ];
                Volumes = {
                  "/run/doors" = { };
                  "/keys" = { };
                  "/work" = { };
                };
              };
            };

          default = self.packages.${system}.keeperd-image;
        });

      # ── sync apps (regenerate the vendored mirrors from the pinned inputs) ──
      apps.aarch64-darwin =
        let pkgs = pkgsFor "aarch64-darwin";
        in {
          sync-guest-room = {
            type = "app";
            program = "${pkgs.writeShellScriptBin "sync-guest-room" ''
              set -euo pipefail
              for f in daemon.ts mod.ts protocol.ts; do
                install -m 644 ${guest-room}/$f "$PWD/guest-room/$f"; echo "synced guest-room/$f"
              done
            ''}/bin/sync-guest-room";
            meta.description = "Sync ./guest-room/ from the pinned guest-room input";
          };
          sync-ocap-provenance = {
            type = "app";
            program = "${pkgs.writeShellScriptBin "sync-ocap-provenance" ''
              set -euo pipefail
              for f in CHAIN.md README.md SLSA-MAPPING.md capability-provenance.v0.1.schema.json slsa.ts types.ts; do
                install -m 644 ${ocap-provenance}/$f "$PWD/contract/$f"; echo "synced contract/$f"
              done
            ''}/bin/sync-ocap-provenance";
            meta.description = "Sync ./contract/ from the pinned ocap-provenance input";
          };
          sync-door-kit = {
            type = "app";
            program = "${pkgs.writeShellScriptBin "sync-door-kit" ''
              set -euo pipefail
              for f in keeper.ts runtime.ts concierge.ts; do
                install -m 644 ${door-kit}/lib/$f "$PWD/lib/$f"; echo "synced lib/$f"
              done
            ''}/bin/sync-door-kit";
            meta.description = "Sync ./lib/ from the pinned door-kit input";
          };
        };

      # ── daemon-side wire conformance (Linux, so CI actually runs it) ──
      # keeperd's METHODS table must match the published keeper-wire agreement.
      # Unlike the darwin-only mirror checks below, this is Linux-scoped and wired
      # into CI (nix build .#checks.<sys>.keeper-wire-methods).
      checks = (forEach (system:
        let pkgs = pkgsFor system;
        in {
          keeper-wire-methods = pkgs.runCommand "keeper-wire-methods" {
            nativeBuildInputs = [ pkgs.deno ];
            DENO_DIR = "/tmp/deno";
          } ''
            export HOME=$TMPDIR
            deno run --no-remote --allow-read ${./tests/keeper-wire-methods.ts} \
              ${./keeperd.ts} \
              ${keeper-wire}/manifest.json
            touch $out
          '';
        })) // {
        # ── mirror checks: the vendored dirs must match the pinned inputs ──
        aarch64-darwin = let pkgs = pkgsFor "aarch64-darwin";
        in {
          guest-room-mirror = pkgs.runCommand "guest-room-mirror" { } ''
            for f in daemon.ts mod.ts protocol.ts; do
              if ! diff -u ${guest-room}/$f ${./guest-room}/$f; then
                echo "guest-room/$f drifted — run: nix run .#sync-guest-room" >&2; exit 1
              fi
            done
            touch $out
          '';
          ocap-provenance-mirror = pkgs.runCommand "ocap-provenance-mirror" { } ''
            for f in CHAIN.md README.md SLSA-MAPPING.md capability-provenance.v0.1.schema.json slsa.ts types.ts; do
              if ! diff -u ${ocap-provenance}/$f ${./contract}/$f; then
                echo "contract/$f drifted — run: nix run .#sync-ocap-provenance" >&2; exit 1
              fi
            done
            touch $out
          '';
          door-kit-mirror = pkgs.runCommand "door-kit-mirror" { } ''
            for f in keeper.ts runtime.ts concierge.ts; do
              if ! diff -u ${door-kit}/lib/$f ${./lib}/$f; then
                echo "lib/$f drifted — run: nix run .#sync-door-kit" >&2; exit 1
              fi
            done
            touch $out
          '';
        };
      };
    };
}
