{
  description = "microvm-policy: egress and filesystem containment for microVMs";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  # The Go toolchain comes from go-overlay rather than nixpkgs: it tracks go.dev
  # directly (every patch and RC, within hours of release), so the toolchain is
  # never gated on nixpkgs' packaging schedule -- nixpkgs' default `go` still
  # lags a new minor by weeks, and `go_1_XX` attributes only appear once someone
  # packages them.
  inputs.go-overlay.url = "github:purpleclay/go-overlay";
  inputs.go-overlay.inputs.nixpkgs.follows = "nixpkgs";

  outputs = { self, nixpkgs, go-overlay }:
    let
      lib = nixpkgs.lib;
      # The guest modules and the nixosTests are Linux-only, and the proxy is
      # only ever run next to a Linux microVM host.
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      # The exact Go release the egress proxy builds with, and the dev shell
      # develops against.
      #
      # Renovate proposes bumps from the golang-version datasource (see
      # renovate.json). go-overlay publishes a new Go release within hours, but
      # this flake sees only what flake.lock has: bumping the literal on its own
      # fails to evaluate -- `attribute '"1.27.2"' missing` -- for as long as
      # the locked go-overlay predates the release. Merge the lock-file
      # maintenance PR first (scheduled earlier for that reason), or run
      # `nix flake update go-overlay` in the same branch.
      # renovate: datasource=golang-version depName=go
      goVersion = "1.27.3";

      # Scoped deliberately: the overlay is applied to a throwaway nixpkgs
      # instance used only to pull the toolchain out, so nothing else in this
      # flake is evaluated against a modified package set.
      goToolchain = system: (import nixpkgs {
        inherit system;
        overlays = [ go-overlay.overlays.default ];
      }).go-bin.versions.${goVersion};

      # Version is the single source of truth in ./VERSION, bumped and
      # committed by `make release-tag` as part of tagging -- so the Nix
      # build and the git tag can never drift. It names the Nix package and
      # stamps the proxy binary (via ldflags).
      version = lib.fileContents ./VERSION;

      mkEgressProxy = pkgs: (pkgs.buildGoModule.override {
        go = goToolchain pkgs.stdenv.hostPlatform.system;
      }) {
        pname = "egress-proxy";
        inherit version;
        src = ./proxy;
        # Standard library only: there is no module graph to vendor.
        vendorHash = null;

        ldflags = [
          "-s"
          "-w"
          "-X"
          "main.version=${version}"
        ];

        meta = {
          description = "Egress proxy with a CONNECT allowlist, credential-injecting LLM reverse proxy and JSONL audit log";
          homepage = "https://github.com/nix-gizmos/microvm-policy";
          changelog = "https://github.com/nix-gizmos/microvm-policy/releases/tag/v${version}";
          license = lib.licenses.mit;
          mainProgram = "egress-proxy";
          platforms = lib.platforms.linux;
        };
      };

      mkEgressReport = pkgs: pkgs.writeShellApplication {
        name = "egress-report";
        runtimeInputs = [ pkgs.tshark pkgs.gawk pkgs.jq pkgs.coreutils ];
        text = builtins.readFile ./egress-report.sh;
        meta = {
          description = "Summarise or live-watch a microVM egress capture against an allowlist, or judge a run from the egress proxy's audit log";
          homepage = "https://github.com/nix-gizmos/microvm-policy";
          license = lib.licenses.mit;
          mainProgram = "egress-report";
          platforms = lib.platforms.linux;
        };
      };
    in
    {
      # The whole reusable layer. A consumer imports nixosModules.default and
      # uses packages.{egress-proxy,egress-report} in its launcher glue; it
      # sets the microvmPolicy.* options (modules/policy.nix) to its own
      # layout, and computes its allowlist from ./allowlists/common.txt plus
      # whatever workload-specific hosts it knows.
      nixosModules = {
        policy = ./modules/policy.nix;
        egress = ./modules/egress.nix;
        workspace = ./modules/workspace.nix;
        default = { imports = [ ./modules/egress.nix ./modules/workspace.nix ]; };
      };

      packages = forAllSystems (pkgs: {
        egress-proxy = mkEgressProxy pkgs;
        egress-report = mkEgressReport pkgs;
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.egress-proxy;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            # The exact release the derivation builds with.
            (goToolchain pkgs.stdenv.hostPlatform.system)
          ] ++ (with pkgs; [
            gopls
            gotools

            gnumake
            golangci-lint # v2 -- matches `version: "2"` in .golangci.yaml
            gofumpt

            # Release tooling (see `make release` / `make release-tag`).
            # git-cliff renders the release notes (cliff.toml); gh publishes
            # them; gsemver computes the next version.
            git-cliff
            gh
            (pkgs.callPackage ./nix/gsemver.nix { })

            jq
          ]);
        };
      });

      checks = forAllSystems (pkgs:
        let
          system = pkgs.stdenv.hostPlatform.system;
        in
        {
          # buildGoModule runs `go test ./...` in its check phase.
          egress-proxy = self.packages.${system}.egress-proxy;
          egress-report = import ./tests/egress-report.nix {
            inherit pkgs lib;
            egressReport = self.packages.${system}.egress-report;
          };
          egress-integration = import ./tests/egress-integration.nix {
            inherit pkgs lib;
            egressProxy = self.packages.${system}.egress-proxy;
            egressReport = self.packages.${system}.egress-report;
          };
          # The guest module off slirp: pod-network shape (KubeVirt), policy as
          # instance data, proxy environment exported by the guest itself.
          guest-pod-network = import ./tests/guest-pod-network.nix {
            inherit pkgs lib;
            egressProxy = self.packages.${system}.egress-proxy;
          };
          # The workspace guard in its opt-out shape: repoDepth + AppArmor,
          # existing and cloned-after-boot repositories, guarded vs opted out.
          workspace-guard = import ./tests/workspace-guard.nix { inherit pkgs lib; };
        });
    };
}
