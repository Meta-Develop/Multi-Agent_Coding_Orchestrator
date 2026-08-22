{
  description = "Installable maco package and development shell for the Multi-Agent Coding Orchestrator";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay, ... }:
    let
      inherit (nixpkgs) lib;

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forEachSystem = lib.genAttrs systems;
      supplyChainPins =
        builtins.fromTOML (builtins.readFile ./scripts/supply_chain_pins.toml);
      cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);

      pkgsFor = system:
        import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

      rustToolchainFor = pkgs:
        pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

      macoSrc = lib.fileset.toSource {
        root = ./.;
        fileset = lib.fileset.unions [
          ./.cargo
          ./benches
          ./Cargo.lock
          ./Cargo.toml
          ./src
        ];
      };

      macoPackageFor = system:
        let
          pkgs = pkgsFor system;
          rustToolchain = rustToolchainFor pkgs;
          rustPlatform = pkgs.makeRustPlatform {
            cargo = rustToolchain;
            rustc = rustToolchain;
          };
        in
        rustPlatform.buildRustPackage {
          pname = "maco";
          version = cargoToml.package.version;
          src = macoSrc;

          cargoLock.lockFile = ./Cargo.lock;

          # The crate also ships a long-name alias binary. The installable
          # package is the `maco` PATH entry required by the global-install
          # contract.
          cargoBuildFlags = [ "--bin" "maco" ];

          nativeBuildInputs = [
            pkgs.cmake
            pkgs.pkg-config
          ];

          buildInputs = lib.optionals pkgs.stdenv.hostPlatform.isDarwin [
            pkgs.libiconv
          ];

          # Packaging builds the release binary only. The repository Cargo
          # gates remain the correctness suite; they need Git, fixtures, and
          # sometimes a delegated user manager that this derivation does not
          # provide.
          doCheck = false;
          doInstallCheck = true;
          installCheckPhase = ''
            runHook preInstallCheck
            version_output="$("$out/bin/maco" --version)"
            echo "$version_output"
            echo "$version_output" | grep -F "${cargoToml.package.version}"
            test ! -e "$out/bin/multi-agent-coding-orchestrator"
            runHook postInstallCheck
          '';

          postInstall = ''
            rm -f "$out/bin/multi-agent-coding-orchestrator"
          '';

          meta = {
            description = cargoToml.package.description;
            homepage = cargoToml.package.repository;
            license = lib.licenses.agpl3Plus;
            mainProgram = "maco";
            platforms = systems;
          };
        };
    in
    {
      packages = forEachSystem (system: rec {
        maco = macoPackageFor system;
        default = maco;
      });

      apps = forEachSystem (system: rec {
        maco = {
          type = "app";
          program = "${self.packages.${system}.maco}/bin/maco";
        };
        default = maco;
      });

      overlays.default = final: prev: {
        maco = self.packages.${prev.stdenv.hostPlatform.system}.maco;
      };

      devShells = forEachSystem (system:
        let
          pkgs = pkgsFor system;
          rustToolchain = rustToolchainFor pkgs;

          # Hashes are for the pin versions in scripts/supply_chain_pins.toml.
          # Refresh both hashes when those versions change.
          cargo-audit = pkgs.rustPlatform.buildRustPackage {
            pname = "cargo-audit";
            version = supplyChainPins.cargo_audit;
            src = pkgs.fetchCrate {
              pname = "cargo-audit";
              version = supplyChainPins.cargo_audit;
              hash = "sha256-hrkkDRJvXe2fltWjEW2A0/uKVFWq+9O+wRphsJjT1tE=";
            };
            cargoHash = "sha256-pdFoawDRzJ8gPYAAQHwrCVYeaa1ShSqYA8nwpCAnS1s=";
            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [
              pkgs.openssl
              pkgs.zlib
            ];
            buildFeatures = [ "fix" ];
            doCheck = false;
          };

          cargo-deny = pkgs.rustPlatform.buildRustPackage {
            pname = "cargo-deny";
            version = supplyChainPins.cargo_deny;
            src = pkgs.fetchFromGitHub {
              owner = "EmbarkStudios";
              repo = "cargo-deny";
              tag = supplyChainPins.cargo_deny;
              hash = "sha256-sYxRQvJVbVmzajGJdAHnuvJDELv0cyDCCU8cRU0U0oQ=";
            };
            cargoHash = "sha256-Zb6vQCnhhhL9Ducn9eh5P8Gfopl0lQPTXWW8Q0Y5xBQ=";
            nativeBuildInputs = [ pkgs.pkg-config ];
            buildInputs = [ pkgs.zstd ];
            env.ZSTD_SYS_USE_PKG_CONFIG = true;
            doCheck = false;
          };
        in
        {
          default = pkgs.mkShell {
            packages = [
              rustToolchain
              pkgs.python3
              cargo-audit
              cargo-deny
            ];

            RUST_BACKTRACE = "1";
          };
        });
    };
}
