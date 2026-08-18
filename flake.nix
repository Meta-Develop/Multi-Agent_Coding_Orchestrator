{
  description = "Development shell for the Multi-Agent Coding Orchestrator";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { nixpkgs, rust-overlay, ... }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forEachSystem = nixpkgs.lib.genAttrs systems;
      supplyChainPins =
        builtins.fromTOML (builtins.readFile ./scripts/supply_chain_pins.toml);
    in
    {
      devShells = forEachSystem (system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

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
