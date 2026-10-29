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

      # The package fileset has no `.git`, so identity comes from the flake.
      macoSourceIdentity =
        if builtins.isString (self.rev or null)
          && builtins.match "[0-9a-f]{40}" self.rev != null then {
          revision = self.rev;
          state = "clean";
        } else if builtins.isString (self.dirtyRev or null)
          && builtins.match "[0-9a-f]{40}" (lib.removeSuffix "-dirty" self.dirtyRev) != null then {
          # Nix appends `-dirty` to the commit. The recorded revision stays
          # the 40-digit commit; the suffix is not part of the identity.
          revision = lib.removeSuffix "-dirty" self.dirtyRev;
          state = "dirty";
        } else {
          revision = "";
          state = "unknown";
        };

      pkgsFor = system:
        import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

      rustToolchainFor = pkgs:
        pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

      # Headless CAM crate (`coding-agent-manager`). Omit the desktop
      # shell, Node tree, and desktop-only lockfile.
      camHeadlessLibSrc = ./account-manager/core;

      macoSrc = lib.fileset.toSource {
        root = ./.;
        fileset = lib.fileset.unions [
          ./.cargo
          ./assets
          ./benches
          ./build.rs
          ./Cargo.lock
          ./Cargo.toml
          ./flake.nix
          ./flake.lock
          ./rust-toolchain.toml
          ./src
          camHeadlessLibSrc
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
          # Hash immutable source inputs, never Cargo's modified build tree.
          sourceManifest = pkgs.runCommand "maco-source-manifest.json" { } ''
            ${pkgs.python3}/bin/python3 - "${macoSrc}" "$out" <<'PY'
            import hashlib
            import json
            import os
            import pathlib
            import sys

            root = pathlib.Path(sys.argv[1])
            files = []
            for path in sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix()):
                relative = path.relative_to(root).as_posix()
                if path.is_symlink():
                    files.append({
                        "path": relative,
                        "type": "symlink",
                        "target_sha256": hashlib.sha256(os.fsencode(os.readlink(path))).hexdigest(),
                    })
                elif path.is_file():
                    with path.open("rb") as source:
                        digest = hashlib.file_digest(source, "sha256").hexdigest()
                    metadata = path.stat()
                    files.append({
                        "path": relative,
                        "type": "file",
                        "sha256": digest,
                        "size": metadata.st_size,
                        "executable": bool(metadata.st_mode & 0o111),
                    })
                elif not path.is_dir():
                    raise ValueError("unsupported source entry")
            manifest = {
                "schema_version": 1,
                "source_revision": "${macoSourceIdentity.revision}",
                "source_state": "${macoSourceIdentity.state}",
                "files": files,
            }
            pathlib.Path(sys.argv[2]).write_text(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            PY
          '';
        in
        rustPlatform.buildRustPackage {
          pname = "maco";
          version = cargoToml.package.version;
          src = macoSrc;

          cargoLock.lockFile = ./Cargo.lock;

          env = {
            MACO_SOURCE_REVISION = macoSourceIdentity.revision;
            MACO_SOURCE_STATE = macoSourceIdentity.state;
          };

          # Read the generated input at build time, without import-from-derivation.
          preBuild = lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
            export MACO_SOURCE_MANIFEST_SHA256="$(sha256sum "${sourceManifest}" | cut -d ' ' -f 1)"
          '';

          # Select the public CLI and, on Linux, the CAM authority and setup tools.
          cargoBuildFlags = [ "--locked" "-p" "multi-agent-coding-orchestrator" "--bin" "maco" ]
            ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [
              "-p" "coding-agent-manager" "--bin" "account-authority" "--bin" "cam-grok-setup"
            ];

          nativeBuildInputs = [
            pkgs.cmake
            pkgs.pkg-config
          ];

          buildInputs =
            lib.optionals pkgs.stdenv.hostPlatform.isLinux [
              pkgs.dbus
            ]
            ++ lib.optionals pkgs.stdenv.hostPlatform.isDarwin [
              pkgs.libiconv
            ];

          # Packaging builds the selected release binaries. The repository Cargo
          # gates remain the correctness suite; they need Git, fixtures, and
          # sometimes a delegated user manager that this derivation does not
          # provide.
          doCheck = false;
          doInstallCheck = true;
          installCheckPhase = ''
            runHook preInstallCheck
            test -f "$out/bin/maco"
            test ! -L "$out/bin/maco"
            test -x "$out/bin/maco"
            version_output="$("$out/bin/maco" --version)"
            echo "$version_output"
            printf '%s\n' "$version_output" | grep -Fx "maco ${cargoToml.package.version}"
            printf '%s\n' "$version_output" | grep -Fx "package_version=${cargoToml.package.version}"
            printf '%s\n' "$version_output" | grep -Fx "source_revision=${macoSourceIdentity.revision}"
            printf '%s\n' "$version_output" | grep -Fx "source_state=${macoSourceIdentity.state}"
            test ! -e "$out/bin/multi-agent-coding-orchestrator"
          '' + lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
            test -f "$out/bin/account-authority"
            test ! -L "$out/bin/account-authority"
            test -x "$out/bin/account-authority"
            helper_help="$("$out/bin/account-authority" --help 2>&1)"
            printf '%s\n' "$helper_help" | grep -Fx "Usage: account-authority --socket-path PATH"
            test -f "$out/bin/cam-grok-setup"
            test ! -L "$out/bin/cam-grok-setup"
            test -x "$out/bin/cam-grok-setup"
            setup_help="$("$out/bin/cam-grok-setup" --help)"
            printf '%s\n' "$setup_help" | grep -Fx "Usage: cam-grok-setup [--data-dir ABSOLUTE_PATH] prepare ACCOUNT_ID"
            printf '%s\n' "$setup_help" | grep -Fx "No passwords, tokens, auth paths, or default-home import are accepted."
            test -f "$out/source-manifest.json"
            test ! -L "$out/source-manifest.json"
            cmp "${sourceManifest}" "$out/source-manifest.json"
            cmp "$out/source-manifest.json" "$out/share/maco/source-manifest.json"
            ${pkgs.python3}/bin/python3 - "$out" "${macoSrc}/src/bin/maco.rs" "${macoSrc}/account-manager/core/src/bin/grok_setup.rs" <<'PY'
            import hashlib
            import json
            import pathlib
            import stat
            import sys

            root = pathlib.Path(sys.argv[1])
            def digest(path):
                with path.open("rb") as source:
                    return hashlib.file_digest(source, "sha256").hexdigest()
            for name in ("source-manifest.json", "share/maco/source-manifest.json", "share/maco/main-helper.json", "share/maco/grok-setup-helper.json"):
                metadata = (root / name).lstat()
                assert stat.S_ISREG(metadata.st_mode)
                assert 0 < metadata.st_size <= 1024 * 1024
                assert metadata.st_mode & 0o6022 == 0
            binary = root / "bin/maco"
            assert stat.S_ISREG(binary.lstat().st_mode)
            with binary.open("rb") as source:
                assert source.read(4) == b"\x7fELF"
            declaration = json.loads((root / "share/maco/main-helper.json").read_text())
            assert declaration == {
                "schema": "maco-source-bound-main-helper-v1",
                "binary_sha256": digest(binary),
                "source_manifest_sha256": digest(root / "share/maco/source-manifest.json"),
                "main_entry_sha256": digest(pathlib.Path(sys.argv[2])),
            }
            setup = root / "bin/cam-grok-setup"
            metadata = setup.lstat()
            assert stat.S_ISREG(metadata.st_mode) and metadata.st_mode & 0o111
            assert metadata.st_mode & 0o6022 == 0
            with setup.open("rb") as source:
                assert source.read(4) == b"\x7fELF"
            assert json.loads((root / "share/maco/grok-setup-helper.json").read_text()) == {
                "schema": "maco-source-bound-grok-setup-helper-v1",
                "binary_sha256": digest(setup),
                "source_manifest_sha256": digest(root / "share/maco/source-manifest.json"),
                "setup_entry_sha256": digest(pathlib.Path(sys.argv[3])),
            }
            PY
          '' + lib.optionalString (!pkgs.stdenv.hostPlatform.isLinux) ''
            test ! -e "$out/bin/account-authority"
            test ! -e "$out/bin/cam-grok-setup"
            test ! -e "$out/share/maco/grok-setup-helper.json"
            test ! -e "$out/source-manifest.json"
          '' + ''
            runHook postInstallCheck
          '';

          postInstall = ''
            rm -f "$out/bin/multi-agent-coding-orchestrator"
          '' + lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
            install -m 0444 "${sourceManifest}" "$out/source-manifest.json"
            install -Dm 0444 "${sourceManifest}" "$out/share/maco/source-manifest.json"
          '';

          # Strip/patchelf must finish before binding the installed native image.
          postFixup = lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
            ${pkgs.python3}/bin/python3 - "$out" "${macoSrc}/src/bin/maco.rs" "${macoSrc}/account-manager/core/src/bin/grok_setup.rs" <<'PY'
            import hashlib
            import json
            import pathlib
            import sys

            root = pathlib.Path(sys.argv[1])
            def digest(path):
                with path.open("rb") as source:
                    return hashlib.file_digest(source, "sha256").hexdigest()
            declaration = {
                "schema": "maco-source-bound-main-helper-v1",
                "binary_sha256": digest(root / "bin/maco"),
                "source_manifest_sha256": digest(root / "share/maco/source-manifest.json"),
                "main_entry_sha256": digest(pathlib.Path(sys.argv[2])),
            }
            path = root / "share/maco/main-helper.json"
            path.write_text(json.dumps(declaration, sort_keys=True, separators=(",", ":")) + "\n")
            path.chmod(0o444)
            setup_declaration = {
                "schema": "maco-source-bound-grok-setup-helper-v1",
                "binary_sha256": digest(root / "bin/cam-grok-setup"),
                "source_manifest_sha256": digest(root / "share/maco/source-manifest.json"),
                "setup_entry_sha256": digest(pathlib.Path(sys.argv[3])),
            }
            path = root / "share/maco/grok-setup-helper.json"
            path.write_text(json.dumps(setup_declaration, sort_keys=True, separators=(",", ":")) + "\n")
            path.chmod(0o444)
            PY
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
      packages = forEachSystem (system:
        let pkgs = pkgsFor system;
        in rec {
          maco = macoPackageFor system;
          default = maco;
        } // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          runtime-test-helpers = pkgs.runCommand "maco-runtime-test-helpers" { } ''
            mkdir -p "$out/bin"
            ln -s ${pkgs.coreutils}/bin/env "$out/bin/env"
            ln -s ${pkgs.bash}/bin/sh "$out/bin/sh"
            ln -s ${pkgs.coreutils}/bin/sleep "$out/bin/sleep"
            ln -s ${pkgs.coreutils}/bin/stat "$out/bin/stat"
            ln -s ${lib.getBin pkgs.util-linux}/bin/findmnt "$out/bin/findmnt"
          '';
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
            packages =
              [
                rustToolchain
                pkgs.python3
                pkgs.nodejs_22
                pkgs.git
                cargo-audit
                cargo-deny
              ]
              ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [
                pkgs.pkg-config
                pkgs.dbus
              ];

            RUST_BACKTRACE = "1";
          };
        });
    };
}
