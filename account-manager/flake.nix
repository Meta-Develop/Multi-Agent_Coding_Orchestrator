{
  description = "Coding Agent Manager — development shell for a Tauri v2 + React application";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    # Reuse the root toolchain closure. Application libraries still come from
    # the original nixpkgs input above, with its unchanged lock and hashes.
    toolchain-nixpkgs.url = "github:NixOS/nixpkgs/da5ad661ba4e5ef59ba743f0d112cbc30e474f32";
    # Match MACO's reviewed overlay revision without changing this app's
    # nixpkgs/library lock. The toolchain itself comes from rust-toolchain.toml.
    rust-overlay = {
      url = "github:oxalica/rust-overlay/b6916ba032e02122d6ed3064f40cabe937363d43";
      inputs.nixpkgs.follows = "toolchain-nixpkgs";
    };
  };

  outputs =
    { nixpkgs, flake-utils, rust-overlay, toolchain-nixpkgs, ... }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        toolchainPkgs = import toolchain-nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
        rustToolchain = toolchainPkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        # Libraries the Tauri v2 webview needs at build and run time on Linux.
        linuxLibs = with pkgs; [
          webkitgtk_4_1
          gtk3
          cairo
          gdk-pixbuf
          glib
          pango
          harfbuzz
          libsoup_3
          librsvg
          openssl
          libsecret
          atk
          libappindicator-gtk3
        ];
      in
      {
        devShells.default = pkgs.mkShell {
          packages =
            with pkgs;
            [
              nodejs_22
              rustToolchain
              rust-analyzer
              pkg-config
              gcc
              # Tauri bundling helpers.
              cargo-tauri
              # Linux packaging targets. AppImage bundling is handled by
              # the Tauri CLI, which downloads its own linuxdeploy tooling.
              dpkg
              rpm
            ]
            ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux linuxLibs;

          shellHook = ''
            export PKG_CONFIG_PATH="${pkgs.lib.makeSearchPath "lib/pkgconfig" linuxLibs}:$PKG_CONFIG_PATH"
            export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath linuxLibs}:$LD_LIBRARY_PATH"
            # WebKitGTK 2.4x needs the DMA-BUF renderer disabled under many
            # Nix-provided GPU stacks; without this `tauri dev` opens a blank
            # window. See docs/DEVELOPMENT.md.
            export WEBKIT_DISABLE_DMABUF_RENDERER=1
            echo "Coding Agent Manager dev shell — node $(node --version), cargo $(cargo --version | cut -d' ' -f2)"
          '';
        };

        packages = pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux rec {
          coding-agent-manager = pkgs.callPackage ./nix/package.nix {
            inherit linuxLibs;
            iconDir = ./src-tauri/icons;
            # Content hash of the Linux release binary from `npm run tauri:build`.
            # Refresh with `nix hash file --sri` after rebuilding that binary.
            unwrappedSha256 = "sha256-O0vPhOKtxT6ilNEvcvaQiYMmN08OYRXNmOw6v4vHZc0=";
          };
          default = coding-agent-manager;
        };
      }
    );
}
