# Wraps a Linux release binary produced by the documented Tauri build:
#
#   nix develop --command bash -lc 'npm ci && npm run tauri:build'
#
# Official GitHub installers are not published yet (M7 / FR-10). This
# package is not a cargoHash/npmHash source build; it imports that binary
# by content hash and wraps it for a Nix profile or Home Manager.
#
# After tauri:build:
#
#   nix hash file --sri "$CARGO_TARGET_DIR/release/coding-agent-manager"
#   nix-store --add-fixed sha256 \
#     "$CARGO_TARGET_DIR/release/coding-agent-manager"
#
# Put the SRI hash in `unwrappedSha256` in flake.nix. Default
# CARGO_TARGET_DIR is src-tauri/target when unset.
{
  lib,
  stdenv,
  stdenvNoCC,
  wrapGAppsHook3,
  makeWrapper,
  copyDesktopItems,
  makeDesktopItem,
  linuxLibs,
  iconDir,
  unwrappedSha256,
}:

let
  unwrapped = stdenvNoCC.mkDerivation {
    name = "coding-agent-manager";
    outputHash = unwrappedSha256;
    outputHashMode = "flat";
    preferLocalBuild = true;

    # Substituted from the store when the hash is already present.
    # Otherwise the builder explains how to add the binary.
    buildCommand = ''
      echo "Official signed installers are not published yet." >&2
      echo "Build the Linux release binary:" >&2
      echo "  nix develop --command bash -lc 'npm ci && npm run tauri:build'" >&2
      echo "If the root filesystem is small, point CARGO_TARGET_DIR, CARGO_HOME," >&2
      echo "and the npm cache at a larger volume first." >&2
      echo "Then add the binary to the Nix store and set unwrappedSha256:" >&2
      echo "  nix-store --add-fixed sha256 \$CARGO_TARGET_DIR/release/coding-agent-manager" >&2
      exit 1
    '';

    meta = {
      description = "Unwrapped Coding Agent Manager release binary";
      license = lib.licenses.gpl3Plus;
    };
  };
in
stdenv.mkDerivation {
  pname = "coding-agent-manager";
  version = "0.1.0";

  src = iconDir;
  dontConfigure = true;
  dontBuild = true;
  dontStrip = true;

  nativeBuildInputs = [
    wrapGAppsHook3
    makeWrapper
    copyDesktopItems
  ];

  buildInputs = linuxLibs;

  desktopItems = [
    (makeDesktopItem {
      name = "coding-agent-manager";
      desktopName = "Coding Agent Manager";
      comment = "Account manager for AI coding agents";
      exec = "coding-agent-manager";
      icon = "coding-agent-manager";
      startupWMClass = "dev.metadevelop.coding-agent-manager";
      categories = [ "Development" ];
      startupNotify = true;
    })
  ];

  installPhase = ''
    runHook preInstall
    install -Dm755 ${unwrapped} $out/bin/coding-agent-manager
    install -Dm644 32x32.png $out/share/icons/hicolor/32x32/apps/coding-agent-manager.png
    install -Dm644 128x128.png $out/share/icons/hicolor/128x128/apps/coding-agent-manager.png
    install -Dm644 128x128@2x.png $out/share/icons/hicolor/256x256/apps/coding-agent-manager.png
    install -Dm644 icon.png $out/share/icons/hicolor/512x512/apps/coding-agent-manager.png
    runHook postInstall
  '';

  preFixup = ''
    gappsWrapperArgs+=(
      --prefix LD_LIBRARY_PATH : ${lib.makeLibraryPath linuxLibs}
      --set WEBKIT_DISABLE_DMABUF_RENDERER 1
    )
  '';

  meta = {
    description = "Unified account, credential, and quota manager for AI coding agents";
    homepage = "https://github.com/Meta-Develop/Coding-Agent-Manager";
    license = lib.licenses.gpl3Plus;
    mainProgram = "coding-agent-manager";
    platforms = lib.platforms.linux;
  };
}
