{ pkgs ? import <nixpkgs> { } }:

let
  fenix = import (fetchTarball "https://github.com/nix-community/fenix/archive/main.tar.gz") { };

  rustToolchain = fenix.combine [
    fenix.stable.cargo
    fenix.stable.rustc
    fenix.stable.rust-analyzer
    fenix.stable.clippy
    fenix.stable.rustfmt
    fenix.targets.x86_64-pc-windows-gnu.stable.rust-std
  ];

  crossPkgs = pkgs.pkgsCross.mingwW64;
in
pkgs.mkShell {
  # Herramientas que se ejecutan en el HOST (tu PC Linux x86_64)
  nativeBuildInputs = [
    rustToolchain
    pkgs.gcc                          # Proveé 'cc' para proc-macros / build.rs en Linux
    crossPkgs.stdenv.cc               # Cross-compiler (x86_64-w64-mingw32-gcc)
    pkgs.pkg-config
  ];

  # Librerías para el TARGET (Windows)
  buildInputs = [
    crossPkgs.windows.pthreads
  ];

  # Configuración explícita de linkers para Cargo
  CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = "${crossPkgs.stdenv.cc}/bin/x86_64-w64-mingw32-gcc";
  
  # Asegura que el linker nativo 'cc' sea accesible para la arquitectura Host
  CC_x86_64_unknown_linux_gnu = "${pkgs.gcc}/bin/gcc";

  PKG_CONFIG_ALLOW_CROSS = "1";
}
