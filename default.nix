# This file describes your repository contents.
# It should return a set of nix derivations
# and optionally the special attributes `lib`, `modules` and `overlays`.
# It should NOT import <nixpkgs>. Instead, you should take pkgs as an argument.
# Having pkgs default to <nixpkgs> is fine though, and it lets you use short
# commands such as:
#     nix-build -A mypackage

{ system ? builtins.currentSystem, pkgs ? import <nixpkgs> { inherit system; }, ... }:

{
  # The `lib`, `modules`, and `overlays` names are special
  lib = import ./lib { inherit pkgs; }; # functions
  modules = import ./modules; # NixOS modules
  overlays = import ./overlays; # nixpkgs overlays

  # JetBrains Toolbox added with libsecret dependency for Linux
  # Upstream source: https://github.com/NixOS/nixpkgs/blob/master/pkgs/by-name/je/jetbrains-toolbox/package.nix
  # Currently at 00e2c2c3587ab8a46be285ddf7e2e62e22155eed
  jetbrains-toolbox = pkgs.callPackage ./pkgs/jetbrains-toolbox { };

  # some-qt5-package = pkgs.libsForQt5.callPackage ./pkgs/some-qt5-package { };
  # ...
}
