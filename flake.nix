{
  description = "NixOS modules for matrix related services";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-24.05";
  };

  outputs = inputs@{ self, ... }:
    let
      pkgs = inputs.nixpkgs.legacyPackages.x86_64-linux;
      inherit (pkgs) lib;
      matrix-lib = import ./lib.nix { inherit (inputs.nixpkgs) lib; };
    in
    {
      nixosModules = {
        default = import ./module.nix { inherit pkgs lib matrix-lib; };
      };
      packages = {
        test-nginx-pipeline = pkgs.callPackage ./tests/nginx-pipeline { inherit pkgs lib matrix-lib; inherit (inputs) nixpkgs; };
      };
    };
}
