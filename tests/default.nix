{ nixpkgs, pkgs, lib, ... }:
{
  nginx-pipeline = pkgs.callPackage ./nginx-pipeline { inherit nixpkgs pkgs lib; };
}
