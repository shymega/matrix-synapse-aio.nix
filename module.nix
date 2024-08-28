{ pkgs, lib, ... }:

{
  imports = [
    ./matrix-synapse
    ./matrix-sliding-sync
  ];
}
