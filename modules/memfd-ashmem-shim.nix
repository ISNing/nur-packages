{ config, lib, pkgs, ... }:

let
  cfg = config.services.memfd-ashmem-shim;
  
  shimPackage = config.boot.kernelPackages.callPackage ../pkgs/memfd-ashmem-shim { };
in
{
  options.services.memfd-ashmem-shim = {
    enable = lib.mkEnableOption "memfd ashmem shim OOT kernel module";
  };

  config = lib.mkIf cfg.enable {
    boot.extraModulePackages = [ shimPackage ];

    boot.kernelModules = [ "memfd_ashmem_shim" ];
  };
}