{ lib, stdenv, kernel }:

stdenv.mkDerivation {
  pname = "memfd-ashmem-shim";
  version = "0.0.0-dev";

  src = ./.;

  nativeBuildInputs = kernel.moduleBuildDependencies;

  makeFlags = [
    "KDIR=${kernel.dev}/lib/modules/${kernel.modDirVersion}/build"
    
    "INSTALL_MOD_PATH=$(out)"
  ];

  meta = with lib; {
    description = "OOT kernel module shim for memfd";
    license = licenses.gpl2;
    platforms = platforms.linux;
    broken = kernel.kernelOlder "5.0"; 
  };
}