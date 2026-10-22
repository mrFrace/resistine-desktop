# The Phoenix SIEM agent: Wazuh agent 5.0.0 beta5, as built for the Phoenix
# manager (dashboard.phoenix.exposed). The .deb is only served to signed-in
# Phoenix users, so it is pinned by hash with requireFile. To add it:
#
#   nix-store --add-fixed sha256 phoenix-agent_5.0.0-1_amd64.deb
#
# The output is the unpacked /opt/phoenix-agent tree, used only as a seed:
# the agent writes into its own tree (queue, logs, etc), so
# nix/wazuh-agent.nix copies this into services.wazuh-agent.installDir
# (default /opt/phoenix-agent, the same path) whenever VERSION.json differs.
# The binaries are relocatable (wazuh-control resolves its own dir, libs use
# $ORIGIN/../lib) and run through nix-ld, so they are left unpatched.
{
  lib,
  stdenvNoCC,
  requireFile,
  dpkg,
}:

stdenvNoCC.mkDerivation {
  pname = "phoenix-agent";
  version = "5.0.0-beta5";

  # requireFile marks its file unfree; Wazuh is GPLv2. (overrideAttrs, since
  # older nixpkgs' requireFile takes no meta argument.)
  src = (requireFile {
    name = "phoenix-agent_5.0.0-1_amd64.deb";
    sha256 = "a7935b5f1f516e939c0b1bb75bac585541b755f06621b635b5fef0932ca87981";
    message = ''
      phoenix-agent_5.0.0-1_amd64.deb is not in the nix store. Get it from
      your Phoenix admin (or the manager host) and add it:

        nix-store --add-fixed sha256 phoenix-agent_5.0.0-1_amd64.deb

      Or set programs.phoenix.siem.enable = false to install Phoenix
      without the SIEM agent.
    '';
  }).overrideAttrs (old: {
    meta = (old.meta or { }) // { license = lib.licenses.gpl2Only; };
  });

  nativeBuildInputs = [ dpkg ];

  unpackPhase = "dpkg-deb -x $src root";

  # Prebuilt upstream binaries: no strip, no patchelf, no shebang rewriting.
  dontConfigure = true;
  dontBuild = true;
  dontFixup = true;

  installPhase = ''
    cp -a root/opt/phoenix-agent $out

    # What the package postinst does for a distro it has no SCA set for:
    # install the generic policies into ruleset/sca.
    sca=$out/packages_files/agent_installation_scripts/sca
    # The deb's ruleset/sca also carries cis_debian7.yml, and 5.0 loads every
    # policy found there, so it would report a Debian 7 benchmark for NixOS.
    rm -rf $out/ruleset/sca
    mkdir -p $out/ruleset/sca
    for f in $(cat $sca/generic/sca.files); do
      cp $sca/$f $out/ruleset/sca/
    done
    rm -rf $out/packages_files

    # Placeholder from the build host; the module installs /etc/localtime.
    rm -f $out/etc/localtime
  '';

  meta = {
    description = "Phoenix SIEM agent (Wazuh agent 5.0, prebuilt)";
    license = lib.licenses.gpl2Only;
    platforms = [ "x86_64-linux" ];
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
  };
}
