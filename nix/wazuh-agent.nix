# Wazuh agent 5.0 (beta5, "phoenix" build) under /opt/phoenix-agent, the
# location the upstream .deb installs to.
#
# The agent tree comes from nix/phoenix-agent.nix and is copied into
# installDir whenever its VERSION.json differs; the previous tree is kept as
# installDir.bak-<timestamp>. The binaries are prebuilt and need nix-ld.
#
# Enrollment needs the manager's password (its etc/authd.pass) in
# enrollmentPasswordFile, a root-only file kept out of the nix store.
#
# The manager's :1517 certificate is verified against the Phoenix Agent CA
# (caFile), not pinned, so the manager can reissue it without touching agents.

{ config, lib, pkgs, ... }:

let
  cfg = config.services.wazuh-agent;
  dir = cfg.installDir;

  # logcollector dlopen()s libsystemd.so.0 for the journald source; NixOS has
  # no /usr/lib for it to find. Expose only that one library.
  libsystemdDir = pkgs.runCommand "wazuh-libsystemd" { } ''
    mkdir -p $out/lib
    ln -s ${lib.getLib config.systemd.package}/lib/libsystemd.so.0 $out/lib/
  '';

  ossecConf = pkgs.writeText "ossec.conf" ''
    <!-- Managed by the Phoenix NixOS module; overwritten on start. -->
    <ossec_config>
      <!-- Wazuh 5.0: a bare host means https on port 1517. -->
      <agent>
        <manager>
          <endpoint>${cfg.managerIP}</endpoint>
        </manager>
        <ssl>
          <verification_mode>${cfg.verificationMode}</verification_mode>
          ${lib.optionalString (cfg.verificationMode != "none" && cfg.verificationMode != "system")
            "<certificate_authorities>etc/phoenix-ca.pem</certificate_authorities>"}
        </ssl>
        <enrollment>
          <enabled>yes</enabled>
          <agent_name>${cfg.agentName}</agent_name>
          <authorization_pass_path>etc/authd.pass</authorization_pass_path>
        </enrollment>
        <config-profile>nixos</config-profile>
      </agent>

      <rootcheck>
        <disabled>no</disabled>
        <check_dev>yes</check_dev>
        <check_sys>yes</check_sys>
        <check_pids>yes</check_pids>
        <check_ports>yes</check_ports>
        <check_if>yes</check_if>
        <frequency>43200</frequency>
        <skip_nfs>yes</skip_nfs>
        <ignore>/var/lib/containerd</ignore>
        <ignore>/var/lib/docker/overlay2</ignore>
      </rootcheck>

      <wodle name="syscollector">
        <disabled>no</disabled>
        <interval>1h</interval>
        <scan_on_start>yes</scan_on_start>
        <hardware>yes</hardware>
        <os>yes</os>
        <network>yes</network>
        <packages>yes</packages>
        <ports all="yes">yes</ports>
        <processes>yes</processes>
        <users>yes</users>
        <groups>yes</groups>
        <services>yes</services>
        <browser_extensions>yes</browser_extensions>
        <synchronization>
          <enabled>yes</enabled>
          <interval>5m</interval>
          <max_eps>75</max_eps>
          <integrity_interval>24h</integrity_interval>
        </synchronization>
      </wodle>

      <sca>
        <enabled>yes</enabled>
        <scan_on_start>yes</scan_on_start>
        <interval>${cfg.scaInterval}</interval>
        <policies>
          <!-- NixOS-adapted copy of the stock CIS policy, see scaNotApplicableChecks. -->
          <policy>ruleset/sca/${cfg.scaPolicyFile}</policy>
          <!-- Superseded by the copy above; without this both would run. -->
          <policy enabled="no">ruleset/sca/${cfg.scaSourceFile}</policy>
        </policies>
      </sca>

      <syscheck>
        <disabled>no</disabled>
        <frequency>43200</frequency>
        <directories>/etc,/usr/bin,/usr/sbin</directories>
        <directories>/bin,/sbin,/boot</directories>
        <ignore>/etc/mtab</ignore>
        <ignore>/etc/hosts.deny</ignore>
        <ignore>/etc/random-seed</ignore>
        <ignore>/etc/adjtime</ignore>
        <ignore type="sregex">.log$|.swp$</ignore>
        <skip_nfs>yes</skip_nfs>
        <skip_dev>yes</skip_dev>
        <skip_proc>yes</skip_proc>
        <skip_sys>yes</skip_sys>
        <process_priority>10</process_priority>
        <max_eps>50</max_eps>
        <synchronization>
          <enabled>yes</enabled>
          <interval>5m</interval>
          <max_eps>75</max_eps>
          <integrity_interval>24h</integrity_interval>
        </synchronization>
      </syscheck>

      <localfile>
        <log_format>journald</log_format>
        <location>journald</location>
      </localfile>

      <localfile>
        <log_format>syslog</log_format>
        <location>${dir}/logs/active-responses.log</location>
      </localfile>

      <localfile>
        <log_format>command</log_format>
        <command>df -P</command>
        <frequency>360</frequency>
      </localfile>

      <active-response>
        <disabled>no</disabled>
        <ca_store>etc/wpk_root.pem</ca_store>
        <ca_verification>yes</ca_verification>
      </active-response>

      <logging>
        <log_format>plain</log_format>
      </logging>
    ${cfg.extraConfig}
    </ossec_config>
  '';
in
{
  options.services.wazuh-agent = {
    enable = lib.mkEnableOption "the Phoenix SIEM agent (Wazuh agent 5.0)";

    managerIP = lib.mkOption {
      type = lib.types.str;
      default = "dashboard.phoenix.exposed";
      description = ''
        Wazuh manager written to <agent><manager><endpoint>. Changing it clears
        client.keys so the agent re-enrolls with the new manager.
      '';
    };

    agentName = lib.mkOption {
      type = lib.types.str;
      default = config.networking.hostName;
      description = "Name of this agent (defaults to hostname)";
    };

    installDir = lib.mkOption {
      type = lib.types.str;
      default = "/opt/phoenix-agent";
      description = "Where the agent tree lives (it writes its state there).";
    };

    legacyInstallDirs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "/opt/resistine" ];
      description = ''
        Earlier installDir locations. If installDir does not exist yet, the
        first of these that does is moved there whole, keeping client.keys
        and the agent state, so the agent does not re-enroll.
      '';
    };

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./phoenix-agent.nix { };
      defaultText = lib.literalExpression "phoenix.packages.\${system}.phoenix-agent";
      description = "Agent tree copied into installDir when its version differs.";
    };

    caFile = lib.mkOption {
      type = lib.types.path;
      default = ./phoenix-agent-ca.pem;
      description = ''
        CA the manager's :1517 certificate must chain to, installed as
        etc/phoenix-ca.pem. Defaults to the Phoenix Agent CA.
      '';
    };

    verificationMode = lib.mkOption {
      type = lib.types.enum [ "none" "certificate" "full" "system" ];
      default = "certificate";
      description = ''
        <ssl><verification_mode>: "certificate" checks the chain against
        caFile, "full" also checks the hostname, "system" uses the OS trust
        store instead of caFile, "none" disables verification.
      '';
    };

    enrollmentPasswordFile = lib.mkOption {
      type = lib.types.str;
      default = "/etc/wazuh-agent/authd.pass";
      description = "Root-only file with the manager's enrollment password.";
    };

    scaInterval = lib.mkOption {
      type = lib.types.str;
      default = "12h";
      description = "How often the SCA (CIS) policy scan runs.";
    };

    scaSourceId = lib.mkOption {
      type = lib.types.str;
      default = "sca_distro_independent_linux";
      description = ''
        Policy id of the stock CIS policy the NixOS one is derived from. The
        source file is found by this id, not by filename, so an agent upgrade
        that renames the file cannot silently skip the filtering.
      '';
    };

    scaSourceFile = lib.mkOption {
      type = lib.types.str;
      default = "${cfg.scaSourceId}.yml";
      defaultText = lib.literalExpression ''"''${scaSourceId}.yml"'';
      description = ''
        Filename of the stock policy, used only to disable it in ossec.conf.
        If it is wrong the preStart logs a WARNING with the real name and both
        policies run; grep the journal for "sca-policy:".
      '';
    };

    scaPolicyFile = lib.mkOption {
      type = lib.types.str;
      default = "nixos.yml";
      description = ''
        Filename of the generated policy, written to ruleset/sca. Not
        etc/shared: Wazuh 5.0 replaces that with the manager's group files on
        connect, deleting the policy.
      '';
    };

    scaPolicyId = lib.mkOption {
      type = lib.types.str;
      default = "sca_nixos";
      description = "Policy id of the generated NixOS policy. Must be unique.";
    };

    scaPolicyName = lib.mkOption {
      type = lib.types.str;
      default = "CIS Distribution Independent Linux Benchmark v2.0.0 (NixOS-adapted)";
      description = "Display name of the generated policy, as shown in the dashboard.";
    };

    scaNotApplicableChecks = lib.mkOption {
      type = lib.types.listOf lib.types.int;
      default = [ ];
      example = [ 36011 ];
      description = ''
        SCA check ids that cannot pass on this host. They stay in the
        generated policy, so the check count matches the original, but report
        "Not applicable" instead of "Failed". Unknown ids only warn.
      '';
    };

    extraConfig = lib.mkOption {
      type = lib.types.lines;
      default = "";
      description = "Extra XML inserted before </ossec_config>.";
    };
  };

  config = lib.mkIf cfg.enable {
    # The daemons switch to user and group `wazuh` by name. Declared here so
    # the account is a nologin system user with no sudo, rather than the
    # hand-made login account it used to be.
    users.groups.wazuh = { };
    users.users.wazuh = {
      isSystemUser = true;
      group = "wazuh";
      home = dir;
      createHome = false;
      shell = "${pkgs.shadow}/bin/nologin";
      description = "Wazuh agent service account";
    };

    systemd.services.wazuh-agent = {
      description = "Phoenix SIEM agent (Wazuh)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      environment.LD_LIBRARY_PATH = "${libsystemdDir}/lib";

      # wazuh-control needs awk to build its daemon list; without it, it
      # starts nothing and still prints "Completed.".
      path = with pkgs; [ coreutils gnused gnugrep gawk procps nettools util-linux ];

      preStart = ''
        # Move an agent tree from an earlier location into installDir (once).
        if [ ! -e ${dir} ]; then
          for old in ${lib.escapeShellArgs cfg.legacyInstallDirs}; do
            if [ -d "$old" ] && [ "$old" != ${dir} ]; then
              [ -x "$old/bin/wazuh-control" ] && "$old/bin/wazuh-control" stop || true
              echo "wazuh-agent: moving $old to ${dir}"
              mkdir -p "$(dirname ${dir})"
              mv "$old" ${dir}
              break
            fi
          done
        fi

        # Wazuh's own control script leaves orphaned daemons and stale pid files
        # behind after an unclean stop (e.g. a `nixos-rebuild switch` that
        # restarts the unit). The next `start` then finds a leftover wazuh-execd,
        # never completes its fork, and systemd kills it on timeout. Force a
        # clean slate before each start so the unit self-heals.
        if [ -x ${dir}/bin/wazuh-control ]; then
          ${dir}/bin/wazuh-control stop || true
        fi
        # Exact comm match, so this script (whose cmdline contains "wazuh") is
        # never a target.
        for d in wazuh-execd wazuh-agentd wazuh-syscheckd wazuh-modulesd wazuh-logcollec wazuh-monitord; do
          ${pkgs.procps}/bin/pkill -9 -x "$d" || true
        done
        rm -f ${dir}/var/run/*.pid ${dir}/var/run/*.start 2>/dev/null || true

        # Install or upgrade the tree. The old one is kept whole as a backup
        # rather than merged into, so no stale 4.x file lingers.
        if ! ${pkgs.diffutils}/bin/cmp -s ${cfg.package}/VERSION.json ${dir}/VERSION.json; then
          echo "wazuh-agent: installing ${cfg.package.name} into ${dir}"
          if [ -n "$(ls -A ${dir} 2>/dev/null)" ]; then
            mv ${dir} ${dir}.bak-$(date +%Y%m%d-%H%M%S)
          fi
          mkdir -p ${dir}
          cp -a ${cfg.package}/. ${dir}/
          chmod -R u+w ${dir}
          touch ${dir}/logs/active-responses.log
        fi
        # No /etc/localtime when time.timeZone is unset: the agent then uses UTC.
        if [ -e /etc/localtime ]; then
          cp -L /etc/localtime ${dir}/etc/localtime
        else
          cp ${pkgs.tzdata}/share/zoneinfo/UTC ${dir}/etc/localtime
        fi

        # The agent loads every policy in ruleset/sca, so keep it an exact copy
        # of the package's (the generic CIS policy only), even when
        # VERSION.json is unchanged.
        rm -rf ${dir}/ruleset/sca
        cp -r ${cfg.package}/ruleset/sca ${dir}/ruleset/sca
        chown -R root:wazuh ${dir}/ruleset/sca
        chmod -R u=rwX,g=rX,o= ${dir}/ruleset/sca

        # Derive the NixOS policy from the stock CIS policy the agent ships,
        # rewriting scaNotApplicableChecks to report "Not applicable".
        ${pkgs.python3}/bin/python3 ${./sca-policy-filter.py} \
          ${dir}/ruleset/sca \
          ${dir}/ruleset/sca/${cfg.scaPolicyFile} \
          ${cfg.scaSourceId} \
          ${cfg.scaPolicyId} \
          ${lib.escapeShellArg cfg.scaPolicyName} \
          ${cfg.scaSourceFile} \
          ${lib.concatMapStringsSep " " toString cfg.scaNotApplicableChecks}
        chown root:wazuh ${dir}/ruleset/sca/${cfg.scaPolicyFile}
        chmod 0640 ${dir}/ruleset/sca/${cfg.scaPolicyFile}

        install -o root -g wazuh -m 0640 ${ossecConf} ${dir}/etc/ossec.conf
        install -o root -g wazuh -m 0640 ${cfg.caFile} ${dir}/etc/phoenix-ca.pem

        # client.keys only works with the manager that issued it.
        MARK=${dir}/etc/.nixos-manager
        if [ "$(cat "$MARK" 2>/dev/null)" != ${lib.escapeShellArg cfg.managerIP} ]; then
          echo "wazuh-agent: manager is now ${cfg.managerIP}, clearing client.keys"
          : > ${dir}/etc/client.keys
          echo ${lib.escapeShellArg cfg.managerIP} > "$MARK"
        fi

        if [ -r ${cfg.enrollmentPasswordFile} ]; then
          install -o root -g wazuh -m 0640 ${cfg.enrollmentPasswordFile} ${dir}/etc/authd.pass
        else
          echo "wazuh-agent: WARNING: ${cfg.enrollmentPasswordFile} missing, enrollment will fail"
        fi

        # The agent runs as user wazuh and writes across its tree.
        chown -R wazuh:wazuh ${dir}
        chown root:wazuh ${dir}/etc/ossec.conf ${dir}/etc/authd.pass ${dir}/etc/phoenix-ca.pem 2>/dev/null || true
        chmod 0750 ${dir}
      '';

      serviceConfig = {
        Type = "forking";
        ExecStart = "${dir}/bin/wazuh-control start";
        ExecStop = "${dir}/bin/wazuh-control stop";
        ExecReload = "${dir}/bin/wazuh-control reload";
        # wazuh-control forks the daemons and exits; keep them alive with it.
        KillMode = "process";
        RemainAfterExit = true;
        Restart = "on-failure";
        RestartSec = 10;
        TimeoutStartSec = "5min";
        User = "root";
      };
    };
  };
}
