# Phoenix on NixOS: the app plus the system services it drives.
#
#   imports = [ phoenix.nixosModules.default ];
#   programs.phoenix.enable = true;
#
# On NixOS the app can't install packages, write /etc or enable units, so
# everything it would set up at runtime on other distros is declared here:
#
#   antivirus  ClamAV clamd + freshclam (the app starts and scans through them)
#   siem       the Phoenix SIEM agent (Wazuh 5.0) under /opt/phoenix-agent
#   vpn        what wg-quick needs when the app runs it through pkexec
#
# `self` is the Phoenix flake, so the defaults are the packages it builds.
self:
{
  config,
  options,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.programs.phoenix;
  system = pkgs.stdenv.hostPlatform.system;
  phoenixPkgs = self.packages.${system};

  # The nix-ld flake (github:Mic92/nix-ld) has its own programs.nix-ld.dev
  # switch; turning on the nixpkgs one as well would install two loaders.
  nixLdDev = lib.attrByPath [ "programs" "nix-ld" "dev" "enable" ] false config;
in
{
  imports = [
    ./wazuh-agent.nix

    # Pre-rebrand option names, so existing configs keep evaluating.
    (lib.mkRenamedOptionModule [ "programs" "resistine-desktop" "enable" ] [ "programs" "phoenix" "enable" ])
    (lib.mkRenamedOptionModule [ "programs" "resistine-desktop" "package" ] [ "programs" "phoenix" "package" ])
    (lib.mkRenamedOptionModule [ "programs" "resistine-desktop" "wazuhAgent" ] [ "programs" "phoenix" "siem" "enable" ])
    (lib.mkRenamedOptionModule [ "programs" "resistine-desktop" "clamav" ] [ "programs" "phoenix" "antivirus" "enable" ])
    (lib.mkRenamedOptionModule [ "programs" "resistine-desktop" "clamavPackage" ] [ "programs" "phoenix" "antivirus" "package" ])
  ];

  options.programs.phoenix = {
    enable = lib.mkEnableOption "Phoenix, the security desktop (VPN, antivirus, SIEM, AI chat)";

    package = lib.mkOption {
      type = lib.types.package;
      default = phoenixPkgs.phoenix;
      defaultText = lib.literalExpression "phoenix.packages.\${system}.phoenix";
      description = "The Phoenix package (bin/phoenix and its desktop entry).";
    };

    antivirus = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Run ClamAV for the Antivirus page: clamd (services.clamav.daemon)
          and the freshclam signature updater, both from antivirus.package.
          The app finds them by their unit names and starts them on demand.
        '';
      };

      package = lib.mkOption {
        type = lib.types.package;
        default = phoenixPkgs.clamav;
        defaultText = lib.literalExpression "phoenix.packages.\${system}.clamav";
        description = ''
          The ClamAV to run. Defaults to the one Phoenix is built against:
          some nixpkgs releases ship a ClamAV without
          share/clamav/certs/clamav.crt, which freshclam needs to verify
          signature databases.
        '';
      };

      realtime = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Also run clamonacc (services.clamav.clamonacc), which scans files
          as they are opened. Uses noticeably more CPU and memory.
        '';
      };
    };

    siem = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = pkgs.stdenv.hostPlatform.isx86_64;
        defaultText = lib.literalExpression "pkgs.stdenv.hostPlatform.isx86_64";
        description = ''
          Run the Phoenix SIEM agent (services.wazuh-agent), which the
          Endpoint page shows and the Dashboard reports on. The agent is an
          amd64 build, and its .deb has to be added to the nix store first
          (see nix/phoenix-agent.nix). Set the enrollment password with
          services.wazuh-agent.enrollmentPasswordFile.
        '';
      };
    };

    vpn = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Prepare the system for the Phoenix VPN: the wireguard kernel
          module, a firewall that lets full-tunnel traffic back in, and DNS
          through resolvconf or systemd-resolved. The app runs wg-quick
          through pkexec.
        '';
      };

      looseReversePath = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Set networking.firewall.checkReversePath to "loose". With the
          default strict check, the NixOS firewall drops the replies of a
          full-tunnel wg-quick VPN and the tunnel comes up but passes no
          traffic.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      environment.systemPackages = [ cfg.package ];
      # The app runs its root steps (wg-quick, systemctl start clamav-*,
      # agent commands) through pkexec, which needs polkit's setuid wrapper.
      security.polkit.enable = lib.mkDefault true;
    }

    # Newer nixpkgs only install the wrapper on request; older releases have
    # no such option and always install it.
    (lib.optionalAttrs (options.security.polkit ? enablePkexecWrapper) {
      security.polkit.enablePkexecWrapper = lib.mkDefault true;
    })

    (lib.mkIf cfg.antivirus.enable {
      environment.systemPackages = [ cfg.antivirus.package ];
      services.clamav = {
        package = lib.mkDefault cfg.antivirus.package;
        daemon.enable = lib.mkDefault true;
        updater.enable = lib.mkDefault true;
        clamonacc.enable = lib.mkDefault cfg.antivirus.realtime;
      };
    })

    (lib.mkIf cfg.siem.enable {
      services.wazuh-agent.enable = lib.mkDefault true;
      # The agent binaries are prebuilt and run through nix-ld.
      programs.nix-ld.enable = lib.mkIf (!nixLdDev) (lib.mkDefault true);
    })

    (lib.mkIf cfg.vpn.enable {
      boot.kernelModules = [ "wireguard" ];
      networking.firewall.checkReversePath = lib.mkIf cfg.vpn.looseReversePath (lib.mkDefault "loose");
    })

    {
      assertions = [
        {
          assertion = !cfg.siem.enable || config.services.wazuh-agent.enable;
          message = ''
            programs.phoenix.siem.enable is on but services.wazuh-agent.enable
            is forced off elsewhere. Set programs.phoenix.siem.enable = false
            to run Phoenix without the SIEM agent.
          '';
        }
        {
          assertion = !cfg.siem.enable || pkgs.stdenv.hostPlatform.isx86_64;
          message = "The Phoenix SIEM agent is only built for x86_64; set programs.phoenix.siem.enable = false.";
        }
        {
          assertion = !cfg.vpn.enable || config.networking.resolvconf.enable || config.services.resolved.enable;
          message = ''
            The Phoenix VPN sets DNS through resolvconf (wg-quick's DNS =).
            Enable networking.resolvconf or services.resolved, or set
            programs.phoenix.vpn.enable = false.
          '';
        }
      ];
    }
  ]);
}
