# NixOS VM test for nixosModules.default: boots a machine with
# programs.phoenix.enable and checks that the app and the services it drives
# are in place, and that the app starts.
#
#   nix build .#checks.x86_64-linux.nixos-module -L
#
# The SIEM agent is on, so the phoenix-agent .deb must be in the nix store
# (see nix/phoenix-agent.nix). The VM has no network: the agent cannot
# enroll and freshclam cannot download, which the test allows.
{ self, pkgs }:

pkgs.testers.runNixOSTest {
  name = "phoenix-nixos-module";

  nodes.machine = { ... }: {
    imports = [ self.nixosModules.default ];
    programs.phoenix.enable = true;

    users.users.alice = {
      isNormalUser = true;
      uid = 1000;
    };

    virtualisation.memorySize = 2048;
  };

  testScript = ''
    machine.wait_for_unit("multi-user.target")

    with subtest("app is installed"):
        machine.succeed("command -v phoenix")
        machine.succeed("test -f /run/current-system/sw/share/applications/phoenix.desktop")

    with subtest("antivirus units"):
        for unit in ["clamav-daemon.service", "clamav-freshclam.service"]:
            machine.succeed(f"systemctl cat {unit} >/dev/null")
        machine.succeed("command -v clamscan freshclam clamd")

    with subtest("SIEM agent is installed and runs without enrollment"):
        machine.succeed("systemctl cat wazuh-agent.service >/dev/null")
        # preStart copies the tree, then writes ossec.conf last-but-one.
        machine.wait_until_succeeds(
            "grep -q '<endpoint>dashboard.phoenix.exposed</endpoint>' /opt/phoenix-agent/etc/ossec.conf",
            timeout=180,
        )
        machine.succeed("test -x /opt/phoenix-agent/bin/wazuh-control")
        print(machine.execute("systemctl status wazuh-agent --no-pager -n 15")[1])
        machine.succeed("getent passwd wazuh")
        # The binaries are prebuilt; they only run through nix-ld.
        machine.succeed("/opt/phoenix-agent/bin/wazuh-agentd -V")

    with subtest("VPN prerequisites"):
        machine.succeed("lsmod | grep -q '^wireguard'")
        machine.succeed("test -u /run/wrappers/bin/pkexec")

    with subtest("app starts headless"):
        # Runs as a normal user; still running after 20 s means it got past
        # startup. Exit 124 is the timeout, anything else is a crash.
        rc, out = machine.execute(
            "su - alice -c 'QT_QPA_PLATFORM=offscreen timeout 20 phoenix' 2>&1"
        )
        print(out)
        assert rc == 124, f"phoenix exited with {rc}"
        assert "Traceback" not in out, "phoenix printed a traceback"
  '';
}
