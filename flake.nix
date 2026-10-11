{
  description = "Phoenix Desktop — PyQt6 security endpoint (VPN / antivirus / SIEM) manager";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  # Linux only: the macOS and Windows builds go through PyInstaller
  # (packaging/Resistine.spec), and the runtime deps below (secretstorage,
  # jeepney, wireguard-tools, libnotify) are Linux-specific.
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" ] (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        inherit (pkgs) lib;

        # Python 3.13 is the project target (see CLAUDE.md and .github/workflows/ci.yml).
        #
        # Chat over Matrix (plugins/chat/matrix_transport.py) needs matrix-nio
        # >= 0.26 with E2EE, whose crypto backend is vodozemac. nixpkgs only has
        # matrix-nio 0.25 (E2EE via python-olm/libolm, which nixpkgs marks
        # insecure) and no vodozemac binding, so both are provided here.
        python = pkgs.python313.override {
          self = python;
          packageOverrides = pyfinal: pyprev: {
            vodozemac = pyfinal.buildPythonPackage rec {
              pname = "vodozemac";
              version = "0.10.0";
              pyproject = true;
              src = pyfinal.fetchPypi {
                inherit pname version;
                hash = "sha256-lgLtuHq30W57Sq1aCHRz2PtrPumQQ/mq8PVLt4lw3ek=";
              };
              cargoDeps = pkgs.rustPlatform.fetchCargoVendor {
                inherit pname version src;
                hash = "sha256-owvBFMoem6hn4dC9pR/DVqZoHFl7oIRBBodmAgWmDxU=";
              };
              nativeBuildInputs = with pkgs.rustPlatform; [ cargoSetupHook maturinBuildHook ];
              pythonImportsCheck = [ "vodozemac" ];
              meta.license = lib.licenses.asl20;
            };
            matrix-nio = pyprev.matrix-nio.overridePythonAttrs (old: rec {
              version = "0.26.0";
              src = pyfinal.fetchPypi {
                pname = "matrix_nio";
                inherit version;
                hash = "sha256-av96odnm5TUd+Pl59LZHo7NH9jXjBrJuJoL9O1nY5qg=";
              };
              build-system = [ pyfinal.setuptools ];
              patches = [ ];
              postPatch = "";
              optional-dependencies = old.optional-dependencies // {
                e2e = with pyfinal; [ atomicwrites cachetools peewee vodozemac ];
              };
              # The PyPI sdist ships no test suite.
              doCheck = false;
              pythonImportsCheck = [ "nio" "nio.crypto" ];
            });
          };
        };

        # Runtime Python deps. Mirrors scripts/requirements/requirements-linux.txt,
        # narrowed to what is actually imported plus the hiddenimports listed in
        # packaging/Resistine.spec. Omitted on purpose:
        #   pyinstaller  — build-only, the Nix build doesn't freeze the app
        #   pyuac        — Windows privilege elevation
        #   python-wireguard, tee, elevate, distro, darkdetect, html2text
        #                — in requirements-linux.txt but never imported
        pythonDeps = ps: with ps; [
          pyqt6
          cryptography
          keyring
          secretstorage # keyring.backends.SecretService on Linux
          jeepney
          loguru
          markdown
          requests
          httpx
          openai
          pillow
          certifi
          urllib3
          idna
          opentelemetry-api
          opentelemetry-sdk
          opentelemetry-exporter-otlp-proto-http
          # Chat over Matrix (E2EE); see the python override above.
          matrix-nio
        ] ++ matrix-nio.optional-dependencies.e2e;

        pythonEnv = python.withPackages pythonDeps;

        # Qt modules the app touches: QtWidgets/QtCore/QtGui (qtbase) and
        # QtSvg (gui/app_window.py uses QSvgRenderer). qtwayland for native
        # Wayland sessions.
        qtDeps = with pkgs.qt6; [ qtbase qtsvg qtwayland ];

        # External binaries the app shells out to on Linux:
        #   wg / wg-quick        — plugins/vpn
        #   clamscan / freshclam — plugins/antivirus
        #   notify-send          — utils/notifications
        #   ip                   — VPN interface checks
        # systemctl, resolvectl, pkexec and sudo are deliberately NOT included:
        # those must resolve to the running system (pkexec only works via its
        # setuid wrapper), which is why PATH is extended with --suffix below.
        runtimeBins = with pkgs; [ wireguard-tools clamav libnotify iproute2 ];

        # Keep in sync with VERSION in packaging/Resistine.spec — which is also
        # what utils/updates/version.py parses when running from source.
        version = "2026.07.20-rc";
      in
      {
        packages = rec {
          default = phoenix;
          # Pre-rebrand attribute name, kept so existing system configs build.
          resistine = phoenix;

          # The exact ClamAV the wrapper below puts on the app's PATH, exported
          # so a system config can install *this* one rather than whatever its
          # own nixpkgs carries. That matters: the launcher extends PATH with
          # --suffix, so a clamav in the system profile wins, and older builds
          # (e.g. 1.4.3 in nixpkgs 25.11) ship no share/clamav/certs/clamav.crt
          # — which is exactly what plugins/antivirus/clamav_platform_linux.py
          # needs to find for freshclam to verify CVD signatures. Installing
          # this attribute keeps both paths on one version that has the cert.
          inherit (pkgs) clamav;

          phoenix = pkgs.stdenv.mkDerivation {
            pname = "phoenix";
            inherit version;

            src = ./.;

            nativeBuildInputs = [
              pkgs.makeWrapper
              pkgs.qt6.wrapQtAppsHook
            ];

            buildInputs = qtDeps;

            dontBuild = true;

            # Mirrors the CI syntax gate (.github/workflows/ci.yml).
            doCheck = true;
            checkPhase = ''
              runHook preCheck
              ${pythonEnv}/bin/python -m compileall -q main.py gui utils plugins services

              # compileall only *parses*. It cannot catch a dependency that
              # resolves to the wrong version — e.g. an opentelemetry-sdk
              # without ReadableLogRecord, which builds fine here and then
              # kills the app on the first import at startup. So actually
              # import the modules that pull in the third-party surface.
              # All of these are side-effect-free at module level (no file
              # writes), which is why this is safe in the build sandbox.
              QT_QPA_PLATFORM=offscreen ${pythonEnv}/bin/python - <<'EOF'
              import utils.logger        # loguru + opentelemetry (api/sdk/otlp-http)
              import utils.settings      # cryptography + keyring
              import utils.functions
              import plugins.wazuh.config
              import plugins.antivirus.clamav_common
              from PyQt6.QtSvg import QSvgRenderer          # noqa: F401
              from PyQt6.QtWidgets import QApplication      # noqa: F401
              import httpx, markdown, openai, PIL, requests  # noqa: F401
              from nio.crypto import ENCRYPTION_ENABLED       # Matrix chat
              assert ENCRYPTION_ENABLED, "matrix-nio built without E2EE"
              print("import check ok")
              EOF
              runHook postCheck
            '';

            installPhase = ''
              runHook preInstall

              mkdir -p $out/bin $out/share/phoenix
              cp -r main.py gui plugins utils resources docs $out/share/phoenix/

              # utils/updates/version.py parses VERSION out of the PyInstaller
              # spec when not running frozen, so the spec has to ship too.
              install -Dm644 packaging/Resistine.spec \
                $out/share/phoenix/packaging/Resistine.spec

              install -Dm644 LICENSE.md $out/share/phoenix/LICENSE.md
              install -Dm644 LICENSE-3rd-Party.md $out/share/phoenix/LICENSE-3rd-Party.md

              install -Dm644 packaging/linux/phoenix.desktop \
                $out/share/applications/phoenix.desktop
              install -Dm644 resources/icons/app_icon.png \
                $out/share/icons/hicolor/256x256/apps/phoenix.png

              runHook postInstall
            '';

            # The launcher is a shell wrapper, and wrapQtAppsHook only wraps ELF
            # binaries — so opt out and call makeQtWrapper ourselves. This runs
            # in postFixup so qtOwnPathsHook has already put $out/share on
            # XDG_DATA_DIRS (that is what makes the shipped .desktop file and
            # icon visible to the desktop environment).
            dontWrapQtApps = true;
            postFixup = ''
              makeQtWrapper ${pythonEnv}/bin/python $out/bin/phoenix \
                --add-flags "$out/share/phoenix/main.py" \
                --suffix PATH : ${lib.makeBinPath runtimeBins}
            '';

            meta = {
              description = "Phoenix security desktop: VPN (WireGuard), antivirus (ClamAV), SIEM (Wazuh) and AI chat";
              homepage = "https://github.com/Resistine/Resistine-Desktop";
              license = lib.licenses.gpl2Plus;
              platforms = lib.platforms.linux;
              mainProgram = "phoenix";
            };
          };
        };

        apps.default = {
          type = "app";
          program = "${self.packages.${system}.phoenix}/bin/phoenix";
        };

        checks.default = self.packages.${system}.phoenix;

        devShells = {
          # Default shell: every Python dep comes from nixpkgs, so `python
          # main.py` works immediately with no venv and no pip.
          default = pkgs.mkShell {
            packages = [
              pythonEnv
              pkgs.uv
            ] ++ runtimeBins;

            buildInputs = qtDeps;

            env.QT_PLUGIN_PATH = lib.makeSearchPath pkgs.qt6.qtbase.qtPluginPrefix qtDeps;

            shellHook = ''
              echo "Phoenix dev shell (PyQt6, Python ${python.pythonVersion}, deps from nixpkgs)"
              echo
              echo "  python main.py       run the app"
              echo "  python main.py -d    debug mode + runtime inspector"
              echo
              echo "For the pip/uv .venv workflow (and pytest): nix develop .#uv"
            '';
          };

          # Opt-in shell for the documented pip workflow (.venv +
          # scripts/requirements/requirements-linux.txt). PyQt6 comes from a
          # manylinux wheel here, so its bundled Qt libraries need the graphical
          # stack on LD_LIBRARY_PATH.
          uv = pkgs.mkShell {
            packages = [ python pkgs.uv pkgs.gcc ] ++ runtimeBins;

            env.LD_LIBRARY_PATH = lib.makeLibraryPath (with pkgs; [
              stdenv.cc.cc.lib
              zlib
              glib
              dbus
              fontconfig
              freetype
              libGL
              libglvnd
              libdrm
              libxkbcommon
              wayland
              # Non-obvious DT_NEEDED entries of the wheel's bundled Qt libs.
              # Found with: ldd .venv/.../PyQt6/Qt6/lib/libQt6*.so.6 | grep 'not found'
              # Without these, `import PyQt6.QtWidgets` dies before Qt can even
              # pick a platform plugin.
              brotli # libbrotlidec.so.1  (QtNetwork)
              krb5 # libgssapi_krb5.so.2 (QtNetwork)
              openssl # libssl / libcrypto  (QtNetwork TLS)
              pcsclite # libpcsclite.so.1   (QtNetwork smartcard)
              libpulseaudio # libpulse.so.0      (QtMultimedia)
              zstd # libzstd.so.1       (QtCore)
              # XWayland / X11 fallback (QT_QPA_PLATFORM=xcb). The xorg.* attrs
              # are deprecated aliases in current nixpkgs — use the flat names.
              libx11
              libxext
              libxi
              libxrender
              libxcb
              xcb-util-cursor # libxcb-cursor0 in the .deb; qt6 xcb needs it
              libxcb-util
              libxcb-image
              libxcb-keysyms
              libxcb-render-util
              libxcb-wm
            ]);

            shellHook = ''
              if [ ! -d .venv ]; then
                echo "Creating .venv and installing requirements-linux.txt…"
                uv venv --python ${python}/bin/python
                . .venv/bin/activate
                uv pip install -r scripts/requirements/requirements-linux.txt
                uv pip install -r scripts/requirements/requirements-test.txt
              else
                . .venv/bin/activate
              fi

              echo "Phoenix dev shell (.venv / uv)"
              echo "  python main.py       run the app"
              echo "  ./run_tests.sh       tests"
            '';
          };
        };
      });
}
