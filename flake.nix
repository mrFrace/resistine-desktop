{
  description = "Resistine - Tkinter + Cairo (clean fix for tcl_findLibrary)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        # Plain python314 is built without Tk; the app needs tkinter.
        python = pkgs.python314.withPackages (ps: [ ps.tkinter ]);
        # Runtime deps for `nix run` (the dev shell installs them with uv).
        # Build-only and Windows-only requirements are left out.
        appPython = pkgs.python314.withPackages (ps: with ps; [
          tkinter
          customtkinter
          darkdetect
          pillow
          cairocffi
          cairosvg
          uharfbuzz
          blackrenderer
          httpx
          certifi
          openai
          pydantic
          requests
          keyring
          secretstorage
          jeepney
          cryptography
          loguru
          opentelemetry-api
          opentelemetry-sdk
          opentelemetry-exporter-otlp
          distro
          elevate
          html2text
          markdown
          python-dotenv
          tqdm
          decorator
          packaging
        ]);
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            python
            pkgs.uv
            pkgs.wireguard-tools
            pkgs.tcl
            pkgs.tk
            pkgs.cairo
            pkgs.pkg-config
          ];

          shellHook = ''
            echo "🚀 Resistine environment (clean Tkinter setup)"

            # Only set LD_LIBRARY_PATH — do NOT set TCL_LIBRARY / TK_LIBRARY
            export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.cairo ]}:$LD_LIBRARY_PATH"

            # Fresh venv
            if [ ! -d ".venv" ]; then
              echo "Creating fresh .venv..."
              rm -rf .venv
              uv venv --system-site-packages --python ${python}/bin/python
            fi

            source .venv/bin/activate

            echo "Installing dependencies from requirements-linux.txt..."
            uv pip install --upgrade pip
            uv pip install -r scripts/requirements/requirements-linux.txt --upgrade

            echo ""
            echo "✅ Environment ready!"
            echo "Test command (critical):"
            echo "   python -c \"import tkinter, customtkinter, cairocffi; root = tkinter.Tk(); root.destroy(); print('✅ Full Tkinter + customtkinter works!')\""
            echo ""
            echo "Run the app:"
            echo "   uv run main.py"
            echo ""
          '';
        };

        # Optional: for `nix run`
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "resistine";
          version = "0.1.0";

          src = ./.;

          nativeBuildInputs = [ pkgs.makeWrapper ];

          buildInputs = [
            appPython
            pkgs.wireguard-tools
            pkgs.tcl
            pkgs.tk
            pkgs.cairo
          ];

          dontBuild = true;

          installPhase = ''
            mkdir -p $out/bin $out/share/resistine
            cp -r . $out/share/resistine

            makeWrapper ${appPython}/bin/python $out/bin/resistine \
              --add-flags "$out/share/resistine/main.py" \
              --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.wireguard-tools ]} \
              --prefix LD_LIBRARY_PATH : ${pkgs.lib.makeLibraryPath [ pkgs.cairo ]}
          '';

          meta.mainProgram = "resistine";
        };
      });
}
