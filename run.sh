#!/usr/bin/env bash

# Description: This script updates all dependencies and runs the Phoenix application.
# If the .venv folder does not exist, it will run the install.sh script first.
# Usage: ./run.sh

# Author: P3 and the Resistine Team
# Copyright (c) Resistine 2025
# Licensed under the GNU General Public License v2 or later

# Print commands and their arguments as they are executed
set -x

# Exit immediately if a command exits with a non-zero status
set -e

# Navigate to project root (same directory as this script)
cd "$(dirname "$0")"

# Check if .venv exists, if not run install.sh
if [ ! -d ".venv" ]; then
	echo ".venv folder not found. Running install.sh first..."
	./scripts/install.sh
	exit 0
fi

# Activate virtual environment
if [ -f ".venv/bin/activate" ]; then
	source .venv/bin/activate
elif [ -f ".venv/Scripts/activate" ]; then
	source .venv/Scripts/activate
else
	echo "Error: Cannot find activation script. Please run install.sh."
	exit 1
fi

# Detect the operating system
OS="$(uname -s)"
case "$OS" in
Linux*)
	# Install/update requirements if needed
	python3 -m pip install -U -q -r scripts/requirements/requirements-linux.txt
	;;

# MACOS
Darwin*)
	# Make brewed Tcl/Tk visible (for Tkinter)
	if command -v brew >/dev/null; then
		BREW_PREFIX=$(brew --prefix)
		export PATH="$BREW_PREFIX/opt/tcl-tk/bin:$PATH"
		export LDFLAGS="-L$BREW_PREFIX/opt/tcl-tk/lib"
		export CPPFLAGS="-I$BREW_PREFIX/opt/tcl-tk/include"
		
		# Safer alternative to DYLD_LIBRARY_PATH that avoids Bus Error 10 
		# while still allowing Homebrew libraries (like Cairo) to be found.
		export DYLD_FALLBACK_LIBRARY_PATH="$BREW_PREFIX/lib:$DYLD_FALLBACK_LIBRARY_PATH"
	fi

	# Install/update requirements if needed
	export MACOSX_DEPLOYMENT_TARGET=13.0  # Ensure compiled extensions target macOS 13+ (Ventura)
	python3 -m pip install -U -q -r scripts/requirements/requirements-mac.txt

	# Dev escape hatch (macOS only): assume the VPN is up. When you're
	# running this script alongside an installed .pkg whose NetworkExtension
	# already holds the tunnel up, this process's traffic routes through the
	# system tunnel even though *this* instance's internal VPN state stays
	# "Stopped". Setting this var makes plugins.vpn.main.is_vpn_connected()
	# return True so VPN-gated features (the chat access gate, etc.)
	# actually run. If the .pkg tunnel ISN'T up the
	# downstream network calls will just fail — the obvious and expected
	# failure mode in dev. Linux/Windows have different VPN backends, so
	# this export is intentionally scoped to the Darwin arm only.
	export RESISTINE_DEV_VPN_CONNECTED=1
	;;

# Windows (Git Bash, Cygwin, MSYS2)
CYGWIN* | MINGW* | MSYS*)
	# Install/update requirements if needed
	python -m pip install -U -q -r scripts/requirements/requirements-windows.txt
	;;

# Unsupported OS
*)
	echo "Unsupported OS: $OS"
	exit 1
	;;
esac

# Chat debugging: make the OpenAI-compatible client log the raw HTTP
# request/response for every chat turn — you'll see whether stream:true
# is sent, each streamed chunk, and exactly when the server closes the
# stream (e.g. after a background run_security_diagnostic kickoff).
# Override with `OPENAI_LOG=info ./run.sh` to quiet it down.
export OPENAI_LOG="${OPENAI_LOG:-debug}"

# Run the application
python main.py "$@"

# Deactivate the virtual environment
deactivate
