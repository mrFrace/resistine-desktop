#!/usr/bin/env bash

# Description: This script installs the dependencies and runs the application for Linux, MacOS, and Windows.
# It creates a virtual environment in the libraries/venv folder and installs the required Python packages.
# If the libraries/venv folder already exists, it prompts the user to delete it before proceeding.
# Usage: ./install.sh

# Author: P3, Peres J. and the Resistine Team
# Copyright (c) Resistine 2025
# Licensed under the GNU General Public License v2 or later

# Print commands and their arguments as they are executed
set -x

# Exit immediately if a command exits with a non-zero status
set -e

# Check if the venv folder already exists in the libraries folder
if [ -d ".venv" ]; then
	rm -rf .venv

# Detect the operating system
OS="$(uname -s)"
case "$OS" in
Linux*)
	if [ -r /etc/os-release ]; then
		. /etc/os-release
	else
		echo "Cannot determine Linux distribution."
		exit 1
	fi

	distro_tags="$(printf '%s %s' "${ID}" "${ID_LIKE}")"
	case "$distro_tags" in
	*debian* | *ubuntu*)
		# Check if packages are already installed
		PACKAGES_TO_INSTALL=""
		for pkg in python3 python3-venv python3-pip python3-tk wireguard-tools; do
			if ! dpkg -s "$pkg" &>/dev/null; then
				PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL $pkg"
			fi
		done

		if [ -n "$PACKAGES_TO_INSTALL" ]; then
			echo "Installing missing packages:$PACKAGES_TO_INSTALL"
			sudo apt update
			sudo apt install -y $PACKAGES_TO_INSTALL
		else
			echo "All required packages are already installed."
		fi
		;;
	*rhel* | *fedora* | *centos*)
		pkg_mgr="$(command -v dnf || command -v yum || true)"
		if [ -z "$pkg_mgr" ]; then
			echo "dnf/yum not found."
			exit 1
		fi

		# Check if packages are already installed
		PACKAGES_TO_INSTALL=""
		for pkg in python3 python3-pip python3-tkinter wireguard-tools; do
			if ! rpm -q "$pkg" &>/dev/null; then
				PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL $pkg"
			fi
		done

		if [ -n "$PACKAGES_TO_INSTALL" ]; then
			echo "Installing missing packages:$PACKAGES_TO_INSTALL"
			sudo "$pkg_mgr" install -y $PACKAGES_TO_INSTALL
		else
			echo "All required packages are already installed."
		fi
		;;
	*suse*)
		# Check if packages are already installed
		PACKAGES_TO_INSTALL=""
		for pkg in python3 python3-pip python3-tk wireguard-tools; do
			if ! rpm -q "$pkg" &>/dev/null; then
				PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL $pkg"
			fi
		done

		if [ -n "$PACKAGES_TO_INSTALL" ]; then
			echo "Installing missing packages:$PACKAGES_TO_INSTALL"
			sudo zypper refresh
			sudo zypper install -y $PACKAGES_TO_INSTALL
		else
			echo "All required packages are already installed."
		fi
		;;
	*)
		# TODO: This should be improved to support more distros
		echo "Unsupported Linux distribution: ${ID:-unknown}"
		exit 1
		;;
	esac

	# Create venv as regular user (not with sudo)
	python3 -m venv .venv
	;;

# MACOS
Darwin*)
	# TODO: Jackie

	# macOS (Homebrew)
	if ! command -v brew >/dev/null; then
		echo "Homebrew not found. Install from https://brew.sh"
		exit 1
	fi

	PACKAGES_TO_INSTALL=""

	# Check for Python
	if command -v python3 >/dev/null; then
		echo "Python3 is already installed."
	else
		PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL python"
	fi

	# Check for WireGuard
	if command -v wg >/dev/null; then
		echo "WireGuard tools are already installed."
	else
		PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL wireguard-tools"
	fi

	# Check for tcl-tk (via tkinter import)
	if command -v python3 >/dev/null && python3 -c "import tkinter" >/dev/null 2>&1; then
		echo "tcl-tk (tkinter) is already installed."
	else
		if command -v python3 >/dev/null; then
			PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
			PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL python-tk@$PY_VER"
		else
			PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL tcl-tk"
		fi
	fi

	if [ -n "$PACKAGES_TO_INSTALL" ]; then
		echo "Installing missing packages:$PACKAGES_TO_INSTALL"
		brew update
		brew install $PACKAGES_TO_INSTALL
	else
		echo "All required packages are already installed."
	fi

	# Create venv using the available python3
	python3 -m venv .venv
	;;

# Windows (Git Bash, Cygwin, MSYS2)
CYGWIN* | MINGW* | MSYS*)
	# TODO: This should be run instead:
	# build_win_simple.py in the branch Test-Windows-Version

	if ! command -v python >/dev/null; then
		echo "Python not found. Checking for winget..."
		if ! command -v winget >/dev/null; then
			echo "winget not found. Please ensure App Installer is installed from Microsoft Store."
			exit 1
		fi
		echo "Installing Python via winget..."
		winget install -e --id Python.Python.3.14 --accept-package-agreements --accept-source-agreements
	else
		echo "Python is already installed."
	fi

	if [ ! -d ".venv" ]; then
		python -m venv .venv
	fi
	;;

# Unsupported OS
*)
	# TODO: This should be improved to support more OS
	echo "Unsupported OS: $OS"
	exit 1
	;;
esac

# Installation complete, now run the application
echo ""
echo "Installation complete! Starting the application..."
echo ""
./run.sh
