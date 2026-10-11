#!/usr/bin/env bash

# Description: This script builds the Linux application via PyInstaller and packages it into a Debian (.deb) package.
# Usage: ./scripts/build/build-deb.sh

set -e
set -x

# Navigate to project root
cd "$(dirname "$0")/../.."

# Ensure we have a virtual environment active or use the one in the project
if [ -z "$VIRTUAL_ENV" ]; then
	if [ -d ".venv" ]; then
		echo "Activating virtual environment (.venv)..."
		source .venv/bin/activate
	else
		echo "Error: Virtual environment (.venv) not found. Please run ./scripts/install.sh first."
		exit 1
	fi
fi

# Ensure PyInstaller is installed
if ! command -v pyinstaller >/dev/null 2>&1; then
	echo "Error: PyInstaller not found in the virtual environment. Installing requirements..."
	pip install -r scripts/requirements/requirements-linux.txt
fi

# Extract version from packaging/Resistine.spec
VERSION=$(
	python3 - <<'EOF'
import re
with open('packaging/Resistine.spec', 'r') as f:
    match = re.search(r"VERSION\s*=\s*['\"]([^'\"]+)['\"]", f.read())
    if match:
        print(match.group(1))
    else:
        print("0.0.0")
EOF
)
echo "Building Phoenix version: ${VERSION}"

# Run PyInstaller build
echo "Running PyInstaller..."
pyinstaller --clean -y packaging/Resistine.spec

# Verify build output
if [ ! -d "dist/Resistine" ]; then
	echo "Error: PyInstaller build failed. dist/Resistine directory not found."
	exit 1
fi

# Prepare Debian staging directory
STAGING_DIR="dist/deb_staging"
echo "Preparing staging directory at ${STAGING_DIR}..."
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR/DEBIAN"
mkdir -p "$STAGING_DIR/opt/phoenix"
mkdir -p "$STAGING_DIR/usr/bin"
mkdir -p "$STAGING_DIR/usr/share/applications"
mkdir -p "$STAGING_DIR/usr/share/pixmaps"

# Copy PyInstaller files
echo "Copying application files..."
cp -r dist/Resistine/* "$STAGING_DIR/opt/phoenix/"

# Create launcher script
echo "Creating launcher script..."
cat <<'EOF' >"$STAGING_DIR/usr/bin/phoenix"
#!/bin/sh
exec /opt/phoenix/Resistine "$@"
EOF
chmod 755 "$STAGING_DIR/usr/bin/phoenix"

# Copy desktop and icon files
echo "Copying desktop entry and icons..."
cp packaging/linux/phoenix.desktop "$STAGING_DIR/usr/share/applications/"
cp resources/icons/app_icon.png "$STAGING_DIR/usr/share/pixmaps/phoenix.png"

# Process control file
echo "Generating DEBIAN/control file..."
sed "s/\${VERSION}/${VERSION}/g" packaging/linux/control.template >"$STAGING_DIR/DEBIAN/control"

# Copy post-installation and post-removal scripts
echo "Copying package maintenance scripts..."
cp packaging/linux/postinst "$STAGING_DIR/DEBIAN/postinst"
cp packaging/linux/postrm "$STAGING_DIR/DEBIAN/postrm"
chmod 755 "$STAGING_DIR/DEBIAN/postinst"
chmod 755 "$STAGING_DIR/DEBIAN/postrm"

# Build Debian package
DEB_FILE="dist/phoenix_${VERSION}_amd64.deb"
echo "Building Debian package: ${DEB_FILE}..."
dpkg-deb --root-owner-group --build "$STAGING_DIR" "$DEB_FILE"

# Clean up staging directory
echo "Cleaning up staging files..."
rm -rf "$STAGING_DIR"

echo "Success! Built Debian package at: ${DEB_FILE}"
ls -lh "${DEB_FILE}"
