param(
    [switch]$SkipDependencyInstall,
    [switch]$SkipPyInstaller
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path (Split-Path (Split-Path -Parent $PSCommandPath) -Parent) -Parent
Set-Location $ProjectRoot

# Detect whether this machine is ARM64
$_rawArch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
$IsARM64  = $_rawArch -eq "ARM64"

function Get-AppVersion {
    $specPath = Join-Path $ProjectRoot "packaging\Resistine.spec"
    $match = Select-String -Path $specPath -Pattern "VERSION\s*=\s*'([^']+)'" | Select-Object -First 1
    if (-not $match) {
        throw "Could not find VERSION in Resistine.spec"
    }
    return $match.Matches[0].Groups[1].Value
}

function Convert-LicenseMdToTxt {
    <#
    .SYNOPSIS
    Generates LICENSE.txt at the repo root from LICENSE.md, stripping the
    bits of Markdown syntax that would render as visible noise in Inno
    Setup's license-acceptance dialog (which renders text verbatim).

    Inno Setup's LicenseFile= directive wants .txt or .rtf; .md works
    syntactically but shows the literal "#" / "##" / "---" characters
    where headers and rules should be. This converter:
      - Drops leading markdown header markers (# / ## / ### …)
      - Converts horizontal rules (---, ***, ___) into plain dividers
      - Keeps everything else verbatim — GPL text doesn't use any other
        markdown the GPL preamble might rely on
    Writes UTF-8 with Windows line endings (CRLF) since this is a Windows
    artifact consumed by ISCC.
    #>
    param(
        [Parameter(Mandatory)] [string]$SourceMd,
        [Parameter(Mandatory)] [string]$TargetTxt
    )

    if (-not (Test-Path $SourceMd)) {
        throw "Convert-LicenseMdToTxt: source not found: $SourceMd"
    }

    $divider = '=' * 60
    $raw     = Get-Content -Raw $SourceMd -Encoding UTF8
    $lines   = $raw -split "`r?`n"
    $out     = foreach ($line in $lines) {
        # Strip leading "#"/"##"/… (markdown headers) — keep the title text
        $stripped = $line -replace '^\s*#{1,6}\s+', ''
        # Replace markdown horizontal rules with a plain ASCII divider
        if ($stripped -match '^\s*(-{3,}|\*{3,}|_{3,})\s*$') {
            $stripped = $divider
        }
        $stripped
    }

    # Use CRLF for the on-disk file so Inno Setup / Windows Notepad render
    # it as a single logical document with proper line breaks.
    $out -join "`r`n" | Set-Content -Path $TargetTxt -Encoding UTF8 -NoNewline
    Write-Host "  Wrote $TargetTxt ($($out.Count) lines)"
}

function Resolve-InnoCompiler {
    $fromPath = Get-Command iscc.exe -ErrorAction SilentlyContinue
    if ($fromPath -and (Test-Path $fromPath.Path)) {
        return $fromPath.Path
    }

    $searchPaths = @(
        "C:\Program Files (x86)\Inno Setup 6\ISCC.exe",
        "C:\Program Files\Inno Setup 6\ISCC.exe"
    )
    foreach ($candidate in $searchPaths) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    throw "Inno Setup compiler (ISCC.exe) not found. Install Inno Setup 6 first, then rerun this script."
}

function Resolve-BasePython {
    $pythonCmd = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCmd) {
        return @{
            Exe  = $pythonCmd.Path
            Args = @()
            Name = "python"
        }
    }

    $pyCmd = Get-Command py -ErrorAction SilentlyContinue
    if ($pyCmd) {
        & $pyCmd.Path -3 -c "import sys" *> $null
        if ($LASTEXITCODE -eq 0) {
            return @{
                Exe  = $pyCmd.Path
                Args = @("-3")
                Name = "py -3"
            }
        }
    }

    throw "Python was not found. Install Python (or ensure 'py' launcher is available), then rerun the installer build script."
}

$venvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    $basePython = Resolve-BasePython
    Write-Host "Creating .venv for Windows build..."
    & $basePython.Exe @($basePython.Args + @("-m", "venv", ".venv"))
} else {
    Write-Host "Using existing virtual environment: $venvPython"
}

# Build ID (UTC minutes, see packaging/Resistine.spec), shared by PyInstaller
# (the app's BUILD file) and Inno Setup (installer name, displayed version).
if (-not $env:PHOENIX_BUILD) {
    $env:PHOENIX_BUILD = (Get-Date).ToUniversalTime().ToString("yyyyMMddHHmm")
}
$build = $env:PHOENIX_BUILD
Write-Host "Build ID: $build"

# $ErrorActionPreference doesn't cover native commands: a failed pip install
# (e.g. a wheel that needs a compiler) would otherwise still yield an installer.
function Invoke-VenvPython {
    & $venvPython @args
    if ($LASTEXITCODE -ne 0) {
        throw "python $($args -join ' ') failed with exit code $LASTEXITCODE."
    }
}

if (-not $SkipDependencyInstall) {
    Write-Host "Installing build/runtime dependencies into .venv..."
    Invoke-VenvPython -m pip install --upgrade pip
    Invoke-VenvPython -m pip install -r (Join-Path $ProjectRoot "scripts\requirements\requirements-windows.txt")
    Invoke-VenvPython -m pip install pyinstaller
}

if (-not $SkipPyInstaller) {
    Write-Host "Building Windows application bundle with PyInstaller..."
    Invoke-VenvPython -m PyInstaller (Join-Path $ProjectRoot "packaging\Resistine.spec") --clean --noconfirm
}

$sourceDir = Join-Path $ProjectRoot "dist\Phoenix"
if (-not (Test-Path (Join-Path $sourceDir "Phoenix.exe"))) {
    throw "Expected PyInstaller output not found at $sourceDir\Phoenix.exe"
}
Invoke-VenvPython (Join-Path $ProjectRoot "scripts\build\check_bundle.py") $sourceDir

# Copy installer helper files into distribution directory
Write-Host "Copying installer helper files..."
$installServiceSrc = Join-Path $ProjectRoot "scripts\install\install_service.bat"
$installServiceDst = Join-Path $sourceDir "install_service.bat"
if (Test-Path $installServiceSrc) {
    Copy-Item $installServiceSrc $installServiceDst -Force
} else {
    Write-Warning "install_service.bat not found at $installServiceSrc"
}

$vpnServiceSrc = Join-Path $ProjectRoot "plugins\vpn\wireguard\windows_vpn_service.py"
$vpnServiceDir = Join-Path $sourceDir "plugins\vpn\wireguard"
New-Item -ItemType Directory -Force -Path $vpnServiceDir | Out-Null
if (Test-Path $vpnServiceSrc) {
    Copy-Item $vpnServiceSrc (Join-Path $vpnServiceDir "windows_vpn_service.py") -Force
} else {
    Write-Warning "windows_vpn_service.py not found at $vpnServiceSrc"
}
# The service validates tunnel names with the shared validator; it runs as a
# standalone script under the system Python, so ship the module next to it.
$configValidationSrc = Join-Path $ProjectRoot "plugins\vpn\wireguard\config_validation.py"
if (Test-Path $configValidationSrc) {
    Copy-Item $configValidationSrc (Join-Path $vpnServiceDir "config_validation.py") -Force
} else {
    Write-Warning "config_validation.py not found at $configValidationSrc"
}

# Download bundled dependency installers (Python, WireGuard)
Write-Host "Downloading bundled dependency installers..."
$depsScript = Join-Path $ProjectRoot "scripts\build\download-windows-deps.ps1"
if (Test-Path $depsScript) {
    & $depsScript
} else {
    Write-Warning "download-windows-deps.ps1 not found at $depsScript - skipping dependency download"
}

$outputDir = Join-Path $ProjectRoot "dist\installers"
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

# Generate LICENSE.txt from LICENSE.md so the Inno Setup license-acceptance
# screen renders cleanly (without literal "#" / "##" / "---" leaking from
# the source markdown). The .txt is gitignored and regenerated on every
# build, so LICENSE.md remains the single source of truth.
Write-Host "Generating LICENSE.txt for Inno Setup..."
Convert-LicenseMdToTxt `
    -SourceMd (Join-Path $ProjectRoot "LICENSE.md") `
    -TargetTxt (Join-Path $ProjectRoot "LICENSE.txt")

$version = Get-AppVersion
$iscc = Resolve-InnoCompiler
$issScript = Join-Path $ProjectRoot "packaging\windows\ResistineInstaller.iss"

if (-not (Test-Path $issScript)) {
    throw "Inno Setup script not found at $issScript"
}

# Pass the detected architecture to Inno Setup so the .iss can configure
# ArchitecturesInstallIn64BitMode and ArchitecturesAllowed correctly.
$targetArch = if ($IsARM64) { "arm64" } else { "x64" }
Write-Host "Building Windows installer (.exe) with Inno Setup ($targetArch)..."

# ISCC writes Setup.exe, then re-opens it to stamp the icon/version resources.
# That re-open fails with "EndUpdateResource failed (110)" when something still
# holds the freshly written file: Defender's real-time scan, the Search indexer,
# or Explorer previewing the folder. All of those are far more likely under a
# user profile folder (Desktop, OneDrive) than under %TEMP%, so compile into a
# fresh private temp folder, retry the transient lock a few times, and only
# then move the finished .exe into dist\installers.
$innoTempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("phoenix-iscc-" + [System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Force -Path $innoTempDir | Out-Null
$maxAttempts = 3
try {
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        Get-ChildItem -Path $innoTempDir -File -ErrorAction SilentlyContinue | Remove-Item -Force
        & $iscc "/DAppName=Phoenix" "/DAppVersion=$version" "/DAppBuild=$build" "/DSourceDir=$sourceDir" "/DOutputDir=$innoTempDir" "/DTargetArch=$targetArch" $issScript
        if ($LASTEXITCODE -eq 0) { break }
        if ($attempt -eq $maxAttempts) {
            throw ("Inno Setup compilation failed with exit code $LASTEXITCODE after $maxAttempts attempts. " +
                   "If the error is 'EndUpdateResource failed (110)', exclude '$innoTempDir' (or `$env:TEMP) " +
                   "from your antivirus real-time scanning and rerun.")
        }
        Write-Warning "Inno Setup exited with code $LASTEXITCODE (attempt $attempt of $maxAttempts); retrying in 5 s..."
        Start-Sleep -Seconds 5
    }

    $built = @(Get-ChildItem -Path $innoTempDir -Filter "*.exe" -File)
    if ($built.Count -eq 0) {
        throw "Inno Setup reported success but produced no .exe in $innoTempDir"
    }
    foreach ($f in $built) {
        $dest = Join-Path $outputDir $f.Name
        if (Test-Path $dest) { Remove-Item $dest -Force }
        Move-Item -Path $f.FullName -Destination $dest -Force
    }
} finally {
    Remove-Item -Path $innoTempDir -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "Done. Installer output:"
Write-Host "  $outputDir\Phoenix-Setup-${version}-${build}.exe"