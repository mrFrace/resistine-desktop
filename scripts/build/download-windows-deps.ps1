<#
.SYNOPSIS
    Downloads bundled dependency installers for the Resistine Windows installer.
.DESCRIPTION
    Downloads Python 3.13 and WireGuard installers into packaging/windows/deps/
    so they can be bundled into the Inno Setup package. Skips files that already exist.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path (Split-Path (Split-Path -Parent $PSCommandPath) -Parent) -Parent
$DepsDir = Join-Path $ProjectRoot "packaging\windows\deps"

if (-not (Test-Path $DepsDir)) {
    New-Item -ItemType Directory -Force -Path $DepsDir | Out-Null
}

$Downloads = @(
    @{
        Name = "Python 3.13.13"
        Url  = "https://www.python.org/ftp/python/3.13.13/python-3.13.13-amd64.exe"
        File = "python-3.13.13-amd64.exe"
    },
    @{
        Name = "WireGuard 1.1"
        Url  = "https://download.wireguard.com/windows-client/wireguard-amd64-1.1.msi"
        File = "wireguard-amd64.msi"
    }
)

foreach ($dep in $Downloads) {
    $destPath = Join-Path $DepsDir $dep.File
    if (Test-Path $destPath) {
        Write-Host "  Already exists: $($dep.File)"
        continue
    }
    Write-Host "  Downloading $($dep.Name)..."
    try {
        Invoke-WebRequest -Uri $dep.Url -OutFile $destPath -UseBasicParsing
        Write-Host "  OK: $($dep.File) ($([math]::Round((Get-Item $destPath).Length / 1MB, 1)) MB)"
    } catch {
        Write-Error "Failed to download $($dep.Name) from $($dep.Url): $_"
    }
}

Write-Host "Bundled dependencies ready in: $DepsDir"
