# Runs inside the throwaway Windows VM (scripts/build/build-windows-vm.sh
# copies it in). The golden image has only OpenSSH, so this installs the
# build tools first: Python 3.13 (the installer download-windows-deps.ps1
# fetches for the setup anyway) and Inno Setup 6. Then it runs the normal
# build-windows-installer.ps1 (PyInstaller + Inno Setup).
param ([Parameter(Mandatory)] [string]$Zip, [string]$Build)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$InnoUrl = "https://github.com/jrsoftware/issrc/releases/download/is-6_7_1/innosetup-6.7.1.exe"
$Src = "C:\b\src"

Remove-Item C:\b -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $Src | Out-Null
Expand-Archive $Zip -DestinationPath $Src
Set-Location $Src

function Install-Quiet([string]$Exe, [string[]]$ArgList) {
    $p = Start-Process -FilePath $Exe -ArgumentList $ArgList -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "$Exe failed ($($p.ExitCode))" }
}

Write-Host "== Python"
& .\scripts\build\download-windows-deps.ps1
$py = Get-ChildItem .\packaging\windows\deps\python-3.13*-amd64.exe | Select-Object -First 1
if (-not $py) { throw "download-windows-deps.ps1 fetched no Python installer" }
Install-Quiet $py.FullName @("/quiet", "InstallAllUsers=1", "PrependPath=1", "Include_test=0", "Include_launcher=0")
$env:Path = "C:\Program Files\Python313;C:\Program Files\Python313\Scripts;" + $env:Path
& python --version

Write-Host "== Inno Setup"
$inno = "$env:TEMP\innosetup.exe"
Invoke-WebRequest -UseBasicParsing -OutFile $inno -Uri $InnoUrl
Install-Quiet $inno @("/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/SP-", "/ALLUSERS")
Remove-Item $inno

Write-Host "== PyInstaller + installer"
if ($Build) { $env:PHOENIX_BUILD = $Build }
& .\scripts\build\build-windows-installer.ps1
Get-ChildItem .\dist\installers\*.exe | Select-Object Name, Length
