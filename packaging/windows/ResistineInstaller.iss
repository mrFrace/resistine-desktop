#ifndef AppName
  #define AppName "Phoenix"
#endif

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

; Build ID (UTC YYYYMMDDHHMM, see packaging/Resistine.spec). It goes into the
; file name and the version Windows shows, not into AppVersion: the version
; checks below compare dot-separated numbers.
#ifndef AppBuild
  #define AppBuild "0"
#endif

#ifndef SourceDir
  #define SourceDir "..\..\dist\Phoenix"
#endif

#ifndef OutputDir
  #define OutputDir "..\..\dist\installers"
#endif

; AppId stays "ResistineDesktop" so upgrades replace the pre-rebrand install
; in place. Folder, registry and service names below are kept for the same
; reason; only what users see says Phoenix.
#define AppId "ResistineDesktop"

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}+{#AppBuild}
AppPublisher=Phoenix
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
UsePreviousAppDir=yes
UsePreviousGroup=yes
OutputDir={#OutputDir}
OutputBaseFilename={#AppName}-Setup-{#AppVersion}-{#AppBuild}
Compression=lzma2
SolidCompression=yes
#ifdef TargetArch
  #if TargetArch == "arm64"
    ArchitecturesAllowed=arm64
    ArchitecturesInstallIn64BitMode=arm64
  #else
    ArchitecturesAllowed=x64compatible
    ArchitecturesInstallIn64BitMode=x64compatible
  #endif
#else
  ArchitecturesAllowed=x64compatible
  ArchitecturesInstallIn64BitMode=x64compatible
#endif
PrivilegesRequired=admin
; Auto-update robustness: an older build's in-app updater only hides to the
; tray instead of quitting, leaving its files locked. CloseApplications=force
; makes Setup forcibly terminate the running app (via RestartManager, then a
; hard kill) so the update can proceed without a "files in use" prompt — which
; is what lets already-deployed buggy versions auto-update without a manual
; reinstall. RestartApplications=no leaves the relaunch to the single [Run]
; entry (runasoriginaluser, no 'skipifsilent') so we don't double-launch.
CloseApplications=force
RestartApplications=no
WizardStyle=modern
DisableDirPage=auto
DisableReadyPage=yes
DisableProgramGroupPage=yes
SetupIconFile=..\..\resources\icons\icon.ico
UninstallDisplayIcon={app}\Phoenix.exe
SetupLogging=yes
; Show the GPL-2.0-or-later text on the install acceptance screen. Inno
; reads this at compile time and displays the contents as plain text in
; the License Agreement dialog. LICENSE.txt is generated from LICENSE.md
; by scripts/build/build-windows-installer.ps1 (markdown stripped so the
; "#"/"##"/"---" syntax doesn't render as literal noise). The .txt is
; gitignored and produced fresh on every build. Third-party licenses
; are shipped as a separate file inside the install dir (see [Files]
; below) since they're 370+ lines and would dominate the acceptance
; dialog if combined.
LicenseFile=..\..\LICENSE.txt

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop icon"; Flags: unchecked
Name: "startup"; Description: "Start Phoenix when I sign in"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
; License files — installed next to the app so end users, auditors, and
; security teams can find them via the install directory without needing to
; go to GitHub. LICENSE.md is also shown at the install acceptance screen
; (see LicenseFile= in [Setup] above).
Source: "..\..\LICENSE.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE-3rd-Party.md"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\sbom.cdx.json"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
; Bundled dependency installers — only extracted when the dep is missing
Source: "deps\python-3.13.13-amd64.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall nocompression; Check: NeedPythonInstall
Source: "deps\wireguard-amd64.msi"; DestDir: "{tmp}"; Flags: deleteafterinstall nocompression; Check: NeedWireGuardInstall

[Icons]
Name: "{autoprograms}\{#AppName}\{#AppName}"; Filename: "{app}\Phoenix.exe"
Name: "{autoprograms}\{#AppName}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\Phoenix.exe"; Tasks: desktopicon

[Registry]
Root: HKLM64; Subkey: "Software\Resistine"; ValueType: string; ValueName: "InstallDir"; ValueData: "{app}"; Flags: uninsdeletevalue uninsdeletekeyifempty
Root: HKLM64; Subkey: "Software\Resistine"; ValueType: string; ValueName: "Version"; ValueData: "{#AppVersion}"; Flags: uninsdeletevalue
Root: HKLM64; Subkey: "Software\Resistine"; ValueType: string; ValueName: "Build"; ValueData: "{#AppBuild}"; Flags: uninsdeletevalue
Root: HKLM64; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "Phoenix"; ValueData: """{app}\Phoenix.exe"""; Tasks: startup; Flags: uninsdeletevalue

[Run]
; No 'skipifsilent': WinSparkle runs this installer with /SILENT during an
; auto-update, and we still want the app relaunched afterward (otherwise the
; update applies but "nothing happens" — the app just stays closed).
Filename: "{app}\Phoenix.exe"; Description: "Launch {#AppName}"; Flags: nowait postinstall runasoriginaluser; Check: ShouldPerformInstallAction

[InstallDelete]
; Shortcuts created by pre-rebrand installers (AppName was "Resistine").
Type: files; Name: "{autoprograms}\Resistine\Resistine.lnk"
Type: files; Name: "{autoprograms}\Resistine\Uninstall Resistine.lnk"
Type: dirifempty; Name: "{autoprograms}\Resistine"
Type: files; Name: "{autodesktop}\Resistine.lnk"
; The app itself was Resistine.exe before the rename.
Type: files; Name: "{app}\Resistine.exe"

[UninstallDelete]
; Inno Setup only removes files recorded in its install manifest. Python
; generates __pycache__\*.pyc bytecode (e.g. windows_vpn_service.cpython-XX.pyc)
; at runtime, and other components may drop logs/configs inside {app}. These
; untracked files keep {app} non-empty so it survives uninstall and triggers a
; "folder already exists" warning on the next fresh install. Force-remove the
; entire install tree so nothing lingers.
Type: filesandordirs; Name: "{app}"

[Code]
type
  TMaintenanceAction = (maInstall, maReinstall, maUninstall);

var
  ExistingInstallDetected: Boolean;
  ExistingInstallDir: string;
  ExistingInstallVersion: string;
  ExistingUninstallCmd: string;
  ExistingAppExecutableAvailable: Boolean;
  ExistingUninstallerAvailable: Boolean;
  MaintenancePage: TWizardPage;
  MaintenanceInfoLabel: TNewStaticText;
  InstallRadio: TRadioButton;
  ReinstallRadio: TRadioButton;
  UninstallRadio: TRadioButton;
  MaintenanceActionHeaderLabel: TNewStaticText;
  MaintenanceActionDetailHeaderLabel: TNewStaticText;
  MaintenanceActionDetailLabel: TNewStaticText;
  MaintenanceDataOptionsHeaderLabel: TNewStaticText;
  MaintenanceDataOptionsEmptyLabel: TNewStaticText;
  RemoveUserDataCheck: TNewCheckBox;
  BackupSettingsCheck: TNewCheckBox;
  BackupHelpLabel: TNewStaticText;
  RemoveUserDataHelpLabel: TNewStaticText;
  PreflightPage: TWizardPage;
  PreflightInfoLabel: TNewStaticText;
  PreflightActionHeaderLabel: TNewStaticText;
  PreflightActionLabel: TNewStaticText;
  PreflightChecksHeaderLabel: TNewStaticText;
  PreflightChecksLabel: TNewStaticText;
  PreflightTasksHeaderLabel: TNewStaticText;
  PreflightTasksLabel: TNewStaticText;
  SelectedAction: TMaintenanceAction;
  RemoveUserDataAfterUninstall: Boolean;
  PendingReinstallRestore: Boolean;
  ReinstallBackupRoot: string;
  ReinstallBackupUserDataDir: string;
  ReinstallBackupCommonDataDir: string;
  DependencyInstallWarnings: string;
  DependencyInstallAttempted: Boolean;
  LastDependencyPreflightText: string;
  StandaloneUninstallRemoveUserData: Boolean;
  MaintenanceUninstallByInstaller: Boolean;
  CloseAfterMaintenanceUninstall: Boolean;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if not IsAdminInstallMode then
  begin
    SuppressibleMsgBox('This installer must be run as Administrator.', mbError, MB_OK, IDOK);
    Result := False;
  end;
end;

function PopVersionPart(var S: string): Integer;
var
  P: Integer;
  Part: string;
begin
  P := Pos('.', S);
  if P = 0 then
  begin
    Part := S;
    S := '';
  end
  else
  begin
    Part := Copy(S, 1, P - 1);
    Delete(S, 1, P);
  end;
  Result := StrToIntDef(Part, 0);
end;

function CompareVersionStrings(A, B: string): Integer;
var
  SA: string;
  SB: string;
  PA: Integer;
  PB: Integer;
begin
  SA := A;
  SB := B;
  while (SA <> '') or (SB <> '') do
  begin
    PA := PopVersionPart(SA);
    PB := PopVersionPart(SB);
    if PA < PB then
    begin
      Result := -1;
      exit;
    end;
    if PA > PB then
    begin
      Result := 1;
      exit;
    end;
  end;
  Result := 0;
end;

function GetRegistryString64(Name: string; var Value: string): Boolean;
begin
  Result := RegQueryStringValue(HKLM64, 'Software\Resistine', Name, Value);
  if not Result then
    Result := RegQueryStringValue(HKLM, 'Software\Resistine', Name, Value);
end;

function GetUninstallRegistryString(const SubKey, Name: string; var Value: string): Boolean;
begin
  Result := RegQueryStringValue(HKLM64, SubKey, Name, Value);
  if not Result then
    Result := RegQueryStringValue(HKLM, SubKey, Name, Value);
end;

function QuotePath(const S: string): string;
begin
  Result := '"' + S + '"';
end;

function GetLegacyUserDataDir: string;
begin
  Result := ExpandConstant('{userappdata}\Resistine');
end;

{ The app keeps per-user data in %APPDATA%\Phoenix and moves a pre-rebrand
  %APPDATA%\Resistine there on first start. Until then the legacy dir is the
  live one. }
function GetResistineUserDataDir: string;
begin
  Result := ExpandConstant('{userappdata}\Phoenix');
  if (not DirExists(Result)) and DirExists(GetLegacyUserDataDir) then
    Result := GetLegacyUserDataDir;
end;

function GetResistineCommonDataDir: string;
begin
  Result := ExpandConstant('{commonappdata}\Resistine');
end;

function GetInteropSubkey: string;
begin
  Result := 'Software\Resistine\InstallerInterop';
end;

function RunHiddenCmd(const Params: string; var ResultCode: Integer): Boolean;
begin
  Result := Exec(ExpandConstant('{cmd}'), '/C ' + Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function HiddenCmdSucceeded(const Params: string): Boolean;
var
  ResultCode: Integer;
begin
  Result := RunHiddenCmd(Params, ResultCode) and (ResultCode = 0);
end;

function IsWireGuardInstalled: Boolean;
begin
  Result := FileExists('C:\Program Files\WireGuard\wireguard.exe');
end;

function IsPythonInstalled: Boolean;
begin
  { Accept Python 3.13 or newer only.  Older 3.x versions (3.10/3.11/3.12)
    trigger the bundled installer to upgrade the user.  We check both
    user-local and system-wide install locations for 3.13 and 3.14. }
  Result :=
    FileExists(ExpandConstant('{localappdata}\Programs\Python\Python313\python.exe')) or
    FileExists(ExpandConstant('{localappdata}\Programs\Python\Python314\python.exe')) or
    FileExists(ExpandConstant('{pf}\Python313\python.exe')) or
    FileExists(ExpandConstant('{pf}\Python314\python.exe'));
end;

function IsWingetAvailable: Boolean;
begin
  Result := HiddenCmdSucceeded('where winget >nul 2>nul');
end;

function IsInternetReachable: Boolean;
begin
  { Heuristic only; ICMP may be blocked on some networks. }
  Result := HiddenCmdSucceeded('ping -n 1 -w 1200 1.1.1.1 >nul 2>nul');
end;

function IsResistineRunning: Boolean;
begin
  { Resistine.exe: builds from before the rename }
  Result := HiddenCmdSucceeded('tasklist /FI "IMAGENAME eq Phoenix.exe" | find /I "Phoenix.exe" >nul') or
            HiddenCmdSucceeded('tasklist /FI "IMAGENAME eq Resistine.exe" | find /I "Resistine.exe" >nul');
end;

function IsVpnServiceInstalled: Boolean;
begin
  Result := HiddenCmdSucceeded('sc query "ResistineVPN" >nul 2>nul');
end;

function ServiceExists(const ServiceName: string): Boolean;
begin
  Result := HiddenCmdSucceeded('sc query ' + QuotePath(ServiceName) + ' >nul 2>nul');
end;

function TryKillResistineProcess(ForceKill: Boolean): Boolean;
var
  ResultCode: Integer;
  Params: string;
begin
  if ForceKill then
    Params := 'taskkill /F /T /IM Phoenix.exe /IM Resistine.exe >nul 2>nul'
  else
    Params := 'taskkill /T /IM Phoenix.exe /IM Resistine.exe >nul 2>nul';

  { taskkill returns non-zero if not running; treat "not running" as success. }
  RunHiddenCmd(Params, ResultCode);

  { Also kill tray process (pythonw.exe running tray.py) }
  RunHiddenCmd(
    'powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name=''python.exe'' OR Name=''pythonw.exe''\" | ' +
    'Where-Object { $_.CommandLine -like ''*tray.py*'' -or $_.CommandLine -like ''*Resistine*'' } | ' +
    'ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }" >nul 2>nul',
    ResultCode);

  Sleep(750);
  Result := not IsResistineRunning;
end;

function BoolStatus(const Value: Boolean; const TrueText, FalseText: string): string;
begin
  if Value then
    Result := TrueText
  else
    Result := FalseText;
end;

function DirectoryExistsAndNotEmpty(const DirName: string): Boolean;
begin
  Result := DirExists(DirName);
  if Result then
    Result := HiddenCmdSucceeded('dir /A /B ' + QuotePath(DirName) + ' 2>nul | findstr . >nul');
end;

procedure DeleteDirectoryIfExists(const DirName: string);
var
  ResultCode: Integer;
begin
  if DirExists(DirName) then
  begin
    RunHiddenCmd('rmdir /S /Q ' + QuotePath(DirName), ResultCode);
  end;
end;

function CopyDirectoryTree(const SrcDir, DstDir: string): Boolean;
var
  ResultCode: Integer;
begin
  if not DirExists(SrcDir) then
  begin
    Result := True;
    exit;
  end;

  ForceDirectories(DstDir);

  if HiddenCmdSucceeded('where robocopy >nul 2>nul') then
  begin
    if not RunHiddenCmd(
      'robocopy ' + QuotePath(SrcDir) + ' ' + QuotePath(DstDir) +
      ' /E /R:1 /W:1 /NFL /NDL /NJH /NJS /NP >nul', ResultCode) then
    begin
      Result := False;
      exit;
    end;
    Result := ResultCode <= 7;
    exit;
  end;

  if not RunHiddenCmd(
    'xcopy ' + QuotePath(SrcDir) + ' ' + QuotePath(DstDir) +
    ' /E /I /H /Y >nul', ResultCode) then
  begin
    Result := False;
    exit;
  end;
  Result := (ResultCode = 0) or (ResultCode = 1);
end;

procedure DeleteResistineUserData;
begin
  DeleteDirectoryIfExists(ExpandConstant('{userappdata}\Phoenix'));
  DeleteDirectoryIfExists(GetLegacyUserDataDir);
  DeleteDirectoryIfExists(GetResistineCommonDataDir);
end;

function WaitForServiceAbsent(const ServiceName: string; Attempts, DelayMs: Integer): Boolean;
var
  I: Integer;
begin
  for I := 0 to Attempts - 1 do
  begin
    if not ServiceExists(ServiceName) then
    begin
      Result := True;
      exit;
    end;
    Sleep(DelayMs);
  end;
  Result := not ServiceExists(ServiceName);
end;

function WaitForServiceStoppedOrAbsent(const ServiceName: string; Attempts, DelayMs: Integer): Boolean;
var
  I: Integer;
begin
  for I := 0 to Attempts - 1 do
  begin
    if (not ServiceExists(ServiceName)) or
       HiddenCmdSucceeded('sc query ' + QuotePath(ServiceName) + ' | find /I "STOPPED" >nul 2>nul') then
    begin
      Result := True;
      exit;
    end;
    Sleep(DelayMs);
  end;

  Result := (not ServiceExists(ServiceName)) or
    HiddenCmdSucceeded('sc query ' + QuotePath(ServiceName) + ' | find /I "STOPPED" >nul 2>nul');
end;

procedure RemoveLegacyStartupArtifacts;
begin
  RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'ResistineVPNTray');
  RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'ResistineVPN');
  RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'Resistine');
  RegDeleteValue(HKLM64, 'Software\Microsoft\Windows\CurrentVersion\Run', 'ResistineVPNTray');
  RegDeleteValue(HKLM64, 'Software\Microsoft\Windows\CurrentVersion\Run', 'ResistineVPN');
  RegDeleteValue(HKLM64, 'Software\Microsoft\Windows\CurrentVersion\Run', 'Resistine');
  RegDeleteValue(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Run', 'ResistineVPNTray');
  RegDeleteValue(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Run', 'ResistineVPN');
  RegDeleteValue(HKLM, 'Software\Microsoft\Windows\CurrentVersion\Run', 'Resistine');
  RegDeleteValue(HKLM64, 'Software\Microsoft\Windows\CurrentVersion\Run', 'Phoenix');

  DeleteFile(ExpandConstant('{userdesktop}\Resistine VPN.lnk'));
end;

function RunBundledServiceCleanupScript: Boolean;
var
  ResultCode: Integer;
  ScriptPath: string;
begin
  Result := False;

  ScriptPath := ExpandConstant('{app}\install_service.bat');
  if not FileExists(ScriptPath) then
    exit;

  Log('Uninstall cleanup: invoking bundled service cleanup script');
  if Exec(
    ExpandConstant('{cmd}'),
    '/C call ' + QuotePath(ScriptPath) + ' /uninstallquiet',
    ExpandConstant('{app}'),
    SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    Log('Bundled service cleanup exit code: ' + IntToStr(ResultCode));
    Result := ResultCode = 0;
  end
  else
    Log('Bundled service cleanup script failed to launch');
end;

procedure ForceKillServiceProcess(const ServiceName: string);
var
  ResultCode: Integer;
begin
  { Force-kill the service's hosting process by PID. The ResistineVPN service
    is hosted by PythonService.exe running windows_vpn_service.py from the
    install folder; if it lingers after "sc stop" it keeps open handles on
    files there (including runtime-generated __pycache__ .pyc files), which
    blocks folder removal. Querying the live service for its PID lets us target
    only that process instead of killing unrelated python hosts. }
  RunHiddenCmd(
    'powershell -NoProfile -Command "$s = Get-CimInstance Win32_Service -Filter \"Name=''' + ServiceName + '''\"; ' +
    'if ($s -and $s.ProcessId -gt 0) { Stop-Process -Id $s.ProcessId -Force -ErrorAction SilentlyContinue }" >nul 2>nul',
    ResultCode);
end;

procedure StopAndDeleteService(const ServiceName: string);
var
  I: Integer;
  ResultCode: Integer;
begin
  if not ServiceExists(ServiceName) then
    exit;

  RunHiddenCmd('sc stop ' + QuotePath(ServiceName) + ' >nul 2>nul', ResultCode);
  WaitForServiceStoppedOrAbsent(ServiceName, 15, 1000);

  { Ensure the hosting process is gone (releases file handles on the install
    folder) before deleting the registration. Must run while the service still
    exists so its PID is queryable. }
  ForceKillServiceProcess(ServiceName);
  Sleep(750);

  for I := 0 to 4 do
  begin
    RunHiddenCmd('sc delete ' + QuotePath(ServiceName) + ' >nul 2>nul', ResultCode);
    if WaitForServiceAbsent(ServiceName, 3, 1000) then
      exit;
    Sleep(500);
  end;
end;

procedure RemoveNamedWireGuardTunnel(const TunnelName: string);
var
  ResultCode: Integer;
  WireGuardExe: string;
  ServiceName: string;
begin
  ServiceName := 'WireGuardTunnel$' + TunnelName;
  WireGuardExe := 'C:\Program Files\WireGuard\wireguard.exe';

  if ServiceExists(ServiceName) then
  begin
    RunHiddenCmd('sc stop ' + QuotePath(ServiceName) + ' >nul 2>nul', ResultCode);
    WaitForServiceStoppedOrAbsent(ServiceName, 10, 1000);
  end;

  if FileExists(WireGuardExe) then
    RunHiddenCmd(QuotePath(WireGuardExe) + ' /uninstalltunnelservice ' + TunnelName + ' >nul 2>nul', ResultCode);

  StopAndDeleteService(ServiceName);
end;

procedure RemoveResistineVpnServicesAndTunnels;
begin
  RemoveLegacyStartupArtifacts;

  RunBundledServiceCleanupScript;

  Log('Uninstall cleanup: stopping/removing Resistine VPN Windows service');
  StopAndDeleteService('ResistineVPN');

  Log('Uninstall cleanup: stopping/removing Resistine WireGuard tunnel services');
  RemoveNamedWireGuardTunnel('resistine');
  RemoveNamedWireGuardTunnel('resistine_default');
  RemoveNamedWireGuardTunnel('resistine_vpn');

  { Always delete WireGuard config files on uninstall, not just when user opts-in }
  Log('Uninstall cleanup: removing WireGuard configuration files');
  DeleteDirectoryIfExists(ExpandConstant('{userappdata}\Phoenix\wireguard'));
  DeleteDirectoryIfExists(ExpandConstant('{userappdata}\Resistine\wireguard'));
  DeleteDirectoryIfExists(ExpandConstant('{commonappdata}\Resistine\wireguard'));
end;

function HasAnyResistineUserData: Boolean;
begin
  Result := DirectoryExistsAndNotEmpty(ExpandConstant('{userappdata}\Phoenix')) or
            DirectoryExistsAndNotEmpty(GetLegacyUserDataDir) or
            DirectoryExistsAndNotEmpty(GetResistineCommonDataDir);
end;

procedure DetectExistingInstall;
var
  LegacyUninstallKey: string;
  InnoUninstallKey: string;
begin
  ExistingInstallDetected := False;
  ExistingInstallDir := '';
  ExistingInstallVersion := '';
  ExistingUninstallCmd := '';
  ExistingAppExecutableAvailable := False;
  ExistingUninstallerAvailable := False;

  GetRegistryString64('InstallDir', ExistingInstallDir);
  GetRegistryString64('Version', ExistingInstallVersion);

  InnoUninstallKey := 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#AppId}_is1';
  LegacyUninstallKey := 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Resistine';

  if GetUninstallRegistryString(InnoUninstallKey, 'UninstallString', ExistingUninstallCmd) then
  begin
    if ExistingInstallVersion = '' then
      GetUninstallRegistryString(InnoUninstallKey, 'DisplayVersion', ExistingInstallVersion);
    if ExistingInstallDir = '' then
      GetUninstallRegistryString(InnoUninstallKey, 'InstallLocation', ExistingInstallDir);
  end
  else if GetUninstallRegistryString(LegacyUninstallKey, 'UninstallString', ExistingUninstallCmd) then
  begin
    if ExistingInstallVersion = '' then
      GetUninstallRegistryString(LegacyUninstallKey, 'DisplayVersion', ExistingInstallVersion);
    if ExistingInstallDir = '' then
      GetUninstallRegistryString(LegacyUninstallKey, 'InstallLocation', ExistingInstallDir);
  end;

  if (ExistingInstallDir = '') and DirExists(ExpandConstant('{autopf}\{#AppName}')) then
    ExistingInstallDir := ExpandConstant('{autopf}\{#AppName}');

  if (ExistingUninstallCmd = '') and FileExists(AddBackslash(ExistingInstallDir) + 'unins000.exe') then
    ExistingUninstallCmd := QuotePath(AddBackslash(ExistingInstallDir) + 'unins000.exe');
  if (ExistingUninstallCmd = '') and FileExists(AddBackslash(ExistingInstallDir) + 'Uninstall.exe') then
    ExistingUninstallCmd := QuotePath(AddBackslash(ExistingInstallDir) + 'Uninstall.exe');

  ExistingInstallDetected := (ExistingInstallDir <> '') or (ExistingUninstallCmd <> '');
end;

function ExtractExePathFromCommand(const CommandLine: string): string; forward;
function ShouldPerformInstallAction: Boolean; forward;

function NeedPythonInstall: Boolean;
begin
  Result := ShouldPerformInstallAction and (not IsPythonInstalled);
end;

function NeedWireGuardInstall: Boolean;
begin
  Result := ShouldPerformInstallAction and (not IsWireGuardInstalled);
end;

function ExistingUninstallerLooksLikeInno: Boolean;
var
  ExePath: string;
begin
  ExePath := LowerCase(ExtractFileName(ExtractExePathFromCommand(ExistingUninstallCmd)));
  Result := Pos('unins', ExePath) = 1;
end;

procedure SetInstallerUninstallInteropFlags(const RemoveUserData: Boolean);
begin
  RegWriteStringValue(HKLM64, GetInteropSubkey, 'TriggeredByInstaller', '1');
  if RemoveUserData then
    RegWriteStringValue(HKLM64, GetInteropSubkey, 'RemoveUserData', '1')
  else
    RegWriteStringValue(HKLM64, GetInteropSubkey, 'RemoveUserData', '0');
end;

procedure ClearInstallerUninstallInteropFlags;
begin
  RegDeleteValue(HKLM64, GetInteropSubkey, 'TriggeredByInstaller');
  RegDeleteValue(HKLM64, GetInteropSubkey, 'RemoveUserData');
  RegDeleteValue(HKLM, GetInteropSubkey, 'TriggeredByInstaller');
  RegDeleteValue(HKLM, GetInteropSubkey, 'RemoveUserData');
end;

procedure LoadInstallerUninstallInteropFlags;
var
  Triggered: string;
  RemoveData: string;
begin
  MaintenanceUninstallByInstaller := False;
  StandaloneUninstallRemoveUserData := False;

  if RegQueryStringValue(HKLM64, GetInteropSubkey, 'TriggeredByInstaller', Triggered) or
     RegQueryStringValue(HKLM, GetInteropSubkey, 'TriggeredByInstaller', Triggered) then
  begin
    MaintenanceUninstallByInstaller := Triggered = '1';
  end;

  if RegQueryStringValue(HKLM64, GetInteropSubkey, 'RemoveUserData', RemoveData) or
     RegQueryStringValue(HKLM, GetInteropSubkey, 'RemoveUserData', RemoveData) then
  begin
    StandaloneUninstallRemoveUserData := RemoveData = '1';
  end;

  if MaintenanceUninstallByInstaller then
    ClearInstallerUninstallInteropFlags;
end;

function BackupDataForReinstall: Boolean;
var
  AnySourceData: Boolean;
  OkUser: Boolean;
  OkCommon: Boolean;
  ContinueWithoutBackup: Integer;
begin
  Result := True;
  PendingReinstallRestore := False;

  if (BackupSettingsCheck = nil) or (not BackupSettingsCheck.Checked) then
    exit;

  AnySourceData := DirExists(GetResistineUserDataDir) or DirExists(GetResistineCommonDataDir);
  if not AnySourceData then
    exit;

  ReinstallBackupRoot := ExpandConstant('{tmp}\ResistineReinstallBackup');
  ReinstallBackupUserDataDir := AddBackslash(ReinstallBackupRoot) + 'UserAppData';
  ReinstallBackupCommonDataDir := AddBackslash(ReinstallBackupRoot) + 'CommonAppData';

  DeleteDirectoryIfExists(ReinstallBackupRoot);
  ForceDirectories(ReinstallBackupRoot);

  OkUser := CopyDirectoryTree(GetResistineUserDataDir, ReinstallBackupUserDataDir);
  OkCommon := CopyDirectoryTree(GetResistineCommonDataDir, ReinstallBackupCommonDataDir);

  if not (OkUser and OkCommon) then
  begin
    ContinueWithoutBackup := SuppressibleMsgBox(
      'Phoenix could not back up all settings before reinstall.' + #13#10 +
      'You can cancel and back up manually, or continue the reinstall without a complete backup.' + #13#10#13#10 +
      'Continue without backup?',
      mbError, MB_YESNO, IDNO);
    if ContinueWithoutBackup <> IDYES then
    begin
      Result := False;
      exit;
    end;
    DeleteDirectoryIfExists(ReinstallBackupRoot);
    exit;
  end;

  PendingReinstallRestore := DirectoryExistsAndNotEmpty(ReinstallBackupUserDataDir) or
                             DirectoryExistsAndNotEmpty(ReinstallBackupCommonDataDir);
end;

procedure RestoreDataAfterReinstallIfNeeded;
var
  OkUser: Boolean;
  OkCommon: Boolean;
begin
  if not PendingReinstallRestore then
    exit;

  OkUser := CopyDirectoryTree(ReinstallBackupUserDataDir, GetResistineUserDataDir);
  OkCommon := CopyDirectoryTree(ReinstallBackupCommonDataDir, GetResistineCommonDataDir);

  if not (OkUser and OkCommon) then
  begin
    SuppressibleMsgBox(
      'Phoenix completed installation, but some backed-up settings could not be restored automatically.' + #13#10 +
      'Backup folder: ' + ReinstallBackupRoot,
      mbError, MB_OK, IDOK);
  end;

  DeleteDirectoryIfExists(ReinstallBackupRoot);
  PendingReinstallRestore := False;
end;

procedure MaybeOfferManualDownload(const FriendlyName, Url: string; const Reason: string);
var
  Response: Integer;
  ResultCode: Integer;
begin
  Response := SuppressibleMsgBox(
    FriendlyName + ' could not be installed automatically.' + #13#10 +
    Reason + #13#10#13#10 +
    'Open the download page now?' + #13#10 + Url,
    mbError, MB_YESNO, IDNO);
  if Response = IDYES then
    ShellExec('open', Url, '', '', SW_SHOWNORMAL, ewNoWait, ResultCode);
end;

procedure AppendDependencyWarning(const WarningText: string);
begin
  if DependencyInstallWarnings <> '' then
    DependencyInstallWarnings := DependencyInstallWarnings + #13#10;
  DependencyInstallWarnings := DependencyInstallWarnings + WarningText;
end;

{ Update the wizard's status line during the post-extraction phase and force an
  immediate repaint, so the blocking dependency/service installs below read as
  real progress instead of a frozen full bar. Inno pumps the message loop during
  Exec(...ewWaitUntilTerminated), so this caption stays visible while they run. }
procedure SetInstallStatus(const Msg: string);
begin
  WizardForm.StatusLabel.Caption := Msg;
  WizardForm.StatusLabel.Update;
end;

function RunWingetDependencyInstall(const FriendlyName, PackageId, DetectPath, DownloadUrl: string): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;

  if FileExists(DetectPath) then
    exit;

  if not IsWingetAvailable then
  begin
    AppendDependencyWarning(FriendlyName + ': winget is not available.');
    MaybeOfferManualDownload(FriendlyName, DownloadUrl, 'winget is not installed or not on PATH.');
    Result := False;
    exit;
  end;

  if not IsInternetReachable then
  begin
    AppendDependencyWarning(FriendlyName + ': internet connectivity check failed.');
    MaybeOfferManualDownload(FriendlyName, DownloadUrl, 'Internet connectivity could not be confirmed.');
    Result := False;
    exit;
  end;

  SetInstallStatus('Installing ' + FriendlyName + '...');
  if not RunHiddenCmd(
    'winget install -e --id ' + QuotePath(PackageId) +
    ' --accept-package-agreements --accept-source-agreements --silent --disable-interactivity',
    ResultCode) then
  begin
    AppendDependencyWarning(FriendlyName + ': failed to launch winget.');
    MaybeOfferManualDownload(FriendlyName, DownloadUrl, 'The installer could not launch winget.');
    Result := False;
    exit;
  end;

  if (ResultCode <> 0) or (not FileExists(DetectPath)) then
  begin
    AppendDependencyWarning(FriendlyName + ': winget install failed (exit code ' + IntToStr(ResultCode) + ').');
    MaybeOfferManualDownload(FriendlyName, DownloadUrl, 'winget exited with code ' + IntToStr(ResultCode) + '.');
    Result := False;
    exit;
  end;
end;

procedure InstallBundledPython;
var
  InstallerPath: string;
  ResultCode: Integer;
begin
  if IsPythonInstalled then exit;

  InstallerPath := ExpandConstant('{tmp}\python-3.13.13-amd64.exe');
  if not FileExists(InstallerPath) then
  begin
    Log('Bundled Python installer not found at: ' + InstallerPath);
    AppendDependencyWarning('Python: bundled installer not found.');
    exit;
  end;

  SetInstallStatus('Installing Python runtime (this can take a minute)...');
  Log('Installing bundled Python 3.13...');
  if Exec(InstallerPath,
    '/quiet InstallAllUsers=1 PrependPath=1 Include_pip=1 Include_launcher=1',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    if ResultCode = 0 then
      Log('Python 3.13 installed successfully')
    else
    begin
      Log('Python installer exited with code: ' + IntToStr(ResultCode));
      AppendDependencyWarning('Python: installer exited with code ' + IntToStr(ResultCode) + '.');
    end;
  end
  else
  begin
    Log('Failed to launch Python installer');
    AppendDependencyWarning('Python: could not launch installer.');
  end;
end;

procedure InstallBundledWireGuard;
var
  InstallerPath: string;
  ResultCode: Integer;
begin
  if IsWireGuardInstalled then exit;

  InstallerPath := ExpandConstant('{tmp}\wireguard-amd64.msi');
  if not FileExists(InstallerPath) then
  begin
    Log('Bundled WireGuard installer not found at: ' + InstallerPath);
    AppendDependencyWarning('WireGuard: bundled installer not found.');
    exit;
  end;

  SetInstallStatus('Installing WireGuard...');
  Log('Installing bundled WireGuard...');
  if Exec('msiexec.exe',
    '/i "' + InstallerPath + '" /qn /norestart DO_NOT_LAUNCH=1',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    if ResultCode = 0 then
      Log('WireGuard installed successfully')
    else
    begin
      Log('WireGuard MSI exited with code: ' + IntToStr(ResultCode));
      AppendDependencyWarning('WireGuard: MSI exited with code ' + IntToStr(ResultCode) + '.');
    end;
  end
  else
  begin
    Log('Failed to launch WireGuard MSI');
    AppendDependencyWarning('WireGuard: could not launch MSI installer.');
  end;
end;

procedure InstallMissingDependenciesWithFeedback;
begin
  if DependencyInstallAttempted then
    exit;

  DependencyInstallAttempted := True;
  DependencyInstallWarnings := '';

  if ShouldPerformInstallAction then
  begin
    { Install Python and WireGuard from bundled installers first }
    InstallBundledPython;
    InstallBundledWireGuard;

    { Fall back to winget if the bundled WireGuard installer failed }
    if not IsWireGuardInstalled then
      RunWingetDependencyInstall(
        'WireGuard Desktop',
        'WireGuard.WireGuard',
        'C:\Program Files\WireGuard\wireguard.exe',
        'https://www.wireguard.com/install/'
      );

    if DependencyInstallWarnings <> '' then
      SuppressibleMsgBox(
        'Phoenix installed successfully, but some optional dependencies still need attention:' + #13#10#13#10 +
        DependencyInstallWarnings,
        mbInformation, MB_OK, IDOK);
  end;
end;

procedure ApplyStartupTaskSelection;
var
  AppExe: string;
begin
  if not ShouldPerformInstallAction then
    exit;

  AppExe := QuotePath(ExpandConstant('{app}\Phoenix.exe'));
  { The pre-rename entry points at Resistine.exe, which is gone now. }
  RegDeleteValue(HKLM64, 'Software\Microsoft\Windows\CurrentVersion\Run', 'Resistine');
  RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'Resistine');
  if WizardIsTaskSelected('startup') then
    RegWriteStringValue(HKLM64, 'Software\Microsoft\Windows\CurrentVersion\Run', 'Phoenix', AppExe)
  else
    RegDeleteValue(HKLM64, 'Software\Microsoft\Windows\CurrentVersion\Run', 'Phoenix');
end;

procedure RunVpnServiceSetupRequired;
var
  ResultCode: Integer;
  ScriptPath: string;
begin
  if not ShouldPerformInstallAction then
    exit;

  ScriptPath := ExpandConstant('{app}\install_service.bat');
  if not FileExists(ScriptPath) then
  begin
    SuppressibleMsgBox(
      'Required VPN service setup script was not found:' + #13#10 + ScriptPath + #13#10#13#10 +
      'Phoenix VPN features will not work until this is repaired.',
      mbError, MB_OK, IDOK);
    exit;
  end;

  SetInstallStatus('Registering the Phoenix VPN service...');
  if not Exec(ExpandConstant('{cmd}'),
    '/D /C call ' + QuotePath(ScriptPath) + ' /quiet',
    ExpandConstant('{app}'),
    SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    SuppressibleMsgBox(
      'The installer could not start required VPN service setup.' + #13#10 +
      'Run install_service.bat as Administrator after setup completes.',
      mbError, MB_OK, IDOK);
    exit;
  end;

  if ResultCode <> 0 then
  begin
    SuppressibleMsgBox(
      'Phoenix installed, but required VPN service setup failed (exit code ' + IntToStr(ResultCode) + ').' + #13#10 +
      'Check: C:\ProgramData\Resistine\vpn_service_install.log' + #13#10 +
      'If service registration succeeded but startup failed, also check: C:\ProgramData\Resistine\vpn_service.log' + #13#10 +
      'Then rerun install_service.bat as Administrator.',
      mbError, MB_OK, IDOK);
  end;
end;

function EnsureResistineClosedForInstall: Boolean;
var
  Response: Integer;
begin
  Result := True;

  if not ShouldPerformInstallAction then
    exit;

  if not IsResistineRunning then
    exit;

  Response := SuppressibleMsgBox(
    'Phoenix is currently running and must be closed before setup can continue.' + #13#10#13#10 +
    'Click Yes to let the installer close it automatically.' + #13#10 +
    'Click No to close it yourself and restart setup later.',
    mbConfirmation, MB_YESNO, IDYES);
  if Response <> IDYES then
  begin
    Result := False;
    exit;
  end;

  if TryKillResistineProcess(False) then
    exit;

  Response := SuppressibleMsgBox(
    'Phoenix did not close cleanly.' + #13#10#13#10 +
    'Force close it now?',
    mbConfirmation, MB_YESNO, IDYES);
  if (Response = IDYES) and TryKillResistineProcess(True) then
    exit;

  if IsResistineRunning then
  begin
    SuppressibleMsgBox('Please close Phoenix and run the installer again.', mbError, MB_OK, IDOK);
    Result := False;
  end;
end;

function EnsureResistineClosedForUninstall: Boolean;
begin
  Result := True;

  if not IsResistineRunning then
    exit;

  Log('Uninstall start: Resistine is running. Forcing process termination.');
  TryKillResistineProcess(True);
  Sleep(600);

  if IsResistineRunning then
  begin
    SuppressibleMsgBox(
      'Phoenix is still running and could not be closed automatically.' + #13#10 +
      'Please close it manually and run uninstall again.',
      mbError, MB_OK, IDOK);
    Result := False;
  end;
end;

function SelectedActionCaption: string;
begin
  case SelectedAction of
    maInstall: Result := 'Install';
    maReinstall: Result := 'Repair';
    maUninstall: Result := 'Uninstall';
  else
    Result := 'Install';
  end;
end;

function GetSelectedMaintenanceAction: TMaintenanceAction;
begin
  if (ReinstallRadio <> nil) and ReinstallRadio.Checked then
    Result := maReinstall
  else if (UninstallRadio <> nil) and UninstallRadio.Checked then
    Result := maUninstall
  else
    Result := maInstall;
end;

function GetMaintenanceActionDetailText(const ActionValue: TMaintenanceAction): string;
begin
  case ActionValue of
    maInstall:
      Result := 'Installs this version over the current app files. Your settings, logs, and VPN data stay in place.';
    maReinstall:
      Result := 'Repairs a broken installation by uninstalling and reinstalling Phoenix. You can back up data first.';
    maUninstall:
      Result := 'Uninstalls Phoenix and exits setup. You can choose whether to keep or remove user data.';
  else
    Result := '';
  end;
end;

procedure RefreshMaintenanceSelectionUI;
var
  ActionValue: TMaintenanceAction;
  ShowBackupOptions: Boolean;
  ShowUninstallOptions: Boolean;
begin
  if MaintenancePage = nil then
    exit;

  ActionValue := GetSelectedMaintenanceAction;

  if MaintenanceActionDetailLabel <> nil then
  begin
    MaintenanceActionDetailLabel.Caption := GetMaintenanceActionDetailText(ActionValue);
    WizardForm.AdjustLabelHeight(MaintenanceActionDetailLabel);
  end;

  ShowBackupOptions := ActionValue = maReinstall;
  ShowUninstallOptions := ActionValue = maUninstall;

  if MaintenanceDataOptionsHeaderLabel <> nil then
  begin
    if ShowBackupOptions then
      MaintenanceDataOptionsHeaderLabel.Caption := 'Repair options'
    else if ShowUninstallOptions then
      MaintenanceDataOptionsHeaderLabel.Caption := 'Uninstall options'
    else
      MaintenanceDataOptionsHeaderLabel.Caption := 'Options';
  end;

  if BackupSettingsCheck <> nil then
  begin
    BackupSettingsCheck.Visible := ShowBackupOptions;
    BackupSettingsCheck.Enabled := ShowBackupOptions and HasAnyResistineUserData;
  end;
  if BackupHelpLabel <> nil then
  begin
    BackupHelpLabel.Visible := ShowBackupOptions;
    BackupHelpLabel.Enabled := ShowBackupOptions;
  end;

  { User data is always removed on uninstall, so hide the checkbox }
  if RemoveUserDataCheck <> nil then
    RemoveUserDataCheck.Visible := False;
  if RemoveUserDataHelpLabel <> nil then
    RemoveUserDataHelpLabel.Visible := False;

  if MaintenanceDataOptionsEmptyLabel <> nil then
  begin
    MaintenanceDataOptionsEmptyLabel.Visible := not (ShowBackupOptions or ShowUninstallOptions);
    if ActionValue = maInstall then
      MaintenanceDataOptionsEmptyLabel.Caption := 'No additional options for Install.'
    else
      MaintenanceDataOptionsEmptyLabel.Caption := 'No additional options for this action.';
  end;
end;

procedure MaintenanceActionChanged(Sender: TObject);
begin
  RefreshMaintenanceSelectionUI;
end;

procedure BuildPreflightSummaryParts(var ActionText, ChecksText, TasksText: string);
var
  PythonState: string;
  WireGuardState: string;
  WingetState: string;
  InternetState: string;
  RunningState: string;
  VpnServiceState: string;
begin
  if IsPythonInstalled then
    PythonState := 'Installed'
  else
    PythonState := 'Missing (bundled installer will run)';

  if IsWireGuardInstalled then
    WireGuardState := 'Installed'
  else
    WireGuardState := 'Missing (bundled installer will run)';

  WingetState := BoolStatus(IsWingetAvailable, 'Available', 'Missing');
  InternetState := BoolStatus(IsInternetReachable, 'Reachable (ICMP heuristic)', 'Not confirmed');
  RunningState := BoolStatus(IsResistineRunning, 'Running (will be closed before install)', 'Not running');
  VpnServiceState := BoolStatus(IsVpnServiceInstalled, 'Installed', 'Not installed');

  ActionText :=
    'Action: ' + SelectedActionCaption + #13#10 +
    'Installer version: {#AppVersion} (build {#AppBuild})' + #13#10;

  if ExistingInstallDetected then
  begin
    ActionText := ActionText + 'Existing install: Yes' + #13#10;
    if ExistingInstallVersion <> '' then
      ActionText := ActionText + 'Installed version: ' + ExistingInstallVersion + #13#10;
    if ExistingInstallDir <> '' then
      ActionText := ActionText + 'Install path: ' + ExistingInstallDir + #13#10;
  end
  else
    ActionText := ActionText + 'Existing install: No' + #13#10;

  ChecksText :=
    '- Python: ' + PythonState + #13#10 +
    '- WireGuard Desktop: ' + WireGuardState + #13#10 +
    '- winget: ' + WingetState + #13#10 +
    '- Internet: ' + InternetState + #13#10 +
    '- Phoenix app: ' + RunningState + #13#10 +
    '- VPN Windows service: ' + VpnServiceState;

  TasksText :=
    '- Desktop icon: ' + BoolStatus(WizardIsTaskSelected('desktopicon'), 'Yes', 'No') + #13#10 +
    '- Start on sign-in: ' + BoolStatus(WizardIsTaskSelected('startup'), 'Yes', 'No') + #13#10 +
    '- VPN service setup: Required (installer will install/repair it)';
end;

procedure RefreshPreflightSummary;
var
  ActionText: string;
  ChecksText: string;
  TasksText: string;
  NextTop: Integer;
begin
  BuildPreflightSummaryParts(ActionText, ChecksText, TasksText);
  LastDependencyPreflightText :=
    'Install summary' + #13#10 + ActionText + #13#10 +
    'System checks' + #13#10 + ChecksText + #13#10#13#10 +
    'Selected options' + #13#10 + TasksText;

  if PreflightInfoLabel <> nil then
  begin
    PreflightInfoLabel.Caption := 'Review what setup will do before installation starts.';
    WizardForm.AdjustLabelHeight(PreflightInfoLabel);
  end;

  if PreflightActionLabel <> nil then
  begin
    PreflightActionLabel.Caption := ActionText;
    WizardForm.AdjustLabelHeight(PreflightActionLabel);
  end;

  if PreflightChecksLabel <> nil then
  begin
    PreflightChecksLabel.Caption := ChecksText;
    WizardForm.AdjustLabelHeight(PreflightChecksLabel);
  end;

  if PreflightTasksLabel <> nil then
  begin
    PreflightTasksLabel.Caption := TasksText;
    WizardForm.AdjustLabelHeight(PreflightTasksLabel);
  end;

  if (PreflightActionHeaderLabel <> nil) and (PreflightActionLabel <> nil) and
     (PreflightChecksHeaderLabel <> nil) and (PreflightChecksLabel <> nil) and
     (PreflightTasksHeaderLabel <> nil) and (PreflightTasksLabel <> nil) then
  begin
    NextTop := PreflightInfoLabel.Top + PreflightInfoLabel.Height + ScaleY(10);

    PreflightActionHeaderLabel.Top := NextTop;
    PreflightActionLabel.Top := PreflightActionHeaderLabel.Top + PreflightActionHeaderLabel.Height + ScaleY(2);
    NextTop := PreflightActionLabel.Top + PreflightActionLabel.Height + ScaleY(8);

    PreflightChecksHeaderLabel.Top := NextTop;
    PreflightChecksLabel.Top := PreflightChecksHeaderLabel.Top + PreflightChecksHeaderLabel.Height + ScaleY(2);
    NextTop := PreflightChecksLabel.Top + PreflightChecksLabel.Height + ScaleY(8);

    PreflightTasksHeaderLabel.Top := NextTop;
    PreflightTasksLabel.Top := PreflightTasksHeaderLabel.Top + PreflightTasksHeaderLabel.Height + ScaleY(2);
  end;
end;

function ExtractExePathFromCommand(const CommandLine: string): string;
var
  P: Integer;
  L: string;
begin
  Result := '';
  L := Trim(CommandLine);
  if L = '' then
    exit;

  if Copy(L, 1, 1) = '"' then
  begin
    Delete(L, 1, 1);
    P := Pos('"', L);
    if P > 0 then
      Result := Copy(L, 1, P - 1);
  end
  else
  begin
    P := Pos('.exe', LowerCase(L));
    if P > 0 then
      Result := Copy(L, 1, P + 3);
  end;
end;

procedure NormalizeExistingInstallState;
var
  UninstallerExePath: string;
  AppExePath: string;
begin
  ExistingAppExecutableAvailable := False;
  ExistingUninstallerAvailable := False;

  if ExistingInstallDir <> '' then
  begin
    AppExePath := AddBackslash(ExistingInstallDir) + 'Phoenix.exe';
    ExistingAppExecutableAvailable := FileExists(AppExePath) or
      FileExists(AddBackslash(ExistingInstallDir) + 'Resistine.exe');
  end;

  if ExistingUninstallCmd <> '' then
  begin
    UninstallerExePath := ExtractExePathFromCommand(ExistingUninstallCmd);
    if (UninstallerExePath <> '') and FileExists(UninstallerExePath) then
      ExistingUninstallerAvailable := True
    else
      ExistingUninstallCmd := '';
  end;

  if (not ExistingUninstallerAvailable) and (ExistingInstallDir <> '') then
  begin
    if FileExists(AddBackslash(ExistingInstallDir) + 'unins000.exe') then
    begin
      ExistingUninstallCmd := QuotePath(AddBackslash(ExistingInstallDir) + 'unins000.exe');
      ExistingUninstallerAvailable := True;
    end
    else if FileExists(AddBackslash(ExistingInstallDir) + 'Uninstall.exe') then
    begin
      ExistingUninstallCmd := QuotePath(AddBackslash(ExistingInstallDir) + 'Uninstall.exe');
      ExistingUninstallerAvailable := True;
    end;
  end;

  if (not ExistingUninstallerAvailable) and (not ExistingAppExecutableAvailable) then
  begin
    if (ExistingInstallDir <> '') or (ExistingInstallVersion <> '') then
      Log('Ignoring stale install metadata (no app exe and no uninstaller found).');

    ExistingInstallDetected := False;
    ExistingInstallDir := '';
    ExistingInstallVersion := '';
    ExistingUninstallCmd := '';

    RegDeleteValue(HKLM64, 'Software\Resistine', 'InstallDir');
    RegDeleteValue(HKLM64, 'Software\Resistine', 'Version');
    RegDeleteValue(HKLM, 'Software\Resistine', 'InstallDir');
    RegDeleteValue(HKLM, 'Software\Resistine', 'Version');
    exit;
  end;

  ExistingInstallDetected := ExistingUninstallerAvailable or ExistingAppExecutableAvailable;
end;

function RunExistingUninstaller(SilentMode: Boolean): Boolean;
var
  ExePath: string;
  Params: string;
  ResultCode: Integer;
  LowerExe: string;
begin
  Result := False;
  ExePath := ExtractExePathFromCommand(ExistingUninstallCmd);
  if (ExePath = '') or (not FileExists(ExePath)) then
  begin
    SuppressibleMsgBox(
      'An existing installation was detected, but its uninstaller could not be found.' + #13#10 +
      'Please uninstall Phoenix manually first.',
      mbError, MB_OK, IDOK);
    exit;
  end;

  LowerExe := LowerCase(ExtractFileName(ExePath));
  Params := '';
  if SilentMode then
  begin
    if Pos('unins', LowerExe) = 1 then
      Params := '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
    else if LowerExe = 'uninstall.exe' then
      Params := '/S';
  end;

  Log('Running existing uninstaller: ' + ExePath + ' ' + Params);
  if Exec(ExePath, Params, '', SW_SHOW, ewWaitUntilTerminated, ResultCode) then
  begin
    Log('Uninstaller exit code: ' + IntToStr(ResultCode));
    Result := (ResultCode = 0);
    if not Result then
      SuppressibleMsgBox('The existing uninstaller returned a non-zero exit code (' + IntToStr(ResultCode) + ').', mbError, MB_OK, IDOK);
  end
  else
  begin
    SuppressibleMsgBox('Failed to launch the existing uninstaller.', mbError, MB_OK, IDOK);
  end;
end;

function GetMaintenanceSummaryText: string;
var
  CompareResult: Integer;
  StatusLine: string;
begin
  StatusLine := 'Detected an existing Phoenix installation.';
  if ExistingInstallVersion <> '' then
  begin
    CompareResult := CompareVersionStrings(ExistingInstallVersion, '{#AppVersion}');
    if CompareResult < 0 then
      StatusLine := StatusLine + #13#10 + 'Installed version: ' + ExistingInstallVersion + ' (older than this installer)'
    else if CompareResult = 0 then
      StatusLine := StatusLine + #13#10 + 'Installed version: ' + ExistingInstallVersion + ' (same as this installer)'
    else
      StatusLine := StatusLine + #13#10 + 'Installed version: ' + ExistingInstallVersion + ' (newer than this installer)';
  end;

  if ExistingInstallDetected and (not ExistingUninstallerAvailable) then
    StatusLine := StatusLine + #13#10 + 'Uninstaller not found. Some maintenance actions are unavailable.';

  Result := StatusLine + #13#10 +
    'Installer version: {#AppVersion} (build {#AppBuild})' + #13#10 +
    'Install location: ' + ExistingInstallDir + #13#10#13#10 +
    'Choose an action below. A short description is shown under each option.';
end;

procedure InitializeWizard;
var
  NextTop: Integer;
begin
  SelectedAction := maInstall;
  CloseAfterMaintenanceUninstall := False;
  DetectExistingInstall;
  NormalizeExistingInstallState;

  if ExistingInstallDetected then
  begin
    MaintenancePage := CreateCustomPage(wpWelcome, 'Phoenix Is Already Installed', 'Choose how you want to continue');

    MaintenanceInfoLabel := TNewStaticText.Create(MaintenancePage);
    MaintenanceInfoLabel.Parent := MaintenancePage.Surface;
    MaintenanceInfoLabel.Left := 0;
    MaintenanceInfoLabel.Top := 0;
    MaintenanceInfoLabel.Width := MaintenancePage.SurfaceWidth;
    MaintenanceInfoLabel.Height := ScaleY(1);
    MaintenanceInfoLabel.AutoSize := False;
    MaintenanceInfoLabel.WordWrap := True;
    MaintenanceInfoLabel.Caption := GetMaintenanceSummaryText;
    WizardForm.AdjustLabelHeight(MaintenanceInfoLabel);
    NextTop := MaintenanceInfoLabel.Top + MaintenanceInfoLabel.Height + ScaleY(8);

    MaintenanceActionHeaderLabel := TNewStaticText.Create(MaintenancePage);
    MaintenanceActionHeaderLabel.Parent := MaintenancePage.Surface;
    MaintenanceActionHeaderLabel.Left := 0;
    MaintenanceActionHeaderLabel.Top := NextTop;
    MaintenanceActionHeaderLabel.Width := MaintenancePage.SurfaceWidth;
    MaintenanceActionHeaderLabel.Caption := 'Action';
    NextTop := MaintenanceActionHeaderLabel.Top + MaintenanceActionHeaderLabel.Height + ScaleY(2);

    InstallRadio := TRadioButton.Create(MaintenancePage);
    InstallRadio.Parent := MaintenancePage.Surface;
    InstallRadio.Left := 0;
    InstallRadio.Top := NextTop;
    InstallRadio.Width := MaintenancePage.SurfaceWidth;
    InstallRadio.Height := ScaleY(22);
    if ExistingUninstallerAvailable then
    begin
      InstallRadio.Caption := 'Install (not available)';
      InstallRadio.Enabled := False;
      InstallRadio.Checked := False;
    end
    else
    begin
      InstallRadio.Caption := 'Install';
      InstallRadio.Enabled := True;
      InstallRadio.Checked := True;
    end;
    InstallRadio.OnClick := @MaintenanceActionChanged;
    NextTop := InstallRadio.Top + InstallRadio.Height + ScaleY(1);

    ReinstallRadio := TRadioButton.Create(MaintenancePage);
    ReinstallRadio.Parent := MaintenancePage.Surface;
    ReinstallRadio.Left := 0;
    ReinstallRadio.Top := NextTop;
    ReinstallRadio.Width := MaintenancePage.SurfaceWidth;
    ReinstallRadio.Height := ScaleY(22);
    ReinstallRadio.Caption := 'Repair installation';
    ReinstallRadio.Enabled := ExistingUninstallerAvailable;
    ReinstallRadio.Checked := ExistingUninstallerAvailable;
    ReinstallRadio.OnClick := @MaintenanceActionChanged;
    NextTop := ReinstallRadio.Top + ReinstallRadio.Height + ScaleY(1);

    UninstallRadio := TRadioButton.Create(MaintenancePage);
    UninstallRadio.Parent := MaintenancePage.Surface;
    UninstallRadio.Left := 0;
    UninstallRadio.Top := NextTop;
    UninstallRadio.Width := MaintenancePage.SurfaceWidth;
    UninstallRadio.Height := ScaleY(22);
    UninstallRadio.Caption := 'Uninstall';
    UninstallRadio.Enabled := ExistingUninstallerAvailable;
    UninstallRadio.OnClick := @MaintenanceActionChanged;
    NextTop := UninstallRadio.Top + UninstallRadio.Height + ScaleY(1);

    MaintenanceActionDetailHeaderLabel := TNewStaticText.Create(MaintenancePage);
    MaintenanceActionDetailHeaderLabel.Parent := MaintenancePage.Surface;
    MaintenanceActionDetailHeaderLabel.Left := 0;
    MaintenanceActionDetailHeaderLabel.Top := NextTop + ScaleY(2);
    MaintenanceActionDetailHeaderLabel.Width := MaintenancePage.SurfaceWidth;
    MaintenanceActionDetailHeaderLabel.Caption := 'What this does';
    NextTop := MaintenanceActionDetailHeaderLabel.Top + MaintenanceActionDetailHeaderLabel.Height + ScaleY(2);

    MaintenanceActionDetailLabel := TNewStaticText.Create(MaintenancePage);
    MaintenanceActionDetailLabel.Parent := MaintenancePage.Surface;
    MaintenanceActionDetailLabel.Left := ScaleX(16);
    MaintenanceActionDetailLabel.Top := NextTop;
    MaintenanceActionDetailLabel.Width := MaintenancePage.SurfaceWidth - ScaleX(16);
    MaintenanceActionDetailLabel.AutoSize := False;
    MaintenanceActionDetailLabel.WordWrap := True;
    MaintenanceActionDetailLabel.Height := ScaleY(1);
    MaintenanceActionDetailLabel.Caption := '';
    WizardForm.AdjustLabelHeight(MaintenanceActionDetailLabel);
    NextTop := MaintenanceActionDetailLabel.Top + MaintenanceActionDetailLabel.Height + ScaleY(8);

    MaintenanceDataOptionsHeaderLabel := TNewStaticText.Create(MaintenancePage);
    MaintenanceDataOptionsHeaderLabel.Parent := MaintenancePage.Surface;
    MaintenanceDataOptionsHeaderLabel.Left := 0;
    MaintenanceDataOptionsHeaderLabel.Top := NextTop;
    MaintenanceDataOptionsHeaderLabel.Width := MaintenancePage.SurfaceWidth;
    MaintenanceDataOptionsHeaderLabel.Caption := 'Options';
    NextTop := MaintenanceDataOptionsHeaderLabel.Top + MaintenanceDataOptionsHeaderLabel.Height + ScaleY(2);

    MaintenanceDataOptionsEmptyLabel := TNewStaticText.Create(MaintenancePage);
    MaintenanceDataOptionsEmptyLabel.Parent := MaintenancePage.Surface;
    MaintenanceDataOptionsEmptyLabel.Left := ScaleX(16);
    MaintenanceDataOptionsEmptyLabel.Top := NextTop;
    MaintenanceDataOptionsEmptyLabel.Width := MaintenancePage.SurfaceWidth - ScaleX(16);
    MaintenanceDataOptionsEmptyLabel.AutoSize := False;
    MaintenanceDataOptionsEmptyLabel.WordWrap := True;
    MaintenanceDataOptionsEmptyLabel.Height := ScaleY(1);
    MaintenanceDataOptionsEmptyLabel.Caption := 'No additional options for this action.';
    WizardForm.AdjustLabelHeight(MaintenanceDataOptionsEmptyLabel);

    BackupSettingsCheck := TNewCheckBox.Create(MaintenancePage);
    BackupSettingsCheck.Parent := MaintenancePage.Surface;
    BackupSettingsCheck.Left := 0;
    BackupSettingsCheck.Top := NextTop;
    BackupSettingsCheck.Width := MaintenancePage.SurfaceWidth;
    BackupSettingsCheck.Height := ScaleY(22);
    BackupSettingsCheck.Caption := 'Back up data before repair';
    BackupSettingsCheck.Checked := True;
    BackupSettingsCheck.Enabled := HasAnyResistineUserData;
    NextTop := BackupSettingsCheck.Top + BackupSettingsCheck.Height + ScaleY(1);

    BackupHelpLabel := TNewStaticText.Create(MaintenancePage);
    BackupHelpLabel.Parent := MaintenancePage.Surface;
    BackupHelpLabel.Left := ScaleX(16);
    BackupHelpLabel.Top := NextTop;
    BackupHelpLabel.Width := MaintenancePage.SurfaceWidth - ScaleX(16);
    BackupHelpLabel.AutoSize := False;
    BackupHelpLabel.WordWrap := True;
    BackupHelpLabel.Height := ScaleY(1);
    if HasAnyResistineUserData then
      BackupHelpLabel.Caption := 'Recommended for Repair. Backs up settings and VPN data and restores them after reinstall when possible.'
    else
      BackupHelpLabel.Caption := 'No Phoenix user data was detected to back up.';
    WizardForm.AdjustLabelHeight(BackupHelpLabel);
    NextTop := BackupHelpLabel.Top + BackupHelpLabel.Height + ScaleY(6);

    RemoveUserDataCheck := TNewCheckBox.Create(MaintenancePage);
    RemoveUserDataCheck.Parent := MaintenancePage.Surface;
    RemoveUserDataCheck.Left := 0;
    RemoveUserDataCheck.Top := NextTop;
    RemoveUserDataCheck.Width := MaintenancePage.SurfaceWidth;
    RemoveUserDataCheck.Height := ScaleY(22);
    RemoveUserDataCheck.Caption := 'Remove user data on uninstall';
    RemoveUserDataCheck.Checked := False;
    RemoveUserDataCheck.Enabled := HasAnyResistineUserData;
    NextTop := RemoveUserDataCheck.Top + RemoveUserDataCheck.Height + ScaleY(1);

    RemoveUserDataHelpLabel := TNewStaticText.Create(MaintenancePage);
    RemoveUserDataHelpLabel.Parent := MaintenancePage.Surface;
    RemoveUserDataHelpLabel.Left := ScaleX(16);
    RemoveUserDataHelpLabel.Top := NextTop;
    RemoveUserDataHelpLabel.Width := MaintenancePage.SurfaceWidth - ScaleX(16);
    RemoveUserDataHelpLabel.AutoSize := False;
    RemoveUserDataHelpLabel.WordWrap := True;
    RemoveUserDataHelpLabel.Height := ScaleY(1);
    if HasAnyResistineUserData then
      RemoveUserDataHelpLabel.Caption := 'Deletes settings, logs, and VPN service data from user and common app-data folders.'
    else
      RemoveUserDataHelpLabel.Caption := 'No Phoenix user data was detected.';
    WizardForm.AdjustLabelHeight(RemoveUserDataHelpLabel);

    RefreshMaintenanceSelectionUI;

    if ExistingInstallDir <> '' then
      WizardForm.DirEdit.Text := ExistingInstallDir;
  end;

  PreflightPage := CreateCustomPage(wpSelectTasks, 'Pre-install Check', 'Review dependency and action status before installation starts');

  PreflightInfoLabel := TNewStaticText.Create(PreflightPage);
  PreflightInfoLabel.Parent := PreflightPage.Surface;
  PreflightInfoLabel.Left := 0;
  PreflightInfoLabel.Top := 0;
  PreflightInfoLabel.Width := PreflightPage.SurfaceWidth;
  PreflightInfoLabel.Height := ScaleY(1);
  PreflightInfoLabel.AutoSize := False;
  PreflightInfoLabel.WordWrap := True;
  PreflightInfoLabel.Caption := 'Review what setup will do before installation starts.';
  WizardForm.AdjustLabelHeight(PreflightInfoLabel);

  NextTop := PreflightInfoLabel.Top + PreflightInfoLabel.Height + ScaleY(10);

  PreflightActionHeaderLabel := TNewStaticText.Create(PreflightPage);
  PreflightActionHeaderLabel.Parent := PreflightPage.Surface;
  PreflightActionHeaderLabel.Left := 0;
  PreflightActionHeaderLabel.Top := NextTop;
  PreflightActionHeaderLabel.Width := PreflightPage.SurfaceWidth;
  PreflightActionHeaderLabel.Caption := 'Install summary';

  PreflightActionLabel := TNewStaticText.Create(PreflightPage);
  PreflightActionLabel.Parent := PreflightPage.Surface;
  PreflightActionLabel.Left := ScaleX(16);
  PreflightActionLabel.Top := PreflightActionHeaderLabel.Top + PreflightActionHeaderLabel.Height + ScaleY(2);
  PreflightActionLabel.Width := PreflightPage.SurfaceWidth - ScaleX(16);
  PreflightActionLabel.AutoSize := False;
  PreflightActionLabel.WordWrap := True;
  PreflightActionLabel.Height := ScaleY(1);
  PreflightActionLabel.Caption := '';

  PreflightChecksHeaderLabel := TNewStaticText.Create(PreflightPage);
  PreflightChecksHeaderLabel.Parent := PreflightPage.Surface;
  PreflightChecksHeaderLabel.Left := 0;
  PreflightChecksHeaderLabel.Top := PreflightActionLabel.Top + ScaleY(80);
  PreflightChecksHeaderLabel.Width := PreflightPage.SurfaceWidth;
  PreflightChecksHeaderLabel.Caption := 'System checks';

  PreflightChecksLabel := TNewStaticText.Create(PreflightPage);
  PreflightChecksLabel.Parent := PreflightPage.Surface;
  PreflightChecksLabel.Left := ScaleX(16);
  PreflightChecksLabel.Top := PreflightChecksHeaderLabel.Top + PreflightChecksHeaderLabel.Height + ScaleY(2);
  PreflightChecksLabel.Width := PreflightPage.SurfaceWidth - ScaleX(16);
  PreflightChecksLabel.AutoSize := False;
  PreflightChecksLabel.WordWrap := True;
  PreflightChecksLabel.Height := ScaleY(1);
  PreflightChecksLabel.Caption := '';

  PreflightTasksHeaderLabel := TNewStaticText.Create(PreflightPage);
  PreflightTasksHeaderLabel.Parent := PreflightPage.Surface;
  PreflightTasksHeaderLabel.Left := 0;
  PreflightTasksHeaderLabel.Top := PreflightChecksLabel.Top + ScaleY(120);
  PreflightTasksHeaderLabel.Width := PreflightPage.SurfaceWidth;
  PreflightTasksHeaderLabel.Caption := 'Selected options';

  PreflightTasksLabel := TNewStaticText.Create(PreflightPage);
  PreflightTasksLabel.Parent := PreflightPage.Surface;
  PreflightTasksLabel.Left := ScaleX(16);
  PreflightTasksLabel.Top := PreflightTasksHeaderLabel.Top + PreflightTasksHeaderLabel.Height + ScaleY(2);
  PreflightTasksLabel.Width := PreflightPage.SurfaceWidth - ScaleX(16);
  PreflightTasksLabel.AutoSize := False;
  PreflightTasksLabel.WordWrap := True;
  PreflightTasksLabel.Height := ScaleY(1);
  PreflightTasksLabel.Caption := '';

  RefreshPreflightSummary;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  ConfirmText: string;
  ExistingIsInno: Boolean;
begin
  Result := True;

  if ExistingInstallDetected then
  if CurPageID = MaintenancePage.ID then
  begin
    RefreshMaintenanceSelectionUI;

    if InstallRadio.Checked then
    begin
      SelectedAction := maInstall;
      RemoveUserDataAfterUninstall := False;
      exit;
    end;

    if ReinstallRadio.Checked then
    begin
      SelectedAction := maReinstall;

      RemoveUserDataAfterUninstall := False;
      if not BackupDataForReinstall then
      begin
        Result := False;
        exit;
      end;

      ExistingIsInno := ExistingUninstallerLooksLikeInno;
      if ExistingIsInno then
        SetInstallerUninstallInteropFlags(False);
      Result := RunExistingUninstaller(True);
      if not Result and ExistingIsInno then
        ClearInstallerUninstallInteropFlags;
      if Result then
        Sleep(1000);
      exit;
    end;

    if UninstallRadio.Checked then
    begin
      SelectedAction := maUninstall;
      RemoveUserDataAfterUninstall := True;

      ConfirmText :=
        'This will uninstall the existing Phoenix installation and close setup.' + #13#10#13#10 +
        'What will be removed:' + #13#10 +
        '- Application files in: ' + ExistingInstallDir + #13#10 +
        '- Start Menu / desktop shortcuts' + #13#10 +
        '- VPN services: ResistineVPN, WireGuardTunnel$resistine, WireGuardTunnel$resistine_default, WireGuardTunnel$resistine_vpn' + #13#10 +
        '- All user data: settings, email, login, logs, and VPN service data' + #13#10 +
        '  (' + GetResistineUserDataDir + ' and ' + GetResistineCommonDataDir + ')' + #13#10 + #13#10 +
        'Continue?';

      if SuppressibleMsgBox(ConfirmText, mbConfirmation, MB_YESNO, IDNO) = IDYES then
      begin
        ExistingIsInno := ExistingUninstallerLooksLikeInno;
        if ExistingIsInno then
          SetInstallerUninstallInteropFlags(True);
        if RunExistingUninstaller(False) then
        begin
          if not ExistingIsInno then
            DeleteResistineUserData;

          if not ExistingIsInno then
          begin
            SuppressibleMsgBox('Uninstall completed and all user data was removed. Setup will now exit.', mbInformation, MB_OK, IDOK);
          end;

          CloseAfterMaintenanceUninstall := True;
          WizardForm.Close;
        end;
        if ExistingIsInno then
          ClearInstallerUninstallInteropFlags;
      end;
      Result := False;
      exit;
    end;
  end;
end;

procedure CancelButtonClick(CurPageID: Integer; var Cancel, Confirm: Boolean);
begin
  if CloseAfterMaintenanceUninstall then
  begin
    Cancel := True;
    Confirm := False;
  end;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;

  { Silent mode (WinSparkle upgrade): skip maintenance page, just overwrite }
  if WizardSilent and ExistingInstallDetected then
  begin
    SelectedAction := maInstall;
    if (MaintenancePage <> nil) and (PageID = MaintenancePage.ID) then
    begin
      Result := True;
      exit;
    end;
  end;

  if ExistingInstallDetected and (SelectedAction = maUninstall) and
     ((PageID = wpSelectTasks) or (PageID = wpReady) or (PageID = wpInstalling) or
      ((PreflightPage <> nil) and (PageID = PreflightPage.ID))) then
    Result := True;
end;

function ShouldPerformInstallAction: Boolean;
begin
  Result := SelectedAction <> maUninstall;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if (MaintenancePage <> nil) and (CurPageID = MaintenancePage.ID) then
    RefreshMaintenanceSelectionUI;

  if (PreflightPage <> nil) and (CurPageID = PreflightPage.ID) then
    RefreshPreflightSummary;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if not EnsureResistineClosedForInstall then
    Result := 'Phoenix must be closed before installation can continue.';
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep <> ssPostInstall then
    exit;

  if not ShouldPerformInstallAction then
    exit;

  { File extraction is done (the bar is full), but the steps below still run for
    several seconds — installing missing prerequisites and registering the VPN
    service. Switch the bar to an animated marquee and show a status caption for
    each step so the wizard clearly reads as "working" instead of frozen. }
  WizardForm.ProgressGauge.Style := npbstMarquee;
  try
    SetInstallStatus('Finishing setup...');
    RestoreDataAfterReinstallIfNeeded;
    ApplyStartupTaskSelection;
    InstallMissingDependenciesWithFeedback;
    RunVpnServiceSetupRequired;
  finally
    WizardForm.ProgressGauge.Style := npbstNormal;
    WizardForm.ProgressGauge.Position := WizardForm.ProgressGauge.Max;
    SetInstallStatus('Finishing installation...');
  end;
end;

function InitializeUninstall(): Boolean;
var
  Summary: string;
  Response: Integer;
begin
  Result := True;
  LoadInstallerUninstallInteropFlags;

  if not EnsureResistineClosedForUninstall then
  begin
    Result := False;
    exit;
  end;

  if MaintenanceUninstallByInstaller then
    exit;

  Summary :=
    'This will uninstall Phoenix from:' + #13#10 +
    ExpandConstant('{app}') + #13#10#13#10 +
    'The uninstaller will remove:' + #13#10 +
    '- ResistineVPN service' + #13#10 +
    '- WireGuardTunnel$resistine' + #13#10 +
    '- WireGuardTunnel$resistine_default' + #13#10 +
    '- WireGuardTunnel$resistine_vpn' + #13#10 +
    '- Wazuh agent (WazuhSvc)' + #13#10 +
    '- Sysmon monitoring service' + #13#10 +
    '- All user data (settings, email, login, logs, and VPN configs):' + #13#10 +
    '  ' + GetResistineUserDataDir + #13#10 +
    '  ' + GetResistineCommonDataDir + #13#10#13#10 +
    'Continue?';

  Response := SuppressibleMsgBox(Summary, mbConfirmation, MB_YESNO, IDYES);
  if Response <> IDYES then
  begin
    Result := False;
    exit;
  end;

  { Always remove user data on uninstall }
  StandaloneUninstallRemoveUserData := True;
end;

procedure RemoveWazuhAndSysmon;
var
  ResultCode: Integer;
begin
  { Stop and uninstall Wazuh agent }
  if HiddenCmdSucceeded('sc query WazuhSvc >nul 2>nul') or
     DirExists('C:\Program Files (x86)\ossec-agent') then
  begin
    Log('Uninstall cleanup: stopping WazuhSvc');
    RunHiddenCmd('sc stop WazuhSvc >nul 2>nul', ResultCode);
    WaitForServiceStoppedOrAbsent('WazuhSvc', 15, 1000);

    { Uninstall via the MSI product registered in the Uninstall registry hive.
      wmic is deprecated and absent on newer Windows 11 builds, so resolve the
      product GUID from the registry and drive msiexec directly. }
    Log('Uninstall cleanup: uninstalling Wazuh agent MSI');
    RunHiddenCmd(
      'powershell -NoProfile -Command "' +
      '$app = Get-ItemProperty ' +
      '''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'',' +
      '''HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'' ' +
      '-ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like ''*Wazuh*'' } | ' +
      'Select-Object -First 1; ' +
      'if ($app) { Start-Process msiexec.exe -ArgumentList ''/x'',$app.PSChildName,''/qn'',''/norestart'' -Wait }" >nul 2>nul',
      ResultCode);

    { Fallback to wmic on older systems where it is still available. }
    if HiddenCmdSucceeded('sc query WazuhSvc >nul 2>nul') then
      RunHiddenCmd(
        'wmic product where "Name like ''%Wazuh%''" call uninstall /nointeractive >nul 2>nul',
        ResultCode);

    { Guarantee the service registration is gone even if the MSI left it. }
    StopAndDeleteService('WazuhSvc');
    Log('Wazuh uninstall complete');
  end;

  { Remove Sysmon/Defender localfile blocks from ossec.conf }
  if FileExists('C:\Program Files (x86)\ossec-agent\ossec.conf') then
  begin
    Log('Uninstall cleanup: removing Resistine entries from ossec.conf');
    RunHiddenCmd(
      'powershell -NoProfile -Command "$c = Get-Content ''C:\Program Files (x86)\ossec-agent\ossec.conf'' -Raw; ' +
      '$c = $c -replace ''(?s)\s*<localfile>\s*<location>Microsoft-Windows-Sysmon/Operational</location>\s*<log_format>eventchannel</log_format>\s*</localfile>'', ''''; ' +
      '$c = $c -replace ''(?s)\s*<localfile>\s*<location>Microsoft-Windows-Windows Defender/Operational</location>\s*<log_format>eventchannel</log_format>\s*</localfile>'', ''''; ' +
      'Set-Content ''C:\Program Files (x86)\ossec-agent\ossec.conf'' $c -Encoding UTF8" >nul 2>nul',
      ResultCode);
  end;

  { Stop and uninstall Sysmon (try 64-bit then 32-bit service name) }
  if HiddenCmdSucceeded('sc query Sysmon64 >nul 2>nul') then
  begin
    Log('Uninstall cleanup: removing Sysmon64');
    RunHiddenCmd(
      'if exist "%ProgramFiles%\Resistine\Sysmon\Sysmon64.exe" ' +
      '"%ProgramFiles%\Resistine\Sysmon\Sysmon64.exe" -u force >nul 2>nul',
      ResultCode);
  end
  else if HiddenCmdSucceeded('sc query Sysmon >nul 2>nul') then
  begin
    Log('Uninstall cleanup: removing Sysmon');
    RunHiddenCmd(
      'if exist "%ProgramFiles%\Resistine\Sysmon\Sysmon.exe" ' +
      '"%ProgramFiles%\Resistine\Sysmon\Sysmon.exe" -u force >nul 2>nul',
      ResultCode);
  end;

  { Remove Resistine Sysmon directory }
  DeleteDirectoryIfExists(ExpandConstant('{pf}\Resistine\Sysmon'));

  { Remove any leftover Wazuh agent directory so the SIEM state is fully clean
    and a fresh install re-enrolls from scratch. }
  DeleteDirectoryIfExists('C:\Program Files (x86)\ossec-agent');
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    RemoveResistineVpnServicesAndTunnels;
    RemoveWazuhAndSysmon;
  end;

  if CurUninstallStep = usPostUninstall then
  begin
    { Remove keyring credentials (master key + update signing key) }
    RunHiddenCmd('cmdkey /delete:phoenix-master-key >nul 2>nul', ResultCode);
    RunHiddenCmd('cmdkey /delete:resistine-master-key >nul 2>nul', ResultCode);
    RunHiddenCmd('cmdkey /delete:resistine-updates >nul 2>nul', ResultCode);

    { Always remove user data and configs on uninstall }
    DeleteResistineUserData;

    { Remove all Resistine registry keys }
    RegDeleteKeyIncludingSubkeys(HKLM64, 'Software\Resistine');
    RegDeleteKeyIncludingSubkeys(HKLM, 'Software\Resistine');
    RegDeleteKeyIncludingSubkeys(HKCU, 'Software\Resistine');
  end;
end;
