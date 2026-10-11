@echo off
:: ============================================================
:: Phoenix (formerly Resistine) — Full Uninstaller
:: Removes services, configs, registry entries, and data dirs.
:: ============================================================
setlocal EnableDelayedExpansion

set SCRIPT_DIR=%~dp0
if "%SCRIPT_DIR:~-1%"=="\" set SCRIPT_DIR=%SCRIPT_DIR:~0,-1%

set SERVICE_NAME=ResistineVPN

:: Project root is always two levels up from scripts\uninstall\.
for %%I in ("%SCRIPT_DIR%\..\..") do set PROJECT_ROOT=%%~fI

:: Try bundled-installer layout first, then fall back to the project-root layout.
set SERVICE_SCRIPT=%SCRIPT_DIR%\windows_vpn_service.py
if not exist "%SERVICE_SCRIPT%" set SERVICE_SCRIPT=%SCRIPT_DIR%\plugins\vpn\wireguard\windows_vpn_service.py
if not exist "%SERVICE_SCRIPT%" set SERVICE_SCRIPT=%PROJECT_ROOT%\plugins\vpn\wireguard\windows_vpn_service.py
set VENV_DIR=%PROJECT_ROOT%\.venv
set VENV_PYTHON=%VENV_DIR%\Scripts\python.exe
set APPDATA_DIR=%APPDATA%\Phoenix
set LEGACY_APPDATA_DIR=%APPDATA%\Resistine
set WG_DIR=%APPDATA_DIR%\wireguard
set PROGRAMDATA_DIR=%PROGRAMDATA%\Resistine
set PROGRAMDATA_WG=%PROGRAMDATA_DIR%\wireguard
set SHORTCUT=%USERPROFILE%\Desktop\Resistine VPN.lnk
set SHORTCUT2=%USERPROFILE%\Desktop\Resistine.lnk
set SHORTCUT3=%USERPROFILE%\Desktop\Phoenix VPN.lnk
set SHORTCUT4=%USERPROFILE%\Desktop\Phoenix.lnk
set WG_EXE=%PROGRAMFILES%\WireGuard\wireguard.exe

:: ============================================================
:: Jump to service section if elevated
:: ============================================================
if "%1"=="/service" goto :remove_service

:: ============================================================
:: PART 1 — User level
:: ============================================================
echo ============================================================
echo  Phoenix Full Uninstaller
echo ============================================================
echo.

:: ---- Kill all Phoenix processes ----
echo [1/6] Stopping Phoenix processes...
powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='python.exe' OR Name='pythonw.exe'\" | Where-Object { $_.CommandLine -like '*tray.py*' -or $_.CommandLine -like '*main.py*' -or $_.CommandLine -like '*Resistine*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }" >nul 2>&1
taskkill /F /IM "Resistine.exe" >nul 2>&1
echo       OK

:: ---- Remove startup registry entries (HKCU) ----
echo [2/6] Removing user startup entries...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "ResistineVPNTray" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "ResistineVPN" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Resistine" /f >nul 2>&1
echo       OK

:: ---- Remove desktop shortcuts ----
echo [3/6] Removing desktop shortcuts...
if exist "%SHORTCUT%" del "%SHORTCUT%" >nul 2>&1
if exist "%SHORTCUT2%" del "%SHORTCUT2%" >nul 2>&1
if exist "%SHORTCUT3%" del "%SHORTCUT3%" >nul 2>&1
if exist "%SHORTCUT4%" del "%SHORTCUT4%" >nul 2>&1
echo       OK

:: ---- Remove user config and data ----
echo [4/6] Removing user config and data...
if exist "%APPDATA_DIR%" (
    rmdir /s /q "%APPDATA_DIR%"
    echo       Removed: %APPDATA_DIR%
) else (
    echo       Not found: %APPDATA_DIR%
)
if exist "%LEGACY_APPDATA_DIR%" rmdir /s /q "%LEGACY_APPDATA_DIR%"
echo       OK

:: ---- Remove venv ----
echo [5/6] Removing virtual environment...
if exist "%VENV_DIR%" (
    rmdir /s /q "%VENV_DIR%"
    echo       Removed: %VENV_DIR%
) else (
    echo       Not found, skipping
)
echo       OK

:: ---- Find system Python to pass to elevated section ----
set PYTHON_FULL=
for /f "tokens=*" %%i in ('py -3 -c "import sys; print(sys.executable)" 2^>nul') do (
    if not defined PYTHON_FULL set PYTHON_FULL=%%i
)
if not defined PYTHON_FULL (
    for /f "tokens=*" %%i in ('where python 2^>nul') do (
        echo %%i | findstr /i "WindowsApps" >nul 2>&1
        if !errorlevel! neq 0 if not defined PYTHON_FULL set PYTHON_FULL=%%i
    )
)

if defined PYTHON_FULL (
    echo %PYTHON_FULL%> "%TEMP%\resistine_python_path.txt"
)

:: ---- Remove services + system data (needs admin) ----
echo [6/6] Removing services and system data ^(requires Admin^)...
set "SERVICE_LOG=%PROGRAMDATA_DIR%\uninstall_service.log"
set "UNINSTALL_WRAPPER=%TEMP%\resistine_uninstall_service_wrapper.bat"
if not exist "%PROGRAMDATA_DIR%" mkdir "%PROGRAMDATA_DIR%" >nul 2>&1
> "%UNINSTALL_WRAPPER%" echo @echo off
>> "%UNINSTALL_WRAPPER%" echo call "%~f0" /service ^> "%SERVICE_LOG%" 2^>^&1
powershell -Command "Start-Process -FilePath '%UNINSTALL_WRAPPER%' -Verb RunAs -Wait"
if %errorlevel% neq 0 (
    echo WARNING: Service removal failed or was cancelled.
)
del "%UNINSTALL_WRAPPER%" >nul 2>&1

del "%TEMP%\resistine_python_path.txt" >nul 2>&1

echo.
echo ============================================================
echo  Uninstall complete. All Phoenix data has been removed.
echo ============================================================
echo.
exit /b 0


:: ============================================================
:: SERVICE REMOVAL + SYSTEM CLEANUP (elevated)
:: ============================================================
:remove_service
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Not running as Administrator.
    pause & exit /b 1
)

echo ============================================================
echo  Removing Phoenix Services and System Data ^(Admin^)
echo ============================================================

:: Read system Python path from temp file
set SYS_PYTHON=
if exist "%TEMP%\resistine_python_path.txt" (
    set /p SYS_PYTHON= < "%TEMP%\resistine_python_path.txt"
)

:: Fallback: search again if temp file missing
if not defined SYS_PYTHON (
    for /f "tokens=*" %%i in ('where python 2^>nul') do (
        echo %%i | findstr /i "WindowsApps" >nul 2>&1
        if !errorlevel! neq 0 if not defined SYS_PYTHON set SYS_PYTHON=%%i
    )
)

if defined SYS_PYTHON (
    echo       Using Python: %SYS_PYTHON%
) else (
    echo WARNING: System Python not found. Will fall back to sc delete.
)

:: ---- Discover and remove all WireGuard tunnels ----
echo Removing WireGuard tunnels...
if exist "%WG_EXE%" (
    :: Tunnels from ProgramData
    if exist "%PROGRAMDATA_WG%" (
        for %%f in ("%PROGRAMDATA_WG%\*.conf") do (
            set TUNNEL=%%~nf
            echo       Removing tunnel: !TUNNEL!
            "%WG_EXE%" /uninstalltunnelservice "!TUNNEL!" >nul 2>&1
            sc stop   "WireGuardTunnel$!TUNNEL!" >nul 2>&1
            sc delete "WireGuardTunnel$!TUNNEL!" >nul 2>&1
        )
    )

    :: Tunnels from AppData
    if exist "%WG_DIR%" (
        for %%f in ("%WG_DIR%\*.conf") do (
            set TUNNEL=%%~nf
            echo       Removing tunnel: !TUNNEL!
            "%WG_EXE%" /uninstalltunnelservice "!TUNNEL!" >nul 2>&1
            sc stop   "WireGuardTunnel$!TUNNEL!" >nul 2>&1
            sc delete "WireGuardTunnel$!TUNNEL!" >nul 2>&1
        )
    )

    :: Any remaining WireGuard tunnel services
    for /f "tokens=2" %%s in ('sc query type^= all state^= all 2^>nul ^| findstr /i "WireGuardTunnel"') do (
        echo       Removing discovered tunnel: %%s
        sc stop   "%%s" >nul 2>&1
        sc delete "%%s" >nul 2>&1
        "%WG_EXE%" /uninstalltunnelservice "%%s" >nul 2>&1
    )
) else (
    echo       WireGuard not found, skipping tunnel removal
)
echo       OK

:: ---- Stop and remove ResistineVPN service ----
echo Removing ResistineVPN service...
sc query %SERVICE_NAME% >nul 2>&1
if %errorlevel% neq 0 goto :vpn_service_not_present

echo       Stopping service...
sc stop %SERVICE_NAME% >nul 2>&1
call :wait_for_stopped 30

echo       Removing service...
if defined SYS_PYTHON (
    "%SYS_PYTHON%" "%SERVICE_SCRIPT%" remove >nul 2>&1
) else if exist "%VENV_PYTHON%" (
    "%VENV_PYTHON%" "%SERVICE_SCRIPT%" remove >nul 2>&1
)
sc delete %SERVICE_NAME% >nul 2>&1
call :wait_for_absence 10
goto :vpn_service_done

:vpn_service_not_present
echo       Not found, skipping

:vpn_service_done

:: ---- Stop and remove Wazuh agent service + MSI ----
echo Removing Wazuh agent...
sc query WazuhSvc >nul 2>&1
if %errorlevel% neq 0 goto :wazuh_not_present
echo       Stopping WazuhSvc...
sc stop WazuhSvc >nul 2>&1
timeout /t 5 /nobreak >nul
sc delete WazuhSvc >nul 2>&1
echo       OK - WazuhSvc removed
:: Uninstall the Wazuh MSI package
echo       Uninstalling Wazuh agent MSI...
wmic product where "Name like '%%Wazuh%%'" call uninstall /nointeractive >nul 2>&1
if exist "C:\Program Files (x86)\ossec-agent" (
    rmdir /s /q "C:\Program Files (x86)\ossec-agent" >nul 2>&1
    echo       Removed ossec-agent directory
)
echo       OK
goto :wazuh_done
:wazuh_not_present
echo       Service not found, checking for leftover files...
if exist "C:\Program Files (x86)\ossec-agent" (
    wmic product where "Name like '%%Wazuh%%'" call uninstall /nointeractive >nul 2>&1
    rmdir /s /q "C:\Program Files (x86)\ossec-agent" >nul 2>&1
    echo       Removed ossec-agent directory
) else (
    echo       Not found, skipping
)
:wazuh_done

:: ---- Remove Sysmon/Defender blocks from ossec.conf ----
echo Cleaning Resistine entries from ossec.conf...
set "OSSEC_CONF=C:\Program Files (x86)\ossec-agent\ossec.conf"
if exist "%OSSEC_CONF%" (
    powershell -NoProfile -Command "$c = Get-Content '%OSSEC_CONF%' -Raw; $c = $c -replace '(?s)\s*<localfile>\s*<location>Microsoft-Windows-Sysmon/Operational</location>\s*<log_format>eventchannel</log_format>\s*</localfile>', ''; $c = $c -replace '(?s)\s*<localfile>\s*<location>Microsoft-Windows-Windows Defender/Operational</location>\s*<log_format>eventchannel</log_format>\s*</localfile>', ''; Set-Content '%OSSEC_CONF%' $c -Encoding UTF8" >nul 2>&1
    echo       OK
) else (
    echo       ossec.conf not found, skipping
)

:: ---- Stop and remove Sysmon service ----
echo Removing Sysmon service...
sc query Sysmon64 >nul 2>&1
if %errorlevel% neq 0 goto :sysmon_not_present
echo       Stopping Sysmon64...
sc stop Sysmon64 >nul 2>&1
timeout /t 3 /nobreak >nul
:: Use Sysmon's own uninstall if available
set "SYSMON_EXE=%PROGRAMFILES%\Resistine\Sysmon\Sysmon64.exe"
if exist "%SYSMON_EXE%" (
    "%SYSMON_EXE%" -u force >nul 2>&1
) else (
    sc delete Sysmon64 >nul 2>&1
)
echo       OK - Sysmon removed
goto :sysmon_done
:sysmon_not_present
echo       Not found, skipping
:sysmon_done

:: ---- Remove keyring credentials ----
echo Removing stored credentials...
if defined SYS_PYTHON (
    "%SYS_PYTHON%" -c "import keyring; keyring.delete_password('phoenix-master-key', 'master-key')" >nul 2>&1
    "%SYS_PYTHON%" -c "import keyring; keyring.delete_password('resistine-master-key', 'master-key')" >nul 2>&1
    "%SYS_PYTHON%" -c "import keyring; keyring.delete_password('resistine-updates', 'resistine-updates')" >nul 2>&1
)
cmdkey /delete:phoenix-master-key >nul 2>&1
cmdkey /delete:resistine-master-key >nul 2>&1
cmdkey /delete:resistine-updates >nul 2>&1
echo       OK

:: ---- Remove startup registry entries (HKLM, requires admin) ----
echo Removing system startup and registry entries...
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "ResistineVPNTray" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "ResistineVPN" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Resistine" /f >nul 2>&1

:: Remove Resistine registry keys
reg delete "HKLM\Software\Resistine" /f >nul 2>&1
reg delete "HKCU\Software\Resistine" /f >nul 2>&1
echo       OK

:: ---- Remove ProgramData ----
echo Removing system data...
if exist "%PROGRAMDATA_DIR%" (
    rmdir /s /q "%PROGRAMDATA_DIR%"
    echo       Removed: %PROGRAMDATA_DIR%
) else (
    echo       Not found: %PROGRAMDATA_DIR%
)

:: Remove Sysmon directory
set "SYSMON_DIR=%PROGRAMFILES%\Resistine\Sysmon"
if exist "%SYSMON_DIR%" (
    rmdir /s /q "%SYSMON_DIR%"
    echo       Removed: %SYSMON_DIR%
)

:: Remove Resistine under Program Files if empty
set "PF_RESISTINE=%PROGRAMFILES%\Resistine"
if exist "%PF_RESISTINE%" (
    rmdir "%PF_RESISTINE%" >nul 2>&1
)
echo       OK

echo.
echo ============================================================
echo  Service removal and system cleanup complete.
echo ============================================================
exit /b 0


:: ============================================================
:: Subroutine: wait_for_stopped <max_seconds>
:: ============================================================
:wait_for_stopped
set /a _WAIT_MAX=%~1
set /a _WAIT_COUNT=0
:_wait_stopped_iter
sc query %SERVICE_NAME% | findstr /C:"STOPPED" >nul 2>&1
if %errorlevel% equ 0 goto :_wait_stopped_done
if !_WAIT_COUNT! geq !_WAIT_MAX! goto :_wait_stopped_timeout
set /a _WAIT_COUNT+=1
echo       Waiting for STOPPED state... ^(!_WAIT_COUNT!/!_WAIT_MAX!^)
timeout /t 1 /nobreak >nul
goto :_wait_stopped_iter
:_wait_stopped_timeout
echo WARNING: Service did not reach STOPPED in !_WAIT_MAX! seconds; proceeding anyway.
:_wait_stopped_done
goto :eof


:: ============================================================
:: Subroutine: wait_for_absence <max_seconds>
:: ============================================================
:wait_for_absence
set /a _ABS_MAX=%~1
set /a _ABS_COUNT=0
:_wait_absence_iter
sc query %SERVICE_NAME% >nul 2>&1
if %errorlevel% neq 0 goto :_wait_absence_gone
if !_ABS_COUNT! geq !_ABS_MAX! goto :_wait_absence_timeout
set /a _ABS_COUNT+=1
echo       Waiting for cleanup... ^(!_ABS_COUNT!/!_ABS_MAX!^)
timeout /t 1 /nobreak >nul
goto :_wait_absence_iter
:_wait_absence_timeout
echo WARNING: Service still registered after !_ABS_MAX! seconds.
echo          It may be marked for deletion; a reboot will complete removal.
goto :eof
:_wait_absence_gone
echo       OK - Service removed
goto :eof
