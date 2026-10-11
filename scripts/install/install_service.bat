@echo off
:: ============================================================
:: Phoenix VPN Service Installer
:: Must be run as Administrator
:: ============================================================

setlocal EnableDelayedExpansion

set "QUIET_MODE="
set "UNINSTALL_MODE="
for %%A in (%*) do (
    if /I "%%~A"=="/quiet" set "QUIET_MODE=1"
    if /I "%%~A"=="/uninstall" set "UNINSTALL_MODE=1"
    if /I "%%~A"=="/uninstallquiet" (
        set "UNINSTALL_MODE=1"
        set "QUIET_MODE=1"
    )
)

:: ---- Config ----
set SERVICE_NAME=ResistineVPN
set SCRIPT_DIR=%~dp0
if "%SCRIPT_DIR:~-1%"=="\" set SCRIPT_DIR=%SCRIPT_DIR:~0,-1%

:: Project root is always two levels up from scripts\install\.
:: Resolved unconditionally so the fallback SERVICE_SCRIPT paths below work
:: correctly — the previous conditional-block version had a parse-time bug
:: where %PROJECT_ROOT% was expanded before it was set.
for %%I in ("%SCRIPT_DIR%\..\..") do set PROJECT_ROOT=%%~fI

:: Try bundled-installer layout first, then fall back to project-root location.
set SERVICE_SCRIPT=%SCRIPT_DIR%\windows_vpn_service.py
if not exist "%SERVICE_SCRIPT%" set SERVICE_SCRIPT=%SCRIPT_DIR%\plugins\vpn\wireguard\windows_vpn_service.py
if not exist "%SERVICE_SCRIPT%" set SERVICE_SCRIPT=%PROJECT_ROOT%\plugins\vpn\wireguard\windows_vpn_service.py
set PROGRAMDATA_DIR=%PROGRAMDATA%\Resistine\wireguard
set LOG_DIR=%PROGRAMDATA%\Resistine
set SERVICE_SETUP_LOG=%LOG_DIR%\vpn_service_install.log

if not exist "%SERVICE_SCRIPT%" (
    echo ERROR: Service script not found.
    echo Last path tried: %SERVICE_SCRIPT%
    echo Project root:    %PROJECT_ROOT%
    echo Script dir:      %SCRIPT_DIR%
    echo.
    echo If you are running an installed copy, the installer package may be missing the service script.
    echo Rebuild the installer after bundling windows_vpn_service.py, or run this script from the project root.
    call :pause_if_needed
    exit /b 1
)

if defined UNINSTALL_MODE goto :uninstall_service

:: ============================================================
:: 1. Check Admin
:: ============================================================
echo [1/6] Checking administrator privileges...
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script must be run as Administrator.
    echo Right-click install_service.bat and select "Run as administrator"
    call :pause_if_needed
    exit /b 1
)
echo       OK - Running as Administrator

:: ============================================================
:: 2. Find real Python (skip WindowsApps stub)
:: ============================================================
echo [2/6] Locating Python installation...
set PYTHON_FULL=

:: Try py launcher first — it returns the newest installed version
for /f "tokens=*" %%i in ('py -3 -c "import sys; print(sys.executable)" 2^>nul') do (
    if not defined PYTHON_FULL set PYTHON_FULL=%%i
)

:: Fall back to PATH if py launcher not available
if not defined PYTHON_FULL (
    for /f "tokens=*" %%i in ('where python 2^>nul') do (
        echo %%i | findstr /i "WindowsApps" >nul 2>&1
        if !errorlevel! neq 0 (
            if not defined PYTHON_FULL set PYTHON_FULL=%%i
        )
    )
)

if not defined PYTHON_FULL (
    for %%v in (313 312 311 310) do (
        if not defined PYTHON_FULL (
            for %%p in (
                "%LOCALAPPDATA%\Programs\Python\Python%%v\python.exe"
                "%PROGRAMFILES%\Python%%v\python.exe"
                "%PROGRAMFILES(x86)%\Python%%v\python.exe"
            ) do (
                if exist %%p (
                    if not defined PYTHON_FULL (
                        set PYTHON_FULL=%%~p
                    )
                )
            )
        )
    )
)

if not defined PYTHON_FULL (
    echo ERROR: Could not find a real Python installation.
    echo Please install Python 3.10+ from https://www.python.org/downloads/
    call :pause_if_needed
    exit /b 1
)

"%PYTHON_FULL%" --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python at %PYTHON_FULL% failed to run.
    call :pause_if_needed
    exit /b 1
)

for /f "tokens=*" %%i in ('"%PYTHON_FULL%" --version') do echo       %%i
echo       Path: %PYTHON_FULL%
echo       OK

:: ============================================================
:: 3. Check WireGuard
:: ============================================================
echo [3/6] Checking WireGuard installation...
set "WG_EXE="
if exist "%PROGRAMFILES%\WireGuard\wireguard.exe" set "WG_EXE=%PROGRAMFILES%\WireGuard\wireguard.exe"
if not defined WG_EXE if exist "%PROGRAMFILES(x86)%\WireGuard\wireguard.exe" set "WG_EXE=%PROGRAMFILES(x86)%\WireGuard\wireguard.exe"
if not defined WG_EXE (
    echo ERROR: WireGuard not found.
    echo Please install from https://www.wireguard.com/install/
    call :pause_if_needed
    exit /b 1
)
echo       OK - WireGuard found at %WG_EXE%

:: ============================================================
:: 4. Install Python dependencies
:: ============================================================
echo [4/6] Installing Python dependencies...

"%PYTHON_FULL%" -m pip install --quiet --upgrade pip

set SERVICE_DEPS=pywin32 pywin32-ctypes

for %%d in (%SERVICE_DEPS%) do (
    echo       Installing %%d...
    "%PYTHON_FULL%" -m pip install --quiet %%d
    if !errorlevel! neq 0 (
        echo ERROR: Failed to install %%d
        call :pause_if_needed
        exit /b 1
    )
)

:: pywin32 post-install
echo       Running pywin32 post-install...
set "PYWIN32_POSTINSTALL_OK="
"%PYTHON_FULL%" -m pywin32_postinstall -install >nul 2>&1
if !errorlevel! equ 0 (
    set "PYWIN32_POSTINSTALL_OK=1"
) else (
    "%PYTHON_FULL%" -c "import sys, pathlib; p = pathlib.Path(sys.prefix) / 'Scripts' / 'pywin32_postinstall.py'; print(p)" > "%TEMP%\resistine_pywin32_postinstall_path.txt" 2>nul
    if exist "%TEMP%\resistine_pywin32_postinstall_path.txt" (
        set /p PYWIN32_POSTINSTALL_SCRIPT=<"%TEMP%\resistine_pywin32_postinstall_path.txt"
        del "%TEMP%\resistine_pywin32_postinstall_path.txt" >nul 2>&1
        if exist "%PYWIN32_POSTINSTALL_SCRIPT%" (
            "%PYTHON_FULL%" "%PYWIN32_POSTINSTALL_SCRIPT%" -install >nul 2>&1
            if !errorlevel! equ 0 set "PYWIN32_POSTINSTALL_OK=1"
        )
    )
)
if defined PYWIN32_POSTINSTALL_OK (
    echo       OK - pywin32 post-install complete
) else (
    echo WARNING: pywin32 post-install step failed or was not found.
    echo          The service may still work, but if it fails to start, rerun this script.
)
echo       OK - Dependencies installed

:: ============================================================
:: 5. Create ProgramData directories
:: ============================================================
echo [5/6] Creating service directories...
if not exist "%PROGRAMDATA_DIR%" (
    mkdir "%PROGRAMDATA_DIR%"
    echo       Created: %PROGRAMDATA_DIR%
) else (
    echo       Exists:  %PROGRAMDATA_DIR%
)
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"
echo       OK

:: ============================================================
:: 6. Install / reinstall Windows service
:: ============================================================
echo [6/6] Installing Windows service...

:: Stop and remove if exists
sc query %SERVICE_NAME% >nul 2>&1
if %errorlevel% equ 0 (
    echo       Stopping existing service...
    sc stop %SERVICE_NAME% >nul 2>&1
    timeout /t 3 /nobreak >nul
    echo       Removing existing service...
    "%PYTHON_FULL%" "%SERVICE_SCRIPT%" remove >nul 2>&1
    call :wait_for_named_service_absent %SERVICE_NAME% 15
)

:: Install
echo       Registering service...
if exist "%SERVICE_SETUP_LOG%" del "%SERVICE_SETUP_LOG%" >nul 2>&1
set "SERVICE_INSTALL_EXIT="
set /a INSTALL_ATTEMPT=1
:install_service_retry
"%PYTHON_FULL%" "%SERVICE_SCRIPT%" --startup auto install > "%SERVICE_SETUP_LOG%" 2>&1
if !errorlevel! neq 0 (
    set "SERVICE_INSTALL_EXIT=!errorlevel!"
    if !INSTALL_ATTEMPT! lss 4 (
        echo       Install attempt !INSTALL_ATTEMPT! failed ^(exit !SERVICE_INSTALL_EXIT!^), retrying...
        timeout /t 3 /nobreak >nul
        set /a INSTALL_ATTEMPT+=1
        goto :install_service_retry
    )
    echo ERROR: Failed to install service ^(exit !SERVICE_INSTALL_EXIT!^).
    echo       Check: %SERVICE_SETUP_LOG%
    echo       Common cause: previous service instance is still being removed by Windows.
    echo       Cleaning up partial registration...
    sc delete %SERVICE_NAME% >nul 2>&1
    call :pause_if_needed
    exit /b 1
) else (
    echo       OK - Service registered
)

:: Start
echo       Starting service...
sc start %SERVICE_NAME% >nul 2>&1
timeout /t 2 /nobreak >nul
sc query %SERVICE_NAME% | findstr "RUNNING" >nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: Service installed but failed to start.
    echo          Check: %LOG_DIR%\vpn_service.log
    echo          Setup log: %SERVICE_SETUP_LOG%
) else (
    echo       OK - Service started
)

:: ============================================================
:: Done
:: ============================================================
echo.
echo ============================================================
echo  Phoenix VPN Service installed successfully!
echo  Python     : %PYTHON_FULL%
echo  Service    : %SERVICE_NAME%
echo  Config dir : %PROGRAMDATA_DIR%
echo  Log file   : %LOG_DIR%\vpn_service.log
echo  Setup log  : %SERVICE_SETUP_LOG%
echo ============================================================
echo.
call :pause_if_needed
exit /b 0

:uninstall_service
echo [1/4] Checking administrator privileges...
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script must be run as Administrator.
    call :pause_if_needed
    exit /b 1
)
echo       OK - Running as Administrator

echo [2/4] Locating Python installation...
set PYTHON_FULL=

for /f "tokens=*" %%i in ('where python 2^>nul') do (
    echo %%i | findstr /i "WindowsApps" >nul 2>&1
    if !errorlevel! neq 0 (
        if not defined PYTHON_FULL (
            set PYTHON_FULL=%%i
        )
    )
)

if not defined PYTHON_FULL (
    for /f "tokens=*" %%i in ('py -3 -c "import sys; print(sys.executable)" 2^>nul') do (
        set PYTHON_FULL=%%i
    )
)

if not defined PYTHON_FULL (
    for %%v in (313 312 311 310) do (
        if not defined PYTHON_FULL (
            for %%p in (
                "%LOCALAPPDATA%\Programs\Python\Python%%v\python.exe"
                "%PROGRAMFILES%\Python%%v\python.exe"
                "%PROGRAMFILES(x86)%\Python%%v\python.exe"
            ) do (
                if exist %%p (
                    if not defined PYTHON_FULL (
                        set PYTHON_FULL=%%~p
                    )
                )
            )
        )
    )
)

if defined PYTHON_FULL (
    echo       Path: %PYTHON_FULL%
    echo       OK
) else (
    echo WARNING: Python not found, will use service-manager fallback only.
)

echo [3/4] Removing startup entries...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "ResistineVPNTray" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "ResistineVPN" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Resistine" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "ResistineVPNTray" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "ResistineVPN" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "Resistine" /f >nul 2>&1
echo       OK

echo [4/4] Removing VPN services...
call :remove_wireguard_tunnel_service resistine
call :remove_wireguard_tunnel_service resistine_default
call :remove_wireguard_tunnel_service resistine_vpn

sc query %SERVICE_NAME% >nul 2>&1
if %errorlevel% equ 0 (
    echo       Stopping ResistineVPN...
    sc stop %SERVICE_NAME% >nul 2>&1
    call :wait_for_named_service_stopped_or_absent %SERVICE_NAME% 15

    if defined PYTHON_FULL (
        echo       Removing ResistineVPN via service script...
        "%PYTHON_FULL%" "%SERVICE_SCRIPT%" remove >nul 2>&1
    )

    sc delete %SERVICE_NAME% >nul 2>&1
    call :wait_for_named_service_absent %SERVICE_NAME% 15
    if !errorlevel! neq 0 (
        echo WARNING: ResistineVPN is still registered.
        call :pause_if_needed
        exit /b 1
    )
    echo       OK - ResistineVPN removed
) else (
    echo       ResistineVPN not found, skipping
)

call :pause_if_needed
exit /b 0

:remove_wireguard_tunnel_service
set "_tunnel_name=%~1"
if not defined _tunnel_name exit /b 0
set "_wg_exe="
if exist "%PROGRAMFILES%\WireGuard\wireguard.exe" set "_wg_exe=%PROGRAMFILES%\WireGuard\wireguard.exe"
if not defined _wg_exe if exist "%PROGRAMFILES(x86)%\WireGuard\wireguard.exe" set "_wg_exe=%PROGRAMFILES(x86)%\WireGuard\wireguard.exe"
if defined _wg_exe (
    sc stop "WireGuardTunnel$!_tunnel_name!" >nul 2>&1
    timeout /t 1 /nobreak >nul
    "!_wg_exe!" /uninstalltunnelservice "!_tunnel_name!" >nul 2>&1
    sc delete "WireGuardTunnel$!_tunnel_name!" >nul 2>&1
    call :wait_for_named_service_absent "WireGuardTunnel$!_tunnel_name!" 10
)
exit /b 0

:wait_for_named_service_stopped_or_absent
set "_svc_name=%~1"
set "_svc_limit=%~2"
if not defined _svc_limit set "_svc_limit=15"
set /a _svc_wait=0
:wait_for_named_service_stopped_or_absent_loop
sc query "!_svc_name!" >nul 2>&1
if !errorlevel! neq 0 exit /b 0
sc query "!_svc_name!" | findstr /I "STOPPED" >nul 2>&1
if !errorlevel! equ 0 exit /b 0
if !_svc_wait! geq !_svc_limit! exit /b 1
timeout /t 1 /nobreak >nul
set /a _svc_wait+=1
goto :wait_for_named_service_stopped_or_absent_loop

:wait_for_named_service_absent
set "_svc_name=%~1"
set "_svc_limit=%~2"
if not defined _svc_limit set "_svc_limit=15"
set /a _svc_wait=0
:wait_for_named_service_absent_loop
sc query "!_svc_name!" >nul 2>&1
if !errorlevel! neq 0 exit /b 0
if !_svc_wait! geq !_svc_limit! exit /b 1
timeout /t 1 /nobreak >nul
set /a _svc_wait+=1
goto :wait_for_named_service_absent_loop

:pause_if_needed
if not defined QUIET_MODE pause
exit /b 0
