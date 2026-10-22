@echo off
:: ============================================================
:: Phoenix VPN — Full Installer
:: ============================================================
setlocal EnableDelayedExpansion

set SCRIPT_DIR=%~dp0
if "%SCRIPT_DIR:~-1%"=="\" set SCRIPT_DIR=%SCRIPT_DIR:~0,-1%
:: Project root is two levels up from scripts\install\
set PROJECT_ROOT=%SCRIPT_DIR%\..\..
for %%I in ("%PROJECT_ROOT%") do set PROJECT_ROOT=%%~fI

set SERVICE_NAME=ResistineVPN
set SERVICE_SCRIPT=%PROJECT_ROOT%\plugins\vpn\wireguard\windows_vpn_service.py
set MAIN_SCRIPT=%PROJECT_ROOT%\main.py
set TRAY_SCRIPT=%PROJECT_ROOT%\gui\tray.py
set ICON=%PROJECT_ROOT%\resources\icons\icon.ico
set VENV_DIR=%PROJECT_ROOT%\.venv
set VENV_PYTHON=%VENV_DIR%\Scripts\python.exe
set VENV_PIP=%VENV_DIR%\Scripts\pip.exe
set REQUIREMENTS=%PROJECT_ROOT%\requirements\requirements-windows.txt
if not exist "%REQUIREMENTS%" set REQUIREMENTS=%PROJECT_ROOT%\requirements.txt
set APPDATA_DIR=%APPDATA%\Phoenix
set WG_DIR=%APPDATA_DIR%\wireguard
set PROGRAMDATA_DIR=%PROGRAMDATA%\Resistine
set PROGRAMDATA_WG=%PROGRAMDATA_DIR%\wireguard
set SHORTCUT=%USERPROFILE%\Desktop\Phoenix VPN.lnk
set STARTUP_KEY=HKCU\Software\Microsoft\Windows\CurrentVersion\Run
set WG_EXE=%PROGRAMFILES%\WireGuard\wireguard.exe
set WG_INSTALLER=%TEMP%\wireguard-installer.exe
set WG_URL=https://download.wireguard.com/windows-client/wireguard-installer.exe

:: ============================================================
:: Jump to service section if elevated via /service flag
:: ============================================================
if "%1"=="/service" goto :install_service

:: ============================================================
:: PART 1 — User level (no admin needed)
:: ============================================================
echo ============================================================
echo  Phoenix VPN Installer
echo ============================================================
echo.

:: ---- Step 1: Find real Python ----
echo [1/6] Locating Python...
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
                if exist %%p if not defined PYTHON_FULL set PYTHON_FULL=%%~p
            )
        )
    )
)

if not defined PYTHON_FULL (
    echo ERROR: Python not found.
    echo Please install Python 3.10+ from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    pause & exit /b 1
)

:: Verify it runs
"%PYTHON_FULL%" --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python at %PYTHON_FULL% failed to run.
    pause & exit /b 1
)

:: Verify version is 3.10+
for /f "tokens=2" %%v in ('"%PYTHON_FULL%" --version 2^>^&1') do set PY_VER=%%v
for /f "tokens=1,2 delims=." %%a in ("%PY_VER%") do (
    set PY_MAJOR=%%a
    set PY_MINOR=%%b
)
if %PY_MAJOR% lss 3 (
    echo ERROR: Python 3.10+ required, found %PY_VER%
    pause & exit /b 1
)
if %PY_MAJOR% equ 3 if %PY_MINOR% lss 10 (
    echo ERROR: Python 3.10+ required, found %PY_VER%
    pause & exit /b 1
)

for /f "tokens=*" %%i in ('"%PYTHON_FULL%" --version') do echo       %%i
echo       Path: %PYTHON_FULL%
echo       OK

:: ---- Step 2: Create or reuse venv (GUI + tray only) ----
echo [2/6] Setting up virtual environment...
if not exist "%VENV_PYTHON%" (
    echo       Creating venv...
    "%PYTHON_FULL%" -m venv "%VENV_DIR%"
    if !errorlevel! neq 0 (
        echo ERROR: Failed to create venv.
        pause & exit /b 1
    )
    echo       OK - venv created
) else (
    echo       OK - existing venv found
)

:: ---- Step 3: Install GUI/tray dependencies into venv ----
echo [3/6] Installing dependencies...
echo       Upgrading pip...
"%VENV_PYTHON%" -m pip install --quiet --upgrade pip

if exist "%REQUIREMENTS%" (
    echo       Installing from %REQUIREMENTS%...
    "%VENV_PYTHON%" -m pip install --quiet -r "%REQUIREMENTS%"
) else (
    echo       No requirements file found, installing defaults...
    "%VENV_PYTHON%" -m pip install --quiet ^
        customtkinter ^
        pillow ^
        pystray ^
        loguru ^
        pywin32 ^
        pywin32-ctypes
)

if %errorlevel% neq 0 (
    echo ERROR: Failed to install dependencies.
    pause & exit /b 1
)
echo       OK - Dependencies installed

:: ---- Step 4: Create AppData directories ----
echo [4/6] Creating app directories...
if not exist "%APPDATA_DIR%" mkdir "%APPDATA_DIR%"
if not exist "%WG_DIR%"      mkdir "%WG_DIR%"
echo       OK - %APPDATA_DIR%

:: ---- Step 5: Desktop shortcut ----
echo [5/6] Creating desktop shortcut...
set VBS=%TEMP%\resistine_shortcut.vbs

>  "%VBS%" echo Set oWS = WScript.CreateObject("WScript.Shell")
>> "%VBS%" echo Set oLink = oWS.CreateShortcut("%SHORTCUT%")
>> "%VBS%" echo oLink.TargetPath = "%VENV_PYTHON%"
>> "%VBS%" echo oLink.Arguments = """%MAIN_SCRIPT%"""
>> "%VBS%" echo oLink.WorkingDirectory = "%SCRIPT_DIR%"
>> "%VBS%" echo oLink.IconLocation = "%ICON%, 0"
>> "%VBS%" echo oLink.Description = "Phoenix VPN"
>> "%VBS%" echo oLink.Save

cscript //nologo "%VBS%"
del "%VBS%" >nul 2>&1

if exist "%SHORTCUT%" (
    echo       OK - Shortcut created on Desktop
) else (
    echo WARNING: Shortcut creation failed
)

:: ---- Step 6: Register tray for startup ----
echo [6/6] Registering tray for startup...
reg add "%STARTUP_KEY%" ^
    /v "%SERVICE_NAME%Tray" ^
    /t REG_SZ ^
    /d "\"%VENV_PYTHON%\" \"%TRAY_SCRIPT%\"" ^
    /f >nul 2>&1

if %errorlevel% neq 0 (
    echo WARNING: Failed to register tray for startup
) else (
    echo       OK - Tray will auto-start on login
)

:: ============================================================
:: PART 2 — Service install (elevate to admin)
:: Write PYTHON_FULL to a temp file so the elevated process can read it
:: (environment variables do not survive UAC elevation boundary)
:: ============================================================
echo %PYTHON_FULL%> "%TEMP%\resistine_python_path.txt"

echo.
echo Installing Windows service ^(requires Admin^)...
powershell -Command "Start-Process cmd -ArgumentList '/c \"%~f0\" /service & pause' -Verb RunAs -Wait"
if %errorlevel% neq 0 (
    echo WARNING: Service installation failed or was cancelled.
    echo          VPN toggle will not work until service is installed.
)

del "%TEMP%\resistine_python_path.txt" >nul 2>&1

:: The tray is now a native QSystemTrayIcon inside the app (gui/system_tray.py),
:: started by main.py — no separate tray process to launch here.

:: ============================================================
:: Done
:: ============================================================
echo.
echo ============================================================
echo  Installation complete!
echo  GUI/Tray   : %VENV_PYTHON%  ^(venv^)
echo  Service    : system Python  ^(no venv^)
echo  App        : %MAIN_SCRIPT%
echo  Tray       : auto-starts on login
echo  Config     : %WG_DIR%
echo  Desktop    : %SHORTCUT%
echo ============================================================
echo.
pause
exit /b 0


:: ============================================================
:: SERVICE SECTION (runs elevated via /service flag)
:: Uses system Python — not the venv — so SYSTEM account has no
:: DLL path issues and pywin32 works without any post-install tricks.
:: ============================================================
:install_service
echo ============================================================
echo  Installing ResistineVPN Service ^(Admin^)
echo ============================================================

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Not running as Administrator.
    pause & exit /b 1
)

:: Read system Python path passed from the user-level section
set SYS_PYTHON=
if exist "%TEMP%\resistine_python_path.txt" (
    set /p SYS_PYTHON= < "%TEMP%\resistine_python_path.txt"
)

:: Fallback: search for Python again if temp file is missing
if not defined SYS_PYTHON (
    for /f "tokens=*" %%i in ('py -3 -c "import sys; print(sys.executable)" 2^>nul') do (
        if not defined SYS_PYTHON set SYS_PYTHON=%%i
    )
)
if not defined SYS_PYTHON (
    for /f "tokens=*" %%i in ('where python 2^>nul') do (
        echo %%i | findstr /i "WindowsApps" >nul 2>&1
        if !errorlevel! neq 0 if not defined SYS_PYTHON set SYS_PYTHON=%%i
    )
)

if not defined SYS_PYTHON (
    echo ERROR: Could not locate system Python. Aborting.
    pause & exit /b 1
)

echo       Using Python: %SYS_PYTHON%

:: ---- Network check ----
echo Checking network...
ping -n 1 8.8.8.8 >nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: No network detected. Downloads may fail.
) else (
    echo       OK
)

:: ---- Check / Install WireGuard ----
echo Checking WireGuard...
if exist "%WG_EXE%" (
    echo       OK - WireGuard already installed
) else (
    echo       Downloading WireGuard...
    powershell -NoProfile -Command ^
        "Invoke-WebRequest -Uri '%WG_URL%' -OutFile '%WG_INSTALLER%' -UseBasicParsing"

    if not exist "%WG_INSTALLER%" (
        echo ERROR: Failed to download WireGuard.
        echo Please install manually from https://www.wireguard.com/install/
        pause & exit /b 1
    )

    echo       Installing WireGuard silently...
    "%WG_INSTALLER%" /S
    timeout /t 5 /nobreak >nul
    del "%WG_INSTALLER%" >nul 2>&1

    if not exist "%WG_EXE%" (
        echo ERROR: WireGuard install failed.
        pause & exit /b 1
    )
    echo       OK - WireGuard installed
)

:: ---- Create ProgramData directories ----
echo Creating service directories...
if not exist "%PROGRAMDATA_DIR%" mkdir "%PROGRAMDATA_DIR%"
if not exist "%PROGRAMDATA_WG%"  mkdir "%PROGRAMDATA_WG%"
echo       OK - %PROGRAMDATA_DIR%

:: ---- Install pywin32 into system Python ----
:: Service runs as SYSTEM using system Python — no venv, no DLL issues.
echo Installing pywin32 to system Python...
"%SYS_PYTHON%" -m pip install --quiet pywin32 pywin32-ctypes
if %errorlevel% neq 0 (
    echo ERROR: Failed to install pywin32.
    pause & exit /b 1
)
echo       OK

:: ---- Clean up any stale WireGuard tunnel services ----
:: Stale WireGuardTunnel$ services from a previous install are the most
:: common cause of reinstall failures. wireguard.exe /installtunnelservice
:: sees the service already exists and skips re-registering it, leaving
:: a broken stopped service that never starts.
echo Cleaning up stale WireGuard tunnels...
if exist "%WG_EXE%" (
    :: Remove tunnels listed in ProgramData conf files
    if exist "%PROGRAMDATA_WG%" (
        for %%f in ("%PROGRAMDATA_WG%\*.conf") do (
            set TUNNEL=%%~nf
            "%WG_EXE%" /uninstalltunnelservice "!TUNNEL!" >nul 2>&1
            sc stop   "WireGuardTunnel$!TUNNEL!" >nul 2>&1
            sc delete "WireGuardTunnel$!TUNNEL!" >nul 2>&1
        )
    )
    :: Also sweep for any registered WireGuardTunnel services in case the
    :: conf was already deleted but the service entry wasn't cleaned up
    for /f "tokens=2" %%s in ('sc query type^= all state^= all 2^>nul ^| findstr /i "WireGuardTunnel"') do (
        sc stop   "%%s" >nul 2>&1
        sc delete "%%s" >nul 2>&1
        "%WG_EXE%" /uninstalltunnelservice "%%s" >nul 2>&1
    )
)
timeout /t 2 /nobreak >nul
echo       OK

:: ---- Remove existing ResistineVPN service ----
sc query %SERVICE_NAME% >nul 2>&1
if %errorlevel% equ 0 (
    echo Stopping existing service...
    sc stop %SERVICE_NAME% >nul 2>&1
    timeout /t 3 /nobreak >nul

    echo Removing existing service...
    "%SYS_PYTHON%" "%SERVICE_SCRIPT%" remove >nul 2>&1

    echo Waiting for service cleanup...
    set RETRY=0
    :wait_loop
    sc query %SERVICE_NAME% >nul 2>&1
    if %errorlevel% equ 0 (
        if !RETRY! lss 10 (
            set /a RETRY+=1
            echo       Still waiting... ^(!RETRY!/10^)
            timeout /t 3 /nobreak >nul
            goto :wait_loop
        ) else (
            echo WARNING: Service handle not released.
            echo          Please restart your PC and run install.bat again.
            pause & exit /b 1
        )
    )
    echo       OK - Service fully removed
)

:: ---- Install service using system Python ----
echo Registering service...
"%SYS_PYTHON%" "%SERVICE_SCRIPT%" --startup auto install
if %errorlevel% neq 0 (
    echo ERROR: Failed to install service.
    pause & exit /b 1
)

:: ---- Start service ----
echo Starting service...
sc start %SERVICE_NAME% >nul 2>&1
timeout /t 3 /nobreak >nul

:: ---- Verify running ----
sc query %SERVICE_NAME% | findstr "RUNNING" >nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: Service installed but not running.
    echo          Check: %PROGRAMDATA_DIR%\vpn_service.log
) else (
    echo       OK - Service running
)

echo.
echo ============================================================
echo  Service installed successfully!
echo  Python     : %SYS_PYTHON%
echo  WireGuard  : %WG_EXE%
echo  Service    : %SERVICE_NAME%
echo  Config dir : %PROGRAMDATA_WG%
echo  Log file   : %PROGRAMDATA_DIR%\vpn_service.log
echo ============================================================
pause
exit /b 0