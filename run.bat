@echo off
setlocal EnableDelayedExpansion

:: Change to the project root (same directory as this script)
cd /d "%~dp0"

:: Check if .venv exists, if not run install.bat
if not exist ".venv" (
    echo .venv folder not found. Running install.bat first...
    call scripts\install\install.bat
    if errorlevel 1 exit /b %errorlevel%
)

:: Activate virtual environment
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
) else (
    echo Error: Cannot find activation script. Please run install.bat.
    exit /b 1
)

:: Install/update requirements
:: Add GTK3 runtime to PATH for Cairo (needed by cairosvg/cairocffi)
if exist "C:\Program Files\GTK3-Runtime Win64\bin" (
    set "PATH=C:\Program Files\GTK3-Runtime Win64\bin;%PATH%"
) else (
    echo WARNING: GTK3 runtime not found. Cairo-based features may not work.
    echo Install it with: winget install -e --id tschoonj.GTKForWindows
)

echo Updating dependencies...
python -m pip install -U -q -r scripts\requirements\requirements-windows.txt
if %errorlevel% neq 0 (
    echo Failed to install requirements.
    exit /b 1
)

:: Check ResistineVPN service; start it if installed-but-stopped, reinstall if missing
call :check_service_state
if "!SERVICE_RUNNING!"=="1" (
    echo [run.bat] service: RUNNING -- skipping
) else if "!SERVICE_EXISTS!"=="1" (
    echo [run.bat] service: installed but not running -- starting
    powershell -NoProfile -Command "Start-Process -FilePath 'sc.exe' -ArgumentList 'start','ResistineVPN' -Verb RunAs -Wait"
    call :check_service_state
    if "!SERVICE_RUNNING!"=="1" (
        echo [run.bat] post-start: service is now RUNNING
    ) else (
        echo [run.bat] post-start: start failed -- registration may be stale ^(marked-for-deletion^); attempting full reinstall
        set "INSTALL_LOG=%PROGRAMDATA%\Resistine\run_bat_install_service.log"
        set "INSTALL_WRAPPER=%TEMP%\resistine_run_install_wrapper.bat"
        if not exist "%PROGRAMDATA%\Resistine" mkdir "%PROGRAMDATA%\Resistine" >nul 2>&1
        call :write_install_wrapper
        powershell -NoProfile -Command "Start-Process -FilePath '!INSTALL_WRAPPER!' -Verb RunAs -Wait"
        del "!INSTALL_WRAPPER!" >nul 2>&1
        call :check_service_state
        if "!SERVICE_RUNNING!"=="1" (
            echo [run.bat] post-reinstall: service is now RUNNING
        ) else (
            echo [run.bat] post-reinstall: still not running -- check !INSTALL_LOG!
        )
    )
) else (
    echo [run.bat] service: not installed -- reinstall required
    set "INSTALL_LOG=%PROGRAMDATA%\Resistine\run_bat_install_service.log"
    set "INSTALL_WRAPPER=%TEMP%\resistine_run_install_wrapper.bat"
    if not exist "%PROGRAMDATA%\Resistine" mkdir "%PROGRAMDATA%\Resistine" >nul 2>&1
    call :write_install_wrapper
    powershell -NoProfile -Command "Start-Process -FilePath '!INSTALL_WRAPPER!' -Verb RunAs -Wait"
    del "!INSTALL_WRAPPER!" >nul 2>&1
    call :check_service_state
    if "!SERVICE_RUNNING!"=="1" (
        echo [run.bat] post-install: service is now RUNNING
    ) else if "!SERVICE_EXISTS!"=="1" (
        echo [run.bat] post-install: service registered but not running
        echo [run.bat] install output: !INSTALL_LOG!
        echo [run.bat] service setup log: %PROGRAMDATA%\Resistine\vpn_service_install.log
    ) else (
        echo [run.bat] post-install: service still not installed -- UAC declined or install failed
        echo [run.bat] install output: !INSTALL_LOG!
    )
)

:: Run the application (debug mode by default)
echo Starting the application in debug mode...
python main.py -d %*

:: Deactivate is implicitly handled by script exit since we used call/local
:: but we can be explicit if needed.
:: call deactivate
goto :eof

:check_service_state
set "SERVICE_EXISTS="
set "SERVICE_RUNNING="
sc query ResistineVPN >nul 2>&1
if errorlevel 1 goto :check_service_state_done
set "SERVICE_EXISTS=1"
sc query ResistineVPN | findstr /C:"RUNNING" >nul 2>&1
if errorlevel 1 goto :check_service_state_done
set "SERVICE_RUNNING=1"
:check_service_state_done
goto :eof

:write_install_wrapper
:: Write a tiny wrapper bat that elevates to run install_service.bat with
:: all output redirected to a log file. Done here (outside parenthesized
:: blocks) so the ^> and ^& escapes don't need extra doubling.
> "%INSTALL_WRAPPER%" echo @echo off
>> "%INSTALL_WRAPPER%" echo call "%~dp0scripts\install\install_service.bat" /quiet ^> "%INSTALL_LOG%" 2^>^&1
goto :eof
