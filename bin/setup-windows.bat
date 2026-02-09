@echo off
REM ============================================================
REM Purple Team Platform v7.0 - Windows Setup
REM Creates venv and installs dependencies
REM ============================================================
setlocal EnableDelayedExpansion

echo.
echo  ============================================================
echo   Purple Team Platform v7.0 - Windows Setup
echo  ============================================================
echo.

REM --- Resolve PURPLE_TEAM_HOME ---
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
for %%I in ("%SCRIPT_DIR%") do set "PURPLE_TEAM_HOME=%%~dpI"
if "%PURPLE_TEAM_HOME:~-1%"=="\" set "PURPLE_TEAM_HOME=%PURPLE_TEAM_HOME:~0,-1%"

echo  Installation directory: %PURPLE_TEAM_HOME%
echo.

REM --- Find Python ---
set "PYTHON_CMD="

python --version >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "PYTHON_CMD=python"
    goto :check_version
)

python3 --version >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "PYTHON_CMD=python3"
    goto :check_version
)

py -3 --version >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "PYTHON_CMD=py -3"
    goto :check_version
)

echo  [ERROR] Python 3 not found.
echo.
echo  Please install Python 3.10+ from:
echo    https://www.python.org/downloads/
echo.
echo  Make sure to check "Add Python to PATH" during installation.
echo.
pause
exit /b 1

:check_version
REM --- Verify Python version is 3.10+ ---
echo  [*] Found Python: %PYTHON_CMD%

for /f "tokens=*" %%V in ('%PYTHON_CMD% --version 2^>^&1') do set "PY_VERSION_STR=%%V"
echo  [*] Version: %PY_VERSION_STR%

%PYTHON_CMD% -c "import sys; exit(0 if sys.version_info >= (3, 10) else 1)" >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo.
    echo  [ERROR] Python 3.10 or later is required.
    echo  Current version: %PY_VERSION_STR%
    echo.
    echo  Please upgrade Python from:
    echo    https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

echo  [OK] Python version is 3.10+
echo.

REM --- Check for requirements.txt ---
if not exist "%PURPLE_TEAM_HOME%\requirements.txt" (
    echo  [WARNING] requirements.txt not found at:
    echo    %PURPLE_TEAM_HOME%\requirements.txt
    echo.
    echo  Continuing with venv creation only...
    echo.
    set "SKIP_INSTALL=1"
) else (
    set "SKIP_INSTALL=0"
)

REM --- Create virtual environment ---
set "VENV_DIR=%PURPLE_TEAM_HOME%\venv"

if exist "%VENV_DIR%\Scripts\python.exe" (
    echo  [*] Virtual environment already exists at:
    echo    %VENV_DIR%
    echo.
    set /p "RECREATE=  Recreate venv? (y/N): "
    if /i "!RECREATE!"=="y" (
        echo  [*] Removing existing venv...
        rmdir /s /q "%VENV_DIR%"
        echo  [*] Creating new virtual environment...
        %PYTHON_CMD% -m venv "%VENV_DIR%"
        if %ERRORLEVEL% neq 0 (
            echo  [ERROR] Failed to create virtual environment.
            pause
            exit /b 1
        )
        echo  [OK] Virtual environment created.
    ) else (
        echo  [*] Keeping existing venv.
    )
) else (
    echo  [*] Creating virtual environment...
    %PYTHON_CMD% -m venv "%VENV_DIR%"
    if %ERRORLEVEL% neq 0 (
        echo  [ERROR] Failed to create virtual environment.
        echo  Make sure the 'venv' module is available:
        echo    %PYTHON_CMD% -m ensurepip
        echo.
        pause
        exit /b 1
    )
    echo  [OK] Virtual environment created at:
    echo    %VENV_DIR%
)

echo.

REM --- Install requirements ---
set "VENV_PYTHON=%VENV_DIR%\Scripts\python.exe"
set "VENV_PIP=%VENV_DIR%\Scripts\pip.exe"

if "%SKIP_INSTALL%"=="1" goto :verify

echo  [*] Upgrading pip...
"%VENV_PYTHON%" -m pip install --upgrade pip >nul 2>&1
echo  [OK] pip upgraded.
echo.

echo  [*] Installing requirements...
echo    Source: %PURPLE_TEAM_HOME%\requirements.txt
echo.

"%VENV_PIP%" install -r "%PURPLE_TEAM_HOME%\requirements.txt"
if %ERRORLEVEL% neq 0 (
    echo.
    echo  [ERROR] Some packages failed to install.
    echo  You may need to install Visual C++ Build Tools for some packages:
    echo    https://visualstudio.microsoft.com/visual-cpp-build-tools/
    echo.
    echo  The platform may still work with reduced functionality.
    echo.
) else (
    echo.
    echo  [OK] All requirements installed successfully.
)

echo.

:verify
REM --- Verify installation ---
echo  ============================================================
echo   Verification
echo  ============================================================
echo.

echo  [*] Checking Python in venv...
"%VENV_PYTHON%" --version
if %ERRORLEVEL% neq 0 (
    echo  [ERROR] Venv Python not working.
    pause
    exit /b 1
)

echo  [*] Checking core imports...
"%VENV_PYTHON%" -c "import sys; sys.path.insert(0, r'%PURPLE_TEAM_HOME%\lib'); import pathlib; print('  [OK] Core Python modules available')" 2>nul
if %ERRORLEVEL% neq 0 (
    echo  [WARNING] Some imports may not be available.
)

echo.

REM --- Create data directories ---
echo  [*] Ensuring data directories exist...
if not exist "%PURPLE_TEAM_HOME%\data\results" mkdir "%PURPLE_TEAM_HOME%\data\results"
if not exist "%PURPLE_TEAM_HOME%\data\evidence" mkdir "%PURPLE_TEAM_HOME%\data\evidence"
if not exist "%PURPLE_TEAM_HOME%\data\reports" mkdir "%PURPLE_TEAM_HOME%\data\reports"
if not exist "%PURPLE_TEAM_HOME%\data\logs" mkdir "%PURPLE_TEAM_HOME%\data\logs"
echo  [OK] Data directories ready.

echo.
echo  ============================================================
echo   Setup Complete
echo  ============================================================
echo.
echo  To launch the platform:
echo    bin\purple-launcher.bat
echo.
echo  Or from PowerShell:
echo    bin\purple-launcher.ps1
echo.
echo  Quick scan:
echo    bin\purple-launcher.bat quick
echo.
echo  ============================================================
echo.

pause
exit /b 0
