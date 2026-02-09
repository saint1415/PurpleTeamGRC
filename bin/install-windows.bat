@echo off
REM ============================================================
REM Purple Team Platform v7.0 - Install from USB to Local System
REM Copies the platform from USB/portable media to a fixed location.
REM Works on Windows 10/11.
REM ============================================================
setlocal EnableDelayedExpansion

echo.
echo  ============================================================
echo   Purple Team Platform v7.0 - Local Installation
echo  ============================================================
echo.

REM --- Resolve source directory ---
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
for %%I in ("%SCRIPT_DIR%") do set "SOURCE_DIR=%%~dpI"
if "%SOURCE_DIR:~-1%"=="\" set "SOURCE_DIR=%SOURCE_DIR:~0,-1%"

echo  Source: %SOURCE_DIR%
echo.

REM --- Default install location ---
set "DEFAULT_TARGET=%USERPROFILE%\PurpleTeamGRC"

set /p "TARGET_DIR=  Install location [%DEFAULT_TARGET%]: "
if "%TARGET_DIR%"=="" set "TARGET_DIR=%DEFAULT_TARGET%"

echo.
echo  Will install to: %TARGET_DIR%
echo.

REM --- Check if target exists ---
if exist "%TARGET_DIR%\" (
    echo  [WARNING] Directory already exists: %TARGET_DIR%
    echo.
    echo    1^) Overwrite ^(replace existing files^)
    echo    2^) Cancel
    echo.
    set /p "OVERWRITE_CHOICE=  Select [2]: "
    if "!OVERWRITE_CHOICE!"=="" set "OVERWRITE_CHOICE=2"
    if "!OVERWRITE_CHOICE!" neq "1" (
        echo  Installation cancelled.
        pause
        exit /b 0
    )
    echo.
)

REM --- Check source != target ---
if /i "%SOURCE_DIR%"=="%TARGET_DIR%" (
    echo  [ERROR] Source and target are the same directory.
    pause
    exit /b 1
)

REM --- Copy files ---
echo  [*] Creating target directory...
if not exist "%TARGET_DIR%" mkdir "%TARGET_DIR%"

echo  [*] Copying platform files...
echo.

REM Use robocopy for efficient copying with exclusions
robocopy "%SOURCE_DIR%" "%TARGET_DIR%" /E /NFL /NDL /NJH /NJS /NC /NS ^
    /XD .git venv __pycache__ ^
    /XF *.pyc >nul 2>&1

REM robocopy exit codes: 0-7 are success, 8+ are errors
if %ERRORLEVEL% geq 8 (
    echo  [ERROR] File copy failed with error %ERRORLEVEL%.
    echo  Trying xcopy fallback...
    echo.

    xcopy "%SOURCE_DIR%\*" "%TARGET_DIR%\" /E /I /H /Y /Q ^
        /EXCLUDE:%SCRIPT_DIR%\xcopy-exclude.tmp >nul 2>&1

    if %ERRORLEVEL% neq 0 (
        echo  [ERROR] File copy failed.
        pause
        exit /b 1
    )
)

REM Clean up items that shouldn't be in the install
if exist "%TARGET_DIR%\.git" rmdir /s /q "%TARGET_DIR%\.git" >nul 2>&1
if exist "%TARGET_DIR%\venv" rmdir /s /q "%TARGET_DIR%\venv" >nul 2>&1

echo  [OK] Files copied.
echo.

REM --- Clean data directories (keep structure, clear contents) ---
echo  [*] Preparing clean data directories...
for %%D in (results evidence reports logs) do (
    if exist "%TARGET_DIR%\data\%%D" (
        del /q "%TARGET_DIR%\data\%%D\*" >nul 2>&1
    ) else (
        mkdir "%TARGET_DIR%\data\%%D" >nul 2>&1
    )
)
echo  [OK] Data directories ready (clean install, no USB data copied).
echo.

REM --- Run setup ---
echo  [*] Running setup to create venv and install dependencies...
echo.

call "%TARGET_DIR%\bin\setup-windows.bat"

echo.
echo  ============================================================
echo   Installation Complete
echo  ============================================================
echo.
echo  Installed to: %TARGET_DIR%
echo.
echo  Launch with:
echo    %TARGET_DIR%\bin\purple-launcher.bat
echo.
echo  Or from PowerShell:
echo    %TARGET_DIR%\bin\purple-launcher.ps1
echo.
echo  Quick scan:
echo    %TARGET_DIR%\bin\purple-launcher.bat quick
echo.
echo  The platform will detect 'installed' mode (full features enabled).
echo  USB data (evidence, reports) was NOT copied -- start fresh.
echo.
echo  ============================================================
echo.

pause
exit /b 0
