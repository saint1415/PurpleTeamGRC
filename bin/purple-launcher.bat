@echo off
REM ============================================================
REM Purple Team Platform v7.0 - Windows Launcher
REM Main entry point for Windows (CMD)
REM ============================================================
setlocal EnableDelayedExpansion

REM --- Resolve PURPLE_TEAM_HOME (parent of bin directory) ---
set "SCRIPT_DIR=%~dp0"
REM Remove trailing backslash
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
REM Go up one directory
for %%I in ("%SCRIPT_DIR%") do set "PURPLE_TEAM_HOME=%%~dpI"
REM Remove trailing backslash
if "%PURPLE_TEAM_HOME:~-1%"=="\" set "PURPLE_TEAM_HOME=%PURPLE_TEAM_HOME:~0,-1%"

REM --- Check for venv Python first ---
set "PYTHON_CMD="
if exist "%PURPLE_TEAM_HOME%\venv\Scripts\python.exe" (
    set "PYTHON_CMD=%PURPLE_TEAM_HOME%\venv\Scripts\python.exe"
    goto :found_python
)

REM --- Try to find system Python ---
REM Try "python" first
python --version >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "PYTHON_CMD=python"
    goto :found_python
)

REM Try "python3"
python3 --version >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "PYTHON_CMD=python3"
    goto :found_python
)

REM Try "py -3" (Python Launcher for Windows)
py -3 --version >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "PYTHON_CMD=py -3"
    goto :found_python
)

REM --- Python not found ---
echo.
echo ============================================================
echo  ERROR: Python 3 not found
echo ============================================================
echo.
echo  Purple Team Platform requires Python 3.10 or later.
echo.
echo  Please install Python from:
echo    https://www.python.org/downloads/
echo.
echo  During installation, make sure to check:
echo    [x] Add Python to PATH
echo.
echo ============================================================
echo.
pause
exit /b 1

:found_python
REM --- Set environment ---
set "PURPLE_TEAM_HOME=%PURPLE_TEAM_HOME%"
set "PYTHONPATH=%PURPLE_TEAM_HOME%\lib;%PYTHONPATH%"

REM --- Launch purple-launcher ---
"%PYTHON_CMD%" "%SCRIPT_DIR%\purple-launcher" %*
set "EXIT_CODE=%ERRORLEVEL%"

endlocal
exit /b %EXIT_CODE%
