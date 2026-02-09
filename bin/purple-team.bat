@echo off
REM ============================================================
REM Purple Team Platform v7.0 - Windows Wrapper
REM Backward-compatible wrapper that calls purple-launcher.bat
REM ============================================================

echo.
echo   Purple Team Platform v7.0
echo   Systems Thinking Security Assessment
echo.

REM Call purple-launcher.bat from the same directory as this script
call "%~dp0purple-launcher.bat" %*
exit /b %ERRORLEVEL%
