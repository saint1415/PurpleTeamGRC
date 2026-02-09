#Requires -Version 5.0
<#
.SYNOPSIS
    Purple Team Platform v7.0 - Windows Launcher (PowerShell)
.DESCRIPTION
    Main entry point for Purple Team Platform on Windows.
    Detects Python, sets up environment, and launches the platform.
.NOTES
    If you get an execution policy error, run:
      Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
    Or launch with:
      powershell -ExecutionPolicy Bypass -File purple-launcher.ps1
#>

param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

# --- Resolve PURPLE_TEAM_HOME ---
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PurpleHome = Split-Path -Parent $ScriptDir

$env:PURPLE_TEAM_HOME = $PurpleHome

# --- Banner ---
Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "  ║      PURPLE TEAM PLATFORM v7.0                ║" -ForegroundColor Magenta
Write-Host "  ║      Systems Thinking Security Assessment      ║" -ForegroundColor Magenta
Write-Host "  ╚═══════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""

# --- Find Python ---
$PythonCmd = $null

# Check venv first
$VenvPython = Join-Path $PurpleHome "venv\Scripts\python.exe"
if (Test-Path $VenvPython) {
    $PythonCmd = $VenvPython
    Write-Host "  [+] Using venv Python: $VenvPython" -ForegroundColor Green
}

# Try system Python commands
if (-not $PythonCmd) {
    $PythonCandidates = @("python", "python3")

    foreach ($candidate in $PythonCandidates) {
        try {
            $result = & $candidate --version 2>&1
            if ($LASTEXITCODE -eq 0) {
                $PythonCmd = $candidate
                Write-Host "  [+] Found Python: $candidate ($result)" -ForegroundColor Green
                break
            }
        } catch {
            # Command not found, try next
        }
    }
}

# Try py launcher
if (-not $PythonCmd) {
    try {
        $result = & py -3 --version 2>&1
        if ($LASTEXITCODE -eq 0) {
            $PythonCmd = "py"
            Write-Host "  [+] Found Python via launcher: py -3 ($result)" -ForegroundColor Green
        }
    } catch {
        # py launcher not found
    }
}

# Python not found
if (-not $PythonCmd) {
    Write-Host ""
    Write-Host "  ERROR: Python 3 not found" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Purple Team Platform requires Python 3.10 or later." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Install Python from:" -ForegroundColor Yellow
    Write-Host "    https://www.python.org/downloads/" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  During installation, make sure to check:" -ForegroundColor Yellow
    Write-Host "    [x] Add Python to PATH" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "  Press Enter to exit"
    exit 1
}

# --- Set PYTHONPATH ---
$LibPath = Join-Path $PurpleHome "lib"
if ($env:PYTHONPATH) {
    $env:PYTHONPATH = "$LibPath;$env:PYTHONPATH"
} else {
    $env:PYTHONPATH = $LibPath
}

# --- Launch ---
$LauncherScript = Join-Path $ScriptDir "purple-launcher"

Write-Host ""

if ($PythonCmd -eq "py") {
    # py launcher needs -3 flag
    if ($Arguments) {
        & py -3 $LauncherScript @Arguments
    } else {
        & py -3 $LauncherScript
    }
} else {
    if ($Arguments) {
        & $PythonCmd $LauncherScript @Arguments
    } else {
        & $PythonCmd $LauncherScript
    }
}

exit $LASTEXITCODE
