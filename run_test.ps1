# Set up environment for Purple Team Platform testing
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null

$env:PURPLE_TEAM_HOME = "C:\Users\Cris\PurpleTeamGRC"
$env:PYTHONIOENCODING = "utf-8"
$env:PYTHONUTF8 = "1"

# Add tools to PATH
$toolsDir = "$env:PURPLE_TEAM_HOME\tools"
$venvScripts = "$env:PURPLE_TEAM_HOME\venv\Scripts"
$env:PATH = "$toolsDir;$toolsDir\gobuster;$toolsDir\amass;$venvScripts;$env:PATH"

# Add nmap to PATH if installed
$nmapPath = "C:\Program Files (x86)\Nmap"
if (Test-Path $nmapPath) {
    $env:PATH = "$nmapPath;$env:PATH"
}

# Add winget packages to PATH
$wingetPkgs = "C:\Users\Cris\AppData\Local\Microsoft\WinGet\Packages"
Get-ChildItem $wingetPkgs -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $env:PATH = "$($_.FullName);$env:PATH"
}

# Refresh PATH to pick up winget installs
$env:PATH = [System.Environment]::GetEnvironmentVariable("PATH", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("PATH", "User") + ";$toolsDir;$toolsDir\gobuster;$toolsDir\amass"

Set-Location $env:PURPLE_TEAM_HOME

# Run the launcher with passed arguments
& ".\venv\Scripts\python.exe" "bin\purple-launcher" @args
