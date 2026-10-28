Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendDir = Join-Path $Root "backend"
$FrontendDir = Join-Path $Root "frontend"
$BackendPython = Join-Path $BackendDir ".venv\Scripts\python.exe"

if (-not (Test-Path $BackendDir)) {
    throw "Backend directory not found: $BackendDir"
}

if (-not (Test-Path $FrontendDir)) {
    throw "Frontend directory not found: $FrontendDir"
}

if (Test-Path $BackendPython) {
    $PythonCommand = ".\.venv\Scripts\python.exe"
} else {
    $PythonCommand = "python"
}

$BackendCommand = @"
Set-Location -Path '$BackendDir'
Write-Host 'Starting pullRequestExploitr backend on http://127.0.0.1:8765' -ForegroundColor Cyan
& $PythonCommand main.py
"@

$FrontendCommand = @"
Set-Location -Path '$FrontendDir'
if (-not (Test-Path 'node_modules')) {
    Write-Host 'Installing frontend dependencies...' -ForegroundColor Yellow
    npm install
}
Write-Host 'Starting pullRequestExploitr frontend on http://localhost:5173' -ForegroundColor Cyan
npm run dev
"@

Start-Process powershell.exe -ArgumentList @(
    "-NoExit",
    "-ExecutionPolicy", "Bypass",
    "-Command", $BackendCommand
)

Start-Process powershell.exe -ArgumentList @(
    "-NoExit",
    "-ExecutionPolicy", "Bypass",
    "-Command", $FrontendCommand
)

Start-Sleep -Seconds 3
Start-Process "http://localhost:5173"
