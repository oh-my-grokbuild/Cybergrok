$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

Write-Host "Cybergrok Windows setup (Grok Build + Python + TypeScript)"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python 3.10+ is required."
    exit 1
}

New-Item -ItemType Directory -Force -Path reports, recon, output, logs, targets, tools\bin | Out-Null

if (-not (Test-Path "$Root\venv")) {
    python -m venv "$Root\venv"
}
& "$Root\venv\Scripts\python.exe" -m pip install --upgrade pip
& "$Root\venv\Scripts\pip.exe" install -e "$Root"

if (Get-Command npm -ErrorAction SilentlyContinue) {
    Push-Location "$Root\mcp"
    npm install
    npm run build
    Pop-Location
}

if (-not (Test-Path "$Root\.env") -and (Test-Path "$Root\.env.example")) {
    Copy-Item "$Root\.env.example" "$Root\.env"
}

if (Test-Path "$Root\tools\update_tools.ps1") {
    & "$Root\tools\update_tools.ps1"
}

Write-Host "Done. Run .\cybergrok.ps1 or: grok plugin install $Root --trust"
