$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$GrokHome = if ($env:GROK_HOME) { $env:GROK_HOME } else { Join-Path $env:USERPROFILE ".grok" }
$AgentNames = @("cybergrok", "recon-scout", "vuln-hunter", "reporter")

Write-Host "Cybergrok Windows setup (Grok Build + Python + TypeScript)"

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python 3.10+ is required."
    exit 1
}

function Install-GrokAgents {
    param([string]$Dest, [string]$Label)
    New-Item -ItemType Directory -Force -Path $Dest | Out-Null
    foreach ($name in $AgentNames) {
        $src = Join-Path $Root "agents\$name.md"
        if (-not (Test-Path $src)) {
            Write-Error "missing agents\$name.md"
            exit 1
        }
        Copy-Item $src (Join-Path $Dest "$name.md") -Force
        Write-Host "  ${Label}: $Dest\$name.md"
    }
}

New-Item -ItemType Directory -Force -Path reports, recon, output, logs, targets, tools\bin | Out-Null

Write-Host "Installing Grok Build agents..."
Install-GrokAgents -Dest (Join-Path $Root ".grok\agents") -Label "project"
Install-GrokAgents -Dest (Join-Path $GrokHome "agents") -Label "user"

$plugin = Join-Path $Root ".grok\plugins\cybergrok"
New-Item -ItemType Directory -Force -Path $plugin | Out-Null
if (-not (Test-Path (Join-Path $plugin "plugin.json"))) {
    Copy-Item (Join-Path $Root "plugin.json") (Join-Path $plugin "plugin.json")
}

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

if (Get-Command grok -ErrorAction SilentlyContinue) {
    Write-Host "Registering the Cybergrok plugin with Grok Build..."
    & grok plugin install $Root --trust
    if ($LASTEXITCODE -eq 0) {
        & grok plugin enable cybergrok
    }
}

Write-Host "Done. Session agent: Cybergrok. Spawn types: recon-scout, vuln-hunter, reporter."
Write-Host "Run .\cybergrok.ps1 (passes --agent .grok\agents\cybergrok.md)"
