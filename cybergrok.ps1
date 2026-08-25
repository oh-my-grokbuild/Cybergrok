$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$env:CYBERGROK_DIR = $ScriptDir
$env:CYBERGROK_ROOT = $ScriptDir
$env:PATH = "$ScriptDir\tools\bin;$ScriptDir\bin;$env:PATH"

if (Test-Path "$ScriptDir\.env") {
    Get-Content "$ScriptDir\.env" | ForEach-Object {
        if ($_ -match '^\s*#' -or $_ -notmatch '=') { return }
        $k, $v = $_.Split('=', 2)
        [Environment]::SetEnvironmentVariable($k.Trim(), $v.Trim().Trim('"'))
    }
}

if (-not (Get-Command grok -ErrorAction SilentlyContinue)) {
    Write-Error "Grok Build CLI ('grok') not found. Install Grok Build, then re-run."
    exit 1
}

& grok @args
