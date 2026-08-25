@echo off
set ROOT=%CYBERGROK_ROOT%
if "%ROOT%"=="" set ROOT=%GROK_PLUGIN_ROOT%
if "%ROOT%"=="" set ROOT=%~dp0..
set CYBERGROK_ROOT=%ROOT%
set PYTHONPATH=%ROOT%\python;%PYTHONPATH%
if exist "%ROOT%\venv\Scripts\python.exe" set PATH=%ROOT%\venv\Scripts;%PATH%
if not exist "%ROOT%\mcp\dist\index.js" (
  echo cybergrok-mcp TypeScript build missing. Run setup_windows.ps1 1>&2
  exit /b 1
)
node "%ROOT%\mcp\launch.cjs" %*
