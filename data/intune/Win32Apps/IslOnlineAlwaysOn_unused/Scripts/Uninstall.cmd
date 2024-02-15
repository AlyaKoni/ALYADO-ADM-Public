@echo off
if not exist C:\ProgramData\AlyaConsulting mkdir C:\ProgramData\AlyaConsulting
if not exist C:\ProgramData\AlyaConsulting\Logs mkdir C:\ProgramData\AlyaConsulting\Logs
for /f %%a in ('powershell.exe -Command "Get-Date -format yyyyMMddHHmmssfff"') do set Timestamp=%%a
set Timestamp=%Timestamp: =0%
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -File "%~dp0Uninstall.ps1" 2>&1 1>>C:\ProgramData\AlyaConsulting\Logs\Uninstall.cmd-%Timestamp%.log
set RETURNCODE=%ERRORLEVEL%
echo RETURNCODE: %RETURNCODE% 1>>C:\ProgramData\AlyaConsulting\Logs\Uninstall.cmd-%Timestamp%.log
EXIT /B %RETURNCODE%
