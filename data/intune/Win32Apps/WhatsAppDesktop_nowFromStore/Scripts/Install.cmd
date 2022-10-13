@echo off
if not exist C:\ProgramData\AlyaConsulting mkdir C:\ProgramData\AlyaConsulting
if not exist C:\ProgramData\AlyaConsulting\Logs mkdir C:\ProgramData\AlyaConsulting\Logs
set Timestamp=%date:~6,4%%date:~3,2%%date:~0,2%%time:~0,2%%time:~3,2%%time:~6,2%
set Timestamp=%Timestamp: =0%
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -File "%~dp0Install.ps1" 2>&1 1>>C:\ProgramData\AlyaConsulting\Logs\Install.cmd-%Timestamp%.log
set RETURNCODE=%ERRORLEVEL%
echo RETURNCODE: %RETURNCODE% 1>>C:\ProgramData\AlyaConsulting\Logs\Install.cmd-%Timestamp%.log
EXIT /B %RETURNCODE%
