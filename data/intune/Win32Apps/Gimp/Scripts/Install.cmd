@echo off
set Timestamp=%date:~6,4%%date:~3,2%%date:~0,2%%time:~0,2%%time:~3,2%%time:~6,2%
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -File "%~dp0Install.ps1" 2>&1 1>>C:\AlyaConsulting\Logs\Install.cmd-%Timestamp%.log
set RETURNCODE=%ERRORLEVEL%
echo RETURNCODE: %RETURNCODE% 1>>C:\AlyaConsulting\Logs\Install.cmd-%Timestamp%.log
EXIT /B %RETURNCODE%
