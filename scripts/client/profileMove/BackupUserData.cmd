@echo off
echo Sichere Benutzerdaten. Bitte warten...
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -File "%~dp0BackupUserData.ps1"
set RETURNCODE=%ERRORLEVEL%
pause
EXIT /B %RETURNCODE%
