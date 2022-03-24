@echo off
echo Restauriere Benutzerdaten. Bitte warten...
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -File "%~dp0RestoreUserData.ps1"
set RETURNCODE=%ERRORLEVEL%
pause
EXIT /B %RETURNCODE%
