@echo off
call "%~dp0..\Shared.cmd"
PWSH.exe -ExecutionPolicy Bypass -NoLogo -NoExit -File "%~dp0%~n0.ps1"
