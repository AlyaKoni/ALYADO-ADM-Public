@echo off
call "%~dp0..\Shared.cmd"
powershell.exe -ExecutionPolicy Bypass -NoLogo -NoExit -File "%~dp0%~n0.ps1"
