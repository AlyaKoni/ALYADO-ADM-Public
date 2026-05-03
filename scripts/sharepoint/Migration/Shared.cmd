@echo off
if exist "C:\Program Files\PowerShell\7\pwsh.exe" goto FOUND
echo *** Can't find pwsh.exe in C:\Program Files\PowerShell\7
echo *** Please edit Shared.cmd with the correct path to pwsh.exe
exit
:FOUND
set PATH=C:\Program Files\PowerShell\7;%PATH%
