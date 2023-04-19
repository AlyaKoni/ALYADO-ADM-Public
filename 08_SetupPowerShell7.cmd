@echo off
net session >nul 2>&1
if %errorLevel% NEQ 0 (
	echo Failure: You need to run this script with administrative permissions
	pause
	EXIT /B 65
) else (
	echo Installing or updating PowerShell
	rem [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Invoke-Expression "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI"'))
	PowerShell -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAIgAmACAAewAgACQAKABJAG4AdgBvAGsAZQAtAFIAZQBzAHQATQBlAHQAaABvAGQAIABoAHQAdABwAHMAOgAvAC8AYQBrAGEALgBtAHMALwBpAG4AcwB0AGEAbABsAC0AcABvAHcAZQByAHMAaABlAGwAbAAuAHAAcwAxACkAIAB9ACAALQBVAHMAZQBNAFMASQAiAA==
	pause
	rem Install-Script Install-VSCode -Scope CurrentUser; Install-VSCode.ps1
	echo For Visual Studio Code:
	echo   Set terminal.integrated.shell.windows to C:\Program Files\PowerShell\7\pwsh.exe
	echo   Install PowerShell extension
	pause
)
