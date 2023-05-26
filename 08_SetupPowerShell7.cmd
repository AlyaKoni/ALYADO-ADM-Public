goto :COMMENTS
    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Loesungen/BasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Loesungen/BasisKonfiguration
    Die Alya Basis Konfiguration ist eine Freie Software: Sie können sie unter den
    Bedingungen der GNU General Public License, wie von der Free Software
    Foundation, Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
    veröffentlichten Version, weiter verteilen und/oder modifizieren.
    Die Alya Basis Konfiguration wird in der Hoffnung, dass sie nützlich sein wird,
    aber OHNE JEDE GEWÄHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewährleistung der MARKTFÄHIGKEIT oder EIGNUNG FUER EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Public License fuer weitere Details:
    https://www.gnu.org/licenses/gpl-3.0.txt
:COMMENTS

net session >nul 2>&1
if %errorLevel% NEQ 0 (
	echo Failure: You need to run this script with administrative permissions
	pause
	EXIT /B 65
) else (
	echo Installing or updating PowerShell 7
	pause
	rem [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Invoke-Expression "& { $(Invoke-RestMethod https://aka.ms/install-powershell.ps1) } -UseMSI"'))
	PowerShell -NoProfile -ExecutionPolicy Bypass -EncodedCommand SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAIgAmACAAewAgACQAKABJAG4AdgBvAGsAZQAtAFIAZQBzAHQATQBlAHQAaABvAGQAIABoAHQAdABwAHMAOgAvAC8AYQBrAGEALgBtAHMALwBpAG4AcwB0AGEAbABsAC0AcABvAHcAZQByAHMAaABlAGwAbAAuAHAAcwAxACkAIAB9ACAALQBVAHMAZQBNAFMASQAiAA==
	echo Installing or updating Visual Studio Code
	pause
	Install-Script Install-VSCode -Scope CurrentUser
    Install-VSCode.ps1
	echo Configure Visual Studio Code:
	echo - Set terminal.integrated.shell.windows to C:\Program Files\PowerShell\7\pwsh.exe
	echo - Set files.encoding to utf8bom
	echo - Install the PowerShell Extension
	pause
)
