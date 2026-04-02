@echo off

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

if not exist C:\ProgramData\AlyaConsulting mkdir C:\ProgramData\AlyaConsulting
if not exist C:\ProgramData\AlyaConsulting\Logs mkdir C:\ProgramData\AlyaConsulting\Logs
set Timestamp=%date:~6,4%%date:~3,2%%date:~0,2%%time:~0,2%%time:~3,2%%time:~6,2%
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -File "%~dp0Install.ps1" 2>&1 1>>C:\ProgramData\AlyaConsulting\Logs\Install.cmd-%Timestamp%.log
set RETURNCODE=%ERRORLEVEL%
echo RETURNCODE: %RETURNCODE% 1>>C:\ProgramData\AlyaConsulting\Logs\Install.cmd-%Timestamp%.log
EXIT /B %RETURNCODE%
