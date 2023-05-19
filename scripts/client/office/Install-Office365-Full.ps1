#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2023

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


    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    06.11.2019 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\client\office\Install-Office365-Full-$($AlyaTimeString).log" | Out-Null

#Checking prepare tool
& "$PSScriptRoot\Prepare-DeployTool.ps1"

#Installing office
Write-Host "Downloading office to $($AlyaTemp)\Office" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$AlyaTemp\Office"))
{
    $tmp = New-Item -Path "$AlyaTemp\Office" -ItemType Directory -Force
}
Push-Location "$AlyaTemp\Office"
cmd /c"$AlyaDeployToolRoot\setup.exe" /download "$AlyaData\client\office\office_full_deploy_config.xml"

Write-Host "Installing office" -ForegroundColor $CommandInfo
cmd /c"$AlyaDeployToolRoot\setup.exe" /configure "$AlyaData\client\office\office_full_deploy_config.xml"
Pop-Location

if (-Not (Test-Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Word.lnk"))
{
    Write-Error "Something went wrong. Please install office by hand with the following command: '$AlyaDeployToolRoot\setup.exe' /configure '$AlyaData\client\office\office_Only_deploy_config.xml'" -ErrorAction Continue
    exit 99
}

Write-Host "Cleaning downloads" -ForegroundColor $CommandInfo
Remove-Item -Path "$AlyaTemp\Office" -Recurse -Force

#Stopping Transscript
Stop-Transcript
