#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2024

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
    31.05.2024 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\teams\Clean-TeamsCache-$($AlyaTimeString).log" | Out-Null

# =============================================================
# Teams stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Teams | Clean-TeamsCache | Teams" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

if (-Not $AlyaIsPsUnix)
{
    Write-Host "Cleaning new teams cache"
    Write-Host "  C:\Users\$env:UserName\AppData\Local\Packages\MSTeams_8wekyb3d8bbwe"
    if (Test-Path "C:\Users\$env:UserName\AppData\Local\Packages\MSTeams_8wekyb3d8bbwe")
    {
        Remove-Item -Path "C:\Users\$env:UserName\AppData\Local\Packages\MSTeams_8wekyb3d8bbwe" -Recurse -Force
    }

    Write-Host "Cleaning classic teams cache"
    Write-Host "  $env:AppData\Microsoft\Teams"
    if (Test-Path "$env:AppData\Microsoft\Teams")
    {
        Remove-Item -Path "$env:AppData\Microsoft\Teams" -Recurse -Force
    }
}
else
{
    Write-Host "Cleaning new teams cache"
    Write-Host "  ~/Library/Group Containers/UBF8T346G9.com.microsoft.teams"
    if (Test-Path "~/Library/Group Containers/UBF8T346G9.com.microsoft.teams")
    {
        Remove-Item -Path "~/Library/Group Containers/UBF8T346G9.com.microsoft.teams" -Recurse -Force
    }
    Write-Host "  ~/Library/Containers/com.microsoft.teams2"
    if (Test-Path "~/Library/Containers/com.microsoft.teams2")
    {
        Remove-Item -Path "~/Library/Containers/com.microsoft.teams2" -Recurse -Force
    }

    Write-Host "Cleaning classic teams cache"
    Write-Host "  ~/Library/Application\ Support/Microsoft/Teams"
    if (Test-Path "~/Library/Application\ Support/Microsoft/Teams")
    {
        Remove-Item -Path "~/Library/Application\ Support/Microsoft/Teams" -Recurse -Force
    }
}

#Stopping Transscript
Stop-Transcript
