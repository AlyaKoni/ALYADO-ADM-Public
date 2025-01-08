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
    18.10.2024 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\teams\Disable-TeamsAIFeatures-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "MicrosoftTeams"

# Logins
LoginTo-Teams

# =============================================================
# Teams stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Teams | Disable-TeamsAIFeatures | Teams" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Checking EnrollFace
Write-Host "Checking EnrollFace" -ForegroundColor $CommandInfo
$Policy = Get-CsTeamsAIPolicy -Identity Global
if ($Policy.EnrollFace -ne "Disabled")
{
    Write-Warning "EnrollFace was set to '$($Policy.EnrollFace)'. Setting now to 'Disabled'."
    Set-CsTeamsAIPolicy -Identity Global -EnrollFace  "Disabled"
}
else
{
    Write-Host "EnrollFace was already set to 'Disabled'."
}

# Checking EnrollVoice
Write-Host "Checking EnrollVoice" -ForegroundColor $CommandInfo
$Policy = Get-CsTeamsAIPolicy -Identity Global
if ($Policy.EnrollVoice -ne "Disabled")
{
    Write-Warning "EnrollVoice was set to '$($Policy.EnrollVoice)'. Setting now to 'Disabled'."
    Set-CsTeamsAIPolicy -Identity Global -EnrollVoice  "Disabled"
}
else
{
    Write-Host "EnrollVoice was already set to 'Disabled'."
}

#Stopping Transscript
Stop-Transcript
