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
    26.10.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Download-AdminTemplates-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Download-AdminTemplates | Local" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Main
$dataRoot = Join-Path (Join-Path $AlyaData "intune") "Policies"
if (-Not (Test-Path $dataRoot))
{
    New-Item -Path $dataRoot -ItemType Directory -Force | Out-Null
}

# Office apps admx templates
Write-Host "Office apps" -ForegroundColor $CommandInfo
$url = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=49030"
$req = Invoke-WebRequestIndep -Uri $url -UseBasicParsing -Method Get
[regex]$regex = "[^`"]*admintemplates_x64[^`"]*.exe"
$newUrl = [regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
$fileName = Split-Path $newUrl -Leaf
Invoke-WebRequest -Uri $newUrl -OutFile "$dataRoot\$fileName"
if (-Not (Test-Path "$dataRoot\OfficeApps"))
{
    New-Item -Path "$dataRoot\OfficeApps" -ItemType Directory -Force | Out-Null
}
Push-Location "$dataRoot"
Write-Host "  Please accept the UAC prompt"
cmd /c ".\$fileName" /quiet /extract:.\OfficeApps
Pop-Location 
Remove-Item -Path "$dataRoot\$fileName" -Force

Write-Host "Policies downloaded to $dataRoot" -ForegroundColor $CommandSuccess

#Stopping Transscript
Stop-Transcript
