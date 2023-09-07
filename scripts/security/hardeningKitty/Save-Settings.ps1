#Requires -Version 2.0
#Requires -RunAsAdministrator

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
    10.08.2023 Konrad Brunner       Initial Version

#>
[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\data\security\hardeningKitty\Save-Settings-$($AlyaTimeString).log" -IncludeInvocationHeader -Force | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
$versionFolder = Get-ChildItem "$Env:ProgramFiles\WindowsPowerShell\Modules\HardeningKitty" | Select-object -Last 1
Import-Module "$($versionFolder.FullName)\HardeningKitty.psm1"

# =============================================================
# Local stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "HardeningKitty | Save-Settings | Local" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

$repDir = "$AlyaData\security\HardeningKitty\settings$AlyaTimeString"
if (-Not (Test-Path $repDir))
{
    New-Item -Path $repDir -ItemType Directory -Force
}

Set-Location $repDir
Invoke-HardeningKitty -Mode Config -Report -ReportFile settings.csv
Write-Host "Settings stored in $repDir"
