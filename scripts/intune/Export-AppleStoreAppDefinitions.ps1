#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2021

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
    Alya Basis Konfiguration ist Freie Software: Sie koennen es unter den
	Bedingungen der GNU General Public License, wie von der Free Software
	Foundation, Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
    veroeffentlichten Version, weiter verteilen und/oder modifizieren.
    Alya Basis Konfiguration wird in der Hoffnung, dass es nuetzlich sein wird,
	aber OHNE JEDE GEWAEHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewaehrleistung der MARKTFAEHIGKEIT oder EIGNUNG FUER EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Public License fuer weitere Details:
	https://www.gnu.org/licenses/gpl-3.0.txt

    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    23.04.2021 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Export-AppleStoreAppDefinitions-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Export-AppleStoreAppDefinitions | Apple" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

$req = Invoke-WebRequest -SkipHttpErrorCheck -Method Get -Uri "https://apps.apple.com/de/developer/microsoft-corporation/id298856275#see-all/i-phonei-pad-apps" -UseBasicParsing
[regex]$regex = "[^`";&?]*/app/[^`";&?]*/id(\d*)"
$matches = ([regex]::Matches($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant'))
$appIds = @()
foreach ($match in $matches)
{
    $appIds += $match.Groups[1].Value
}
$appIds = $appIds | Select-Object -Unique
$appDefs = @()
foreach ($appId in $appIds)
{
    $req = Invoke-WebRequest -SkipHttpErrorCheck -Method Get -Uri ("https://itunes.apple.com/lookup?id="+$appId) -UseBasicParsing
    $def = $req.Content | ConvertFrom-Json
    $appDefs += $def.results[0]
}

$filePath = "$AlyaData\intune\appleAppDefinitions.json"
$appDefs | ConvertTo-Json -Depth 100 | Set-Content -Path $filePath -Encoding UTF8 -Force
Write-Host "Apple Store app defintions exported to: $filePath" -ForegroundColor $CommandSuccess

#Stopping Transscript
Stop-Transcript
