#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2020-2021

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
    14.09.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    $devopsUser = "who@alyaconsulting.onmicrosoft.com",
    $devopsToken = "????????????????????????????????????????????????????",
    $fromUsers = @("Konrad Brunner <konrad.brunner@alyaconsulting.ch>", "Konrad Brunner <konrad.brunner@alyaconsulting.ch>"),
    $toUser = "Konrad Brunner <konrad.brunner@alyaconsulting.ch>"
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\devops\Move-DevOpsTasks-$($AlyaTimeString).log" | Out-Null

# =============================================================
# DevOps stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "DevOps | Move-DevOpsTasks | DEVOPS" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main
$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $devopsUser,$devopsToken)))

$wiMin = 999999
$wiMax = 0
for ($i=1; $i -le 2100; $i++)
{
    $url = "https://mobimo.visualstudio.com/_apis/wit/workitems?ids=$($i)&api-version=4.1"
    $result = $null
    try {
        $result = Invoke-RestMethod -Uri $url -Method Get -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -ErrorAction SilentlyContinue
    } catch {}
    if ($result -and $result.count -gt 0)
    {
        if ($i -lt $wiMin) { $wiMin = $i }
        if ($i -gt $wiMax) { $wiMax = $i }
        $item = $result.value[0]
        Write-Host "Found work item $($i): $($item.fields."System.AssignedTo")"
        $assTo = $item.fields."System.AssignedTo"
        $proj = $item.fields."System.TeamProject"
        if ($fromUsers -contains $assTo)
        {
            $url = "https://mobimo.visualstudio.com/_apis/wit/workitems/$($i)?api-version=4.1"
            $body = '[{"op": "add","path": "/fields/System.AssignedTo","value": "'+$toUser+'"}]'
            Invoke-RestMethod -Uri $url -Method PATCH -ContentType "application/json-patch+json" -Body ([System.Text.Encoding]::UTF8.GetBytes($body)) -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -ErrorAction SilentlyContinue
        }
    }
    else
    {
        Write-Host "Work item $($i) does not exists"
    }
}

Write-Host "Min work item $($wiMin)"
Write-Host "Max work item $($wiMax)"

#Stopping Transscript
Stop-Transcript