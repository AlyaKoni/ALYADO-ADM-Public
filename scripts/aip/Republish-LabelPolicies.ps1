#Requires -Version 5.0

<#
    Copyright (c) Alya Consulting, 2023

    This file is part of the Alya Base Configuration.
	https://alyaconsulting.ch/Loesungen/BasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
	and/or modify it under the terms of the GNU General Publabel labelense as
	published by the Free Software Foundation, either version 3 of the
	labelense, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
	Publabel labelense for more details: https://www.gnu.org/labelenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
	https://alyaconsulting.ch/Loesungen/BasisKonfiguration
    Alya Basis Konfiguration ist Freie Software: Sie koennen es unter den
	Bedingungen der GNU General Publabel labelense, wie von der Free Software
	Foundation, Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
    veroeffentlabelhten Version, weiter verteilen und/oder modifizieren.
    Alya Basis Konfiguration wird in der Hoffnung, dass es nuetzlabelh sein wird,
	aber OHNE JEDE GEWAEHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewaehrleistung der MARKTFAEHIGKEIT oder EIGNUNG FUER EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Publabel labelense fuer weitere Details:
	https://www.gnu.org/labelenses/gpl-3.0.txt

    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    15.02.2023 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$inputPublishFile = $null #Defaults to "$AlyaData\aip\PublishProfiles.xlsx"
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\onprem\Republish-LabelPolicies-$($AlyaTimeString).log" | Out-Null

#Members
if (-Not $inputPublishFile)
{
    $inputPublishFile = "$AlyaData\aip\PublishProfiles.xlsx"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"
Install-ModuleIfNotInstalled "ImportExcel"

# Reading inputPublishFile file
Write-Host "Reading publish file from '$inputPublishFile'" -ForegroundColor $CommandInfo
if (-Not (Test-Path $inputPublishFile))
{
    throw "'$inputPublishFile' not found!"
}
$publishDefs = Import-Excel $inputPublishFile

# Logins
LoginTo-IPPS

# =============================================================
# Exchange stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "UnifiedLabels | Republish-LabelPolicies | EXCHANGE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Configuring labels
try
{

    Write-Host "Retrying distribution of Publish profiles in exchange"
    foreach($publishDef in $publishDefs)
    {
        if (-Not [string]::IsNullOrEmpty($publishDef.ProfileName))
        {
            Write-Host "  Publish profile: $($publishDef.ProfileName)"
            Set-LabelPolicy -Identity $publishDef.ProfileName -RetryDistribution
        }
    }

    Write-Host "Actually configured policies"
    Get-LabelPolicy | Format-Table -Property DisplayName, Name, DistributionStatus, Guid
}
catch
{
    try { Write-Error ($_.Exception | ConvertTo-Json -Depth 3) -ErrorAction Continue } catch {}
	Write-Error ($_.Exception) -ErrorAction Continue
}
finally
{
    DisconnectFrom-EXOandIPPS
}

#Stopping Transscript
Stop-Transcript
