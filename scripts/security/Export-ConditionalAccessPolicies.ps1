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
    18.04.2024 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\security\Export-ConditionalAccessPolicies-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
    
# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Export-ConditionalAccessPolicies | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Getting conditional access policies
Write-Host "Getting conditional access policies" -ForegroundColor $CommandInfo
$policies = (Invoke-AzRestMethod -Uri "$AlyaGraphEndpoint/beta/identity/conditionalAccess/policies").Content | ConvertFrom-Json
$policies = $policies.value

# Exporting conditional access policies
if (-Not (Test-Path "$AlyaData\security"))
{
    New-Item -Path "$AlyaData\security" -ItemType Directory -Force
}
if (-Not (Test-Path "$AlyaData\security\conditionalAccessPolicies"))
{
    New-Item -Path "$AlyaData\security\conditionalAccessPolicies" -ItemType Directory -Force
}
Write-Host "Exporting conditional access policies" -ForegroundColor $CommandInfo
foreach($policy in $policies)
{
    $exPolicy = (Invoke-AzRestMethod -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies/$($policy.Id)").Content
    $exPolicy | Set-Content -Path "$AlyaData\security\conditionalAccessPolicies\$($policy.displayName)" -Encoding $AlyaUtf8Encoding -Force
}

#Stopping Transscript
Stop-Transcript
