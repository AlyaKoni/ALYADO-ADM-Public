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
    21.09.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$srcCondAccessRuleName,
    [Parameter(Mandatory = $true)]
    [string]$dstCondAccessRuleName
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\security\Copy-ConditionalAccessPolicy-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "AzureAdPreview"
    
# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Copy-ConditionalAccessPolicy | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Getting source conditional access policy
Write-Host "Getting source conditional access policy" -ForegroundColor $CommandInfo
$policies = (Invoke-AzRestMethod -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies").Content | ConvertFrom-Json
$srcPolicyId = ($policies.value | Where-Object { $_.displayName -eq $srcCondAccessRuleName }).id
if (-Not $srcPolicyId)
{
	throw "Policy $srcCondAccessRuleName not found"
}
$srcPolicy = Get-AzureADMSConditionalAccessPolicy -PolicyId $srcPolicyId

# Checking destination conditional access policy
Write-Host "Checking destination conditional access policy" -ForegroundColor $CommandInfo
$dstPolicyId = ($policies.value | Where-Object { $_.displayName -eq $dstCondAccessRuleName }).id
if (-Not $dstPolicyId)
{
    Write-Warning "  Does not exist. Creating it now"
    New-AzureADMSConditionalAccessPolicy -DisplayName $dstCondAccessRuleName `
        -Conditions $srcPolicy.Conditions -GrantControls $srcPolicy.GrantControls -SessionControls $srcPolicy.SessionControls
}
else
{
    Write-Host "  Updating"
    $dstPolicy = Get-AzureADMSConditionalAccessPolicy -PolicyId $dstPolicyId
    Set-AzureADMSConditionalAccessPolicy -PolicyId $dstPolicyId -DisplayName $dstCondAccessRuleName `
        -Conditions $srcPolicy.Conditions -GrantControls $srcPolicy.GrantControls -SessionControls $srcPolicy.SessionControls
}

#Stopping Transscript
Stop-Transcript
