#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2022

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
    27.06.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [string]$condAccessRuleName,
    [Parameter(Mandatory = $false)]
    [string[]]$appIdsToExclude = $null
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\security\Add-AllAppsToConditionalAccessPolicy-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "AzureAdPreview"
    
# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Add-AllAppsToConditionalAccessPolicy | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Getting all applications from tenant
Write-Host "Getting all applications from tenant" -ForegroundColor $CommandInfo
$allApps = Get-AzADApplication
$allApps += Get-AzADServicePrincipal

# Getting conditional access policy
Write-Host "Getting conditional access policy" -ForegroundColor $CommandInfo
$policy = Get-AzureADMSConditionalAccessPolicy | where { $_.displayName -eq $condAccessRuleName }
if (-Not $policy.Conditions.Applications)
{
    $policy.Conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
    $apps = @()
}
else
{
    $apps = $policy.Conditions.Applications.IncludeApplications
}

# Removing unwanted apps
Write-Host "Removing unwanted apps" -ForegroundColor $CommandInfo
$dirty = $false
foreach ($app in $appIdsToExclude)
{
    if ($apps.Contains($app))
    {
   		Write-Host "  Removing $app"
		$apps = $apps | where { $_ -ne $app }
        $apps.Remove($app)
        $dirty = $true
    }
}
if ($dirty)
{
    $policy.Conditions.Applications.IncludeApplications = $apps
    Set-AzureADMSConditionalAccessPolicy -PolicyId $policy.id -Conditions $policy.Conditions
}

# Adding apps
Write-Host "Adding apps" -ForegroundColor $CommandInfo
foreach($app in $allApps)
{
    if ($appIdsToExclude -contains $app.AppId)
    {
        Write-Host "Excluded $($app.DisplayName)" -ForegroundColor Yellow
        continue
    }
    if (-Not $apps.Contains($app.AppId))
    {
        #Start-Sleep -Seconds 10
        $appBkp = $apps
        $apps += $app.AppId
        try
        {
            $policy.Conditions.Applications.IncludeApplications = $apps
            Set-AzureADMSConditionalAccessPolicy -PolicyId $policy.id -Conditions $policy.Conditions
            Write-Host "Added $($app.DisplayName)" -ForegroundColor Green
        }
        catch
        {
            Write-Host "Can't add $($app.DisplayName)" -ForegroundColor Red
            $apps = $appBkp
        }
    }
}
Write-Host "Policy has now $($apps.Count) apps assigned" -ForegroundColor $CommandInfo

#Stopping Transscript
Stop-Transcript