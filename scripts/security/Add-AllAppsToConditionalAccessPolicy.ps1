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
    27.06.2022 Konrad Brunner       Initial Version
    16.09.2022 Konrad Brunner       More stable error handling
    20.09.2022 Konrad Brunner       New handling by parsing error message

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
$appsWithErrorExcluded = @()
$appsWithErrorIncluded = @()
#($allApps | Where-Object { $_.DisplayName -like "*Azure*" }).DisplayName
#($allApps | Where-Object { $_.DisplayName -like "*Admin*" }).DisplayName
#($allApps | Where-Object { $_.AppId -eq "0c1307d4-29d6-4389-a11c-5cbe7f65d7fa" }).DisplayName
#($allApps | Where-Object { $_.Id -eq "0c1307d4-29d6-4389-a11c-5cbe7f65d7fa" }).DisplayName

# Getting conditional access policy
Write-Host "Getting conditional access policy" -ForegroundColor $CommandInfo
$policies = (Invoke-AzRestMethod -Uri "$AlyaGraphEndpoint/beta/identity/conditionalAccess/policies").Content | ConvertFrom-Json
$policyId = ($policies.value | Where-Object { $_.displayName -eq $condAccessRuleName }).id
if (-Not $policyId)
{
	throw "Policy $condAccessRuleName not found"
}
$policy = Get-AzureADMSConditionalAccessPolicy -PolicyId $policyId
if (-Not $policy.Conditions)
{
	throw "Not yet implemented: empty `$policy.Conditions"
}
if (-Not $policy.Conditions.Applications)
{
    $policy.Conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
    $policy.Conditions.Applications.IncludeApplications = @('none')
    $policy.Conditions.Applications.ExcludeApplications = @()
    Set-AzureADMSConditionalAccessPolicy -PolicyId $policy.id -Conditions $policy.Conditions
    $policy = Get-AzureADMSConditionalAccessPolicy -PolicyId $policy.id
}

# Setting excluded apps
Write-Host "Setting excluded apps" -ForegroundColor $CommandInfo
$dirty = $true
$appsEx = $appIdsToExclude
$unSupportedFirstyPartyApplications = @()
while ($true)
{
    foreach ($app in $unSupportedFirstyPartyApplications)
    {
        if ($appsEx -contains $app)
        {
		    $appsEx = $appsEx | Where-Object { $_ -ne $app }
            $dirty = $true
        }
    }
    if ($dirty)
    {
        $dirty = $false
        $policy.Conditions.Applications.ExcludeApplications = $appsEx
        $retries = 10
        $wTime = 2
        try
        {
            Write-Host "  Saving ExcludeApplications"
            Set-AzureADMSConditionalAccessPolicy -PolicyId $policy.id -Conditions $policy.Conditions
            break
        }
        catch
        {
            if ($_.Exception.ToString() -like "*HttpStatusCode: 429*" -or $_.Exception.ToString() -like "*HttpStatusCode: 503*")
            {
                $retries = $retries - 1
                Write-Host "  TooManyRequests, retrying." -ForegroundColor $CommandError
                if ($retries -lt 0)
                {
                    throw
                }
                Start-Sleep -Seconds $wTime
                $wTime = $wTime * 2
            }
            else
            {
                if ($_.Exception.ToString() -like "*HttpStatusCode: InternalServerError*")
                {
                    $retries = $retries - 1
                    Write-Host "  InternalServerError, retrying." -ForegroundColor $CommandError
                    if ($retries -lt 0)
                    {
                        throw
                    }
                    Start-Sleep -Seconds $wTime
				    $wTime = $wTime * 2
                }
                else
                {
                    $errorMsg = $_.Exception.ToString()
                    $chk = "Policy contains invalid applications: "
                    if ($errorMsg.IndexOf($chk) -gt -1)
                    {
                        $errorMsg = $errorMsg.Substring($errorMsg.IndexOf($chk) + $chk.Length)
                        $errorMsg = $errorMsg.Substring(0, $errorMsg.IndexOf("}")+1)
   		                Write-Host "  Removing UnSupportedFirstyParty apps from ExcludeApplications: $errorMsg" -ForegroundColor $CommandWarning
                        $errs = $errorMsg | ConvertFrom-Json
                        foreach($app in (Get-Member -InputObject $errs -MemberType NoteProperty))
                        {
                            $unSupportedFirstyPartyApplications += $app.Name
                        }
                    }
                    else
                    {
                        throw
                    }
                }
            }
        }
    }
}

# Setting icluded apps
Write-Host "Setting icluded apps" -ForegroundColor $CommandInfo
$dirty = $true
$appsIn = $allApps.AppId | Select-Object -Unique
$unSupportedFirstyPartyApplications = @()
while ($true)
{
    foreach ($app in $appIdsToExclude)
    {
        if ($appsIn -contains $app)
        {
   		    Write-Host "  Removing excluded app $app from IncludeApplications" -ForegroundColor $CommandWarning
		    $appsIn = $appsIn | Where-Object { $_ -ne $app }
            $dirty = $true
        }
    }
    foreach ($app in $unSupportedFirstyPartyApplications)
    {
        if ($appsIn -contains $app)
        {
		    $appsIn = $appsIn | Where-Object { $_ -ne $app }
            $dirty = $true
        }
    }
    if ($dirty)
    {
        $dirty = $false
        $policy.Conditions.Applications.IncludeApplications = $appsIn
        $retries = 10
        $wTime = 2
        try
        {
            Write-Host "  Saving IncludeApplications"
            Set-AzureADMSConditionalAccessPolicy -PolicyId $policy.id -Conditions $policy.Conditions
            break
        }
        catch
        {
            if ($_.Exception.ToString() -like "*HttpStatusCode: 429*" -or $_.Exception.ToString() -like "*HttpStatusCode: 503*")
            {
                $retries = $retries - 1
                Write-Host "  TooManyRequests, retrying." -ForegroundColor $CommandError
                if ($retries -lt 0)
                {
                    throw
                }
                Start-Sleep -Seconds $wTime
                $wTime = $wTime * 2
            }
            else
            {
                if ($_.Exception.ToString() -like "*HttpStatusCode: InternalServerError*")
                {
                    $retries = $retries - 1
                    Write-Host "  InternalServerError, retrying." -ForegroundColor $CommandError
                    if ($retries -lt 0)
                    {
                        throw
                    }
                    Start-Sleep -Seconds $wTime
				    $wTime = $wTime * 2
                }
                else
                {
                    $errorMsg = $_.Exception.ToString()
                    $chk = "Policy contains invalid applications: "
                    if ($errorMsg.IndexOf($chk) -gt -1)
                    {
                        $errorMsg = $errorMsg.Substring($errorMsg.IndexOf($chk) + $chk.Length)
                        $errorMsg = $errorMsg.Substring(0, $errorMsg.IndexOf("}")+1)
   		                Write-Host "  Removing UnSupportedFirstyParty apps from IncludeApplications: $errorMsg" -ForegroundColor $CommandWarning
                        $errs = $errorMsg | ConvertFrom-Json
                        foreach($app in (Get-Member -InputObject $errs -MemberType NoteProperty))
                        {
                            $unSupportedFirstyPartyApplications += $app.Name
                        }
                    }
                    else
                    {
                        throw
                    }
                }
            }
        }
    }
}
Write-Host "Policy has now $($appsIn.Count) included and $($appsEx.Count) excluded apps assigned" -ForegroundColor $CommandInfo

#Stopping Transscript
Stop-Transcript
