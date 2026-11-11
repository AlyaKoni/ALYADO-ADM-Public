#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2026

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
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
    09.11.2026 Konrad Brunner       Initial version
    09.11.2026 Konrad Brunner       Fixed the connect sync retrieval: unwrapped the value collection and read the features property
    09.11.2026 Konrad Brunner       Forbidden (403) responses now abort the script with a terminating error
#>

<#
.SYNOPSIS
Retrieves the state of the Microsoft Entra ID sync services (Connect Sync and Cloud Sync).

.DESCRIPTION
The Get-EntraSyncState.ps1 script connects to Microsoft Graph and collects the synchronization state of the tenant. It returns one result object with the general sync state (SyncEnabled, LastSyncDateTime, LastPasswordSyncDateTime) and two service detail objects. CloudSync contains the Microsoft Entra Connect Cloud Sync configurations (the AD2AAD service principals with their synchronization jobs, target domains and notification settings). ConnectSync contains the Microsoft Entra Connect Sync state (the beta onPremisesSynchronization service configuration and features). The beta endpoints are queried through the Graph REST API, because the Microsoft Graph PowerShell modules do not provide GA cmdlets for them. Forbidden (403) responses mean a missing permission and abort the script immediately with a terminating error, so a missing permission never produces a misleading result. Other failing detail queries are logged and recorded in the Errors property of the result object without stopping the overall retrieval.

.INPUTS
None. The script does not accept pipeline input.

.OUTPUTS
One result object with SyncEnabled, CloudSync and ConnectSync information.
Creates a log file in the defined logs directory.

.EXAMPLE
PS> .\Get-EntraSyncState.ps1

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
)

# Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transcript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Get-EntraSyncState-$($AlyaTimeString).log" | Out-Null

# Constants
$CloudSyncAppId = "1a4721b3-e57f-4451-ae87-ef078703ec94" # AD2AAD application template id used by Entra Cloud Sync

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"

# Logins
LoginTo-MgGraph -Scopes @("Organization.Read.All", "Application.Read.All", "OnPremDirectorySynchronization.Read.All")

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Get-EntraSyncState | GRAPH" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Reads a property from a Graph REST response object. Invoke-MgGraphRequest returns Hashtables by
# default, but PSObject based responses are supported as well.
function Get-GraphPropertyValue
{
    [CmdletBinding()]
    Param(
        [Parameter()]
        [AllowNull()]
        [object]$GraphObject,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    if ($null -eq $GraphObject)
    {
        return $null
    }
    if ($GraphObject -is [System.Collections.IDictionary])
    {
        if (([System.Collections.IDictionary]$GraphObject).Contains($Name))
        {
            return ([System.Collections.IDictionary]$GraphObject)[$Name]
        }
        return $null
    }
    $property = $GraphObject.PSObject.Properties[$Name]
    if ($null -ne $property)
    {
        return $property.Value
    }
    return $null
}

# Fetches all objects of a paged Graph REST collection
function Get-GraphRestCollection
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )
    $collectionItems = [System.Collections.Generic.List[object]]::new()
    $nextLink = $Uri
    while (-Not [string]::IsNullOrWhiteSpace($nextLink))
    {
        $response = Invoke-MgGraphRequest -Method Get -Uri $nextLink -ErrorAction Stop
        $pageValue = Get-GraphPropertyValue -GraphObject $response -Name "value"
        if ($null -ne $pageValue)
        {
            foreach ($collectionItem in @($pageValue))
            {
                $collectionItems.Add($collectionItem)
            }
        }
        $nextLink = Get-GraphPropertyValue -GraphObject $response -Name "@odata.nextLink"
    }
    $collectionItems.ToArray()
}

# Parses a JSON string secret value of a synchronization configuration
function ConvertFrom-SyncSecretValue
{
    [CmdletBinding()]
    Param(
        [Parameter()]
        [AllowNull()]
        [string]$Value
    )
    if ([string]::IsNullOrWhiteSpace($Value))
    {
        return $null
    }
    return ConvertFrom-Json -InputObject $Value
}

# Checks a caught error for a 403/Forbidden Graph response. Missing permissions must never
# produce misleading results, therefore such errors abort the whole retrieval.
function Test-GraphForbiddenError
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$CaughtError
    )
    if ($null -eq $CaughtError)
    {
        return $false
    }
    $exception = $CaughtError.Exception
    if ($null -eq $exception)
    {
        $exception = $CaughtError
    }
    while ($null -ne $exception)
    {
        if ($exception.Message -match "Forbidden|\b403\b")
        {
            return $true
        }
        $exception = $exception.InnerException
    }
    return $false
}

$errorMessages = [System.Collections.Generic.List[string]]::new()

# =============================================================
# General tenant synchronization state
# =============================================================

Write-Host "Reading organization information" -ForegroundColor $CommandInfo
$tenantId = $null
$tenantDisplayName = $null
$syncEnabled = $null
$lastSyncDateTime = $null
$lastPasswordSyncDateTime = $null
try
{
    $organizationResponse = Invoke-MgGraphRequest -Method Get -Uri "https://graph.microsoft.com/beta/organization" -ErrorAction Stop
    $organizations = @(Get-GraphPropertyValue -GraphObject $organizationResponse -Name "value")
    if ($organizations.Count -gt 0)
    {
        $organization = $organizations[0]
        $tenantId = Get-GraphPropertyValue -GraphObject $organization -Name "id"
        $tenantDisplayName = Get-GraphPropertyValue -GraphObject $organization -Name "displayName"
        $syncEnabled = Get-GraphPropertyValue -GraphObject $organization -Name "onPremisesSyncEnabled"
        $lastSyncDateTime = Get-GraphPropertyValue -GraphObject $organization -Name "onPremisesLastSyncDateTime"
        $lastPasswordSyncDateTime = Get-GraphPropertyValue -GraphObject $organization -Name "onPremisesLastPasswordSyncDateTime"
    }
    else
    {
        $errorMessages.Add("Organization: the Graph response did not contain an organization object")
        Write-Host "  The organization response did not contain an organization object" -ForegroundColor $CommandError
    }
}
catch
{
    if (Test-GraphForbiddenError -CaughtError $_)
    {
        Write-Host "  Forbidden (403) while reading the organization: missing permission, aborting." -ForegroundColor $CommandError
        throw
    }
    $errorMessages.Add("Organization: $($_.Exception.Message)")
    Write-Host "  Reading the organization failed: $($_.Exception.Message)" -ForegroundColor $CommandError
}

# =============================================================
# Cloud Sync (Microsoft Entra Connect Cloud Sync)
# =============================================================

Write-Host "Reading cloud sync information" -ForegroundColor $CommandInfo
$cloudSyncConfigurations = [System.Collections.Generic.List[object]]::new()
try
{
    $cloudSyncServicePrincipals = @(Get-GraphRestCollection -Uri "https://graph.microsoft.com/beta/servicePrincipals?`$filter=appId eq '$($CloudSyncAppId)'")
    foreach ($cloudSyncServicePrincipal in $cloudSyncServicePrincipals)
    {
        $servicePrincipalId = Get-GraphPropertyValue -GraphObject $cloudSyncServicePrincipal -Name "id"
        $servicePrincipalDisplayName = Get-GraphPropertyValue -GraphObject $cloudSyncServicePrincipal -Name "displayName"
        Write-Host "  Found cloud sync configuration '$($servicePrincipalDisplayName)' ($($servicePrincipalId))"

        # Synchronization jobs of the configuration
        $syncJobs = @()
        try
        {
            $jobItems = @(Get-GraphRestCollection -Uri "https://graph.microsoft.com/beta/servicePrincipals/$($servicePrincipalId)/synchronization/jobs")
            $jobList = [System.Collections.Generic.List[object]]::new()
            foreach ($jobItem in $jobItems)
            {
                $jobList.Add([PSCustomObject]@{
                    Id         = Get-GraphPropertyValue -GraphObject $jobItem -Name "id"
                    TemplateId = Get-GraphPropertyValue -GraphObject $jobItem -Name "templateId"
                    Schedule   = Get-GraphPropertyValue -GraphObject $jobItem -Name "schedule"
                    Status     = Get-GraphPropertyValue -GraphObject $jobItem -Name "status"
                })
            }
            $syncJobs = $jobList.ToArray()
        }
        catch
        {
            if (Test-GraphForbiddenError -CaughtError $_)
            {
                Write-Host "    Forbidden (403) while reading the synchronization jobs: missing permission, aborting." -ForegroundColor $CommandError
                throw
            }
            $errorMessages.Add("CloudSync jobs ($($servicePrincipalId)): $($_.Exception.Message)")
            Write-Host "    Reading the synchronization jobs failed: $($_.Exception.Message)" -ForegroundColor $CommandError
        }

        # Secrets of the configuration (target domain and notification settings)
        $targetDomain = $null
        $notificationSettings = $null
        try
        {
            $secrets = @(Get-GraphRestCollection -Uri "https://graph.microsoft.com/beta/servicePrincipals/$($servicePrincipalId)/synchronization/secrets")
            foreach ($secret in $secrets)
            {
                $secretKey = Get-GraphPropertyValue -GraphObject $secret -Name "key"
                $secretValue = Get-GraphPropertyValue -GraphObject $secret -Name "value"
                if ($secretKey -eq "Domain")
                {
                    $domainSettings = ConvertFrom-SyncSecretValue -Value $secretValue
                    $targetDomain = Get-GraphPropertyValue -GraphObject $domainSettings -Name "domain"
                }
                elseif ($secretKey -eq "SyncNotificationSettings")
                {
                    $notificationSettings = ConvertFrom-SyncSecretValue -Value $secretValue
                }
            }
        }
        catch
        {
            if (Test-GraphForbiddenError -CaughtError $_)
            {
                Write-Host "    Forbidden (403) while reading the synchronization secrets: missing permission, aborting." -ForegroundColor $CommandError
                throw
            }
            $errorMessages.Add("CloudSync secrets ($($servicePrincipalId)): $($_.Exception.Message)")
            Write-Host "    Reading the synchronization secrets failed: $($_.Exception.Message)" -ForegroundColor $CommandError
        }

        $cloudSyncConfigurations.Add([PSCustomObject]@{
            ServicePrincipalId    = $servicePrincipalId
            DisplayName           = $servicePrincipalDisplayName
            AppId                 = Get-GraphPropertyValue -GraphObject $cloudSyncServicePrincipal -Name "appId"
            ApplicationTemplateId = Get-GraphPropertyValue -GraphObject $cloudSyncServicePrincipal -Name "applicationTemplateId"
            TargetDomain          = $targetDomain
            NotificationSettings  = $notificationSettings
            SyncJobs              = $syncJobs
        })
    }
}
catch
{
    if (Test-GraphForbiddenError -CaughtError $_)
    {
        Write-Host "  Forbidden (403) while reading the cloud sync service principals: missing permission, aborting." -ForegroundColor $CommandError
        throw
    }
    $errorMessages.Add("CloudSync: $($_.Exception.Message)")
    Write-Host "  Reading the cloud sync service principals failed: $($_.Exception.Message)" -ForegroundColor $CommandError
}

# =============================================================
# Connect Sync (Microsoft Entra Connect Sync)
# =============================================================

Write-Host "Reading connect sync information" -ForegroundColor $CommandInfo
$connectSyncServiceConfigurationId = $null
$connectSyncConfiguration = $null
$connectSyncFeature = $null
try
{
    $onPremisesSyncResponse = Invoke-MgGraphRequest -Method Get -Uri "https://graph.microsoft.com/beta/directory/onPremisesSynchronization" -ErrorAction Stop
    # The collection endpoint returns {"value":[{...}]} (one singleton per tenant), only the call with
    # the tenant id returns the object directly. The detail property is named "features" (plural).
    $onPremisesSyncObjects = @(Get-GraphPropertyValue -GraphObject $onPremisesSyncResponse -Name "value")
    if ($onPremisesSyncObjects.Count -gt 0)
    {
        $onPremisesSyncObject = $onPremisesSyncObjects[0]
    }
    else
    {
        $onPremisesSyncObject = $onPremisesSyncResponse
    }
    $connectSyncServiceConfigurationId = Get-GraphPropertyValue -GraphObject $onPremisesSyncObject -Name "id"
    $connectSyncConfiguration = Get-GraphPropertyValue -GraphObject $onPremisesSyncObject -Name "configuration"
    $connectSyncFeature = Get-GraphPropertyValue -GraphObject $onPremisesSyncObject -Name "features"
}
catch
{
    if (Test-GraphForbiddenError -CaughtError $_)
    {
        Write-Host "  Forbidden (403) while reading the connect sync service configuration: missing permission, aborting." -ForegroundColor $CommandError
        throw
    }
    $errorMessages.Add("ConnectSync: $($_.Exception.Message)")
    Write-Host "  Reading the connect sync service configuration failed: $($_.Exception.Message)" -ForegroundColor $CommandError
}
$connectSyncAvailable = (-Not [string]::IsNullOrWhiteSpace($connectSyncServiceConfigurationId)) -or ($null -ne $connectSyncConfiguration) -or ($null -ne $connectSyncFeature)

# =============================================================
# Result
# =============================================================

$result = [PSCustomObject]@{
    TenantId                 = $tenantId
    TenantDisplayName        = $tenantDisplayName
    SyncEnabled              = $syncEnabled
    LastSyncDateTime         = $lastSyncDateTime
    LastPasswordSyncDateTime = $lastPasswordSyncDateTime
    RetrievedAt              = [DateTime]::UtcNow
    CloudSync                = [PSCustomObject]@{
        Available          = $cloudSyncConfigurations.Count -gt 0
        ConfigurationCount = $cloudSyncConfigurations.Count
        Configurations     = $cloudSyncConfigurations.ToArray()
    }
    ConnectSync              = [PSCustomObject]@{
        Available              = $connectSyncAvailable
        ServiceConfigurationId = $connectSyncServiceConfigurationId
        Configuration          = $connectSyncConfiguration
        Feature                = $connectSyncFeature
    }
    Errors                   = $errorMessages.ToArray()
}

Write-Host "`nSync state summary" -ForegroundColor $CommandInfo
Write-Host "  SyncEnabled: $($syncEnabled)"
Write-Host "  LastSyncDateTime: $($lastSyncDateTime)"
Write-Host "  LastPasswordSyncDateTime: $($lastPasswordSyncDateTime)"
Write-Host "  CloudSync configurations: $($cloudSyncConfigurations.Count)"
Write-Host "  ConnectSync available: $($connectSyncAvailable)"
if ($errorMessages.Count -gt 0)
{
    Write-Host "  Errors: $($errorMessages.Count)" -ForegroundColor $CommandError
}

$result

# Stopping Transcript
Stop-Transcript | Out-Null
