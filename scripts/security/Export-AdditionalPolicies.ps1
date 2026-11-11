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
    07.11.2026 Konrad Brunner       Initial Version
    07.11.2026 Konrad Brunner       Added ChangedOnly parameter (default true), roleManagementPolicies exports only changed policies

#>

<#
.SYNOPSIS
Exports additional Microsoft Graph policy endpoints of a tenant to git friendly JSON files.

.DESCRIPTION
The Export-AdditionalPolicies.ps1 script exports a fixed catalog of additional Microsoft Graph policy
endpoints (v1.0 and beta) as JSON file(s) under data\security\additionalPolicies\<EndpointName>\.
The catalog covers: identitySecurityDefaultsEnforcementPolicy (Security Defaults),
selfServicePasswordResetPolicy, authorizationPolicy, authenticationStrengthPolicies, namedLocations,
crossTenantAccessPolicy (base, default and partners), adminConsentRequestPolicy, permissionGrantPolicies,
appManagementPolicies, defaultAppManagementPolicy, roleManagementPolicies and activityBasedTimeoutPolicies.

The script is robust by design: if the export of one policy fails, the export of the remaining policies
still continues. 404 (endpoint not available in this tenant/API version), 403/401 (missing license or
permission) and empty collections never abort the run. Every endpoint gets a status entry
(exported / empty / notAvailable / forbidden / error with message) in the console, in the transcript and
in the summary file data\security\additionalPolicies\_summary.json (tenant id, timestamp, per endpoint
status, object count and error message). The summary file contains a timestamp and is therefore
intentionally NOT part of the git ready normalization.

Known endpoint notes (verified against the ALYA tenant, 07.11.2026):
- selfServicePasswordResetPolicy was retired by Microsoft in v1.0 AND beta ("Resource not found for the
  segment"). The SSPR settings (incl. isEnabled and numberOfAuthenticationMethodsRequired) moved into the
  authenticationMethodsPolicy resource. The endpoint stays in the catalog so the summary documents its
  availability per tenant.
- roleManagementPolicies does not support a plain tenant wide GET: Graph requires the $filter
  "scopeId eq '/' and scopeType eq 'DirectoryRole'" for PIM for Entra roles (the formerly documented
  roleDefinitionId filter property no longer exists in the service metadata of v1.0 AND beta, verified
  07.11.2026). This script fetches all directory role policies in one paged request including their
  rules ($expand=rules, fallback without expansion). Policy objects carry no role reference property,
  therefore each file is named via the roleDefinitionId embedded in the policy id
  (DirectoryRole_<tenantId>_<roleDefinitionId>) resolved against the directory roleDefinitions;
  policies whose id segment matches no current roleDefinitionId (legacy canonical ids) are resolved
  via per-role single-item GETs with constructed ids (final fallback: full policy id). With
  ChangedOnly=$true (default) only policies carrying a lastModifiedDateTime value (customized
  settings, incl. who and when via lastModifiedBy) are exported; untouched Microsoft defaults are
  skipped and counted as skippedUnchanged in the summary. Without Entra
  ID P2 or the required permission the endpoint is reported as forbidden/error in the summary and the
  run continues.
- activityBasedTimeoutPolicy is exported via its Graph collection endpoint activityBasedTimeoutPolicies.

Singleton policies (e.g. authorizationPolicy) are exported as one JSON file per endpoint. Collections
(e.g. namedLocations) are exported as one JSON file per object, named by displayName (fallback id),
sanitized for file systems and git. Paging is handled automatically.

.PARAMETER ExportGitFriendly
Determines whether the exported JSON files should be normalized for git storage (via Make-JsonGitReady). Default is false.

.PARAMETER ChangedOnly
Applies to the roleManagementPolicies endpoint only. If true (default), only PIM policies with a
lastModifiedDateTime value are exported (= roles whose policy settings were customized; the exported
JSON also documents who changed them via lastModifiedBy). Policies without lastModifiedDateTime are
untouched Microsoft defaults and are skipped (counted as skippedUnchanged in the summary). If false,
all policies are exported.

.INPUTS
None. The script does not accept any pipeline input.

.OUTPUTS
Generates JSON files representing the tenant policy endpoints under data\security\additionalPolicies\<EndpointName>\
and a summary file data\security\additionalPolicies\_summary.json.
Produces a transcript log file in the logs directory.

.EXAMPLE
PS> .\Export-AdditionalPolicies.ps1

.EXAMPLE
PS> .\Export-AdditionalPolicies.ps1 -ExportGitFriendly $true

.EXAMPLE
PS> .\Export-AdditionalPolicies.ps1 -ChangedOnly $false

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [bool]$ExportGitFriendly = $false,
    [bool]$ChangedOnly = $true
)

# Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transcript
Start-Transcript -Path "$($AlyaLogs)\scripts\security\Export-AdditionalPolicies-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"

# Logins
LoginTo-MgGraph -Scopes @("Policy.Read.All","RoleManagement.Read.Directory")

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Export-AdditionalPolicies | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Tenant id for the summary and the roleManagementPolicies scope (fallback: current Graph context)
$tenantId = "$AlyaTenantId"
if ([string]::IsNullOrWhiteSpace($tenantId))
{
    $mgContext = Get-MgContext
    if ($null -ne $mgContext)
    {
        $tenantId = "$($mgContext.TenantId)"
    }
}

# Endpoint catalog (verified against Graph v1.0/beta metadata and docs, 07.11.2026)
# Type: Singleton = one JSON file per endpoint, Collection = one JSON file per object,
#       RoleManagement = special PIM handling (documented scopeId/scopeType filter, see Export-RoleManagementPolicy)
$policyEndpoints = @(
    [PSCustomObject]@{ Name = "identitySecurityDefaultsEnforcementPolicy"; Version = "v1.0"; Uri = "/policies/identitySecurityDefaultsEnforcementPolicy"; Type = "Singleton" },
    # selfServicePasswordResetPolicy: retired by Microsoft in v1.0 AND beta (verified 07.11.2026,
    # "Resource not found for the segment"). SSPR settings moved into authenticationMethodsPolicy
    # (see policyMigrationState). Kept in the catalog so the summary documents the gap per tenant.
    [PSCustomObject]@{ Name = "selfServicePasswordResetPolicy"; Version = "beta"; Uri = "/policies/selfServicePasswordResetPolicy"; Type = "Singleton" },
    [PSCustomObject]@{ Name = "authorizationPolicy"; Version = "v1.0"; Uri = "/policies/authorizationPolicy"; Type = "Singleton" },
    [PSCustomObject]@{ Name = "authenticationStrengthPolicies"; Version = "v1.0"; Uri = "/policies/authenticationStrengthPolicies"; Type = "Collection" },
    [PSCustomObject]@{ Name = "namedLocations"; Version = "v1.0"; Uri = "/identity/conditionalAccess/namedLocations"; Type = "Collection" },
    [PSCustomObject]@{ Name = "crossTenantAccessPolicy"; Version = "v1.0"; Uri = "/policies/crossTenantAccessPolicy"; Type = "Singleton" },
    [PSCustomObject]@{ Name = "crossTenantAccessPolicyDefault"; Version = "v1.0"; Uri = "/policies/crossTenantAccessPolicy/default"; Type = "Singleton" },
    [PSCustomObject]@{ Name = "crossTenantAccessPolicyPartners"; Version = "v1.0"; Uri = "/policies/crossTenantAccessPolicy/partners"; Type = "Collection" },
    [PSCustomObject]@{ Name = "adminConsentRequestPolicy"; Version = "v1.0"; Uri = "/policies/adminConsentRequestPolicy"; Type = "Singleton" },
    [PSCustomObject]@{ Name = "permissionGrantPolicies"; Version = "v1.0"; Uri = "/policies/permissionGrantPolicies"; Type = "Collection" },
    [PSCustomObject]@{ Name = "appManagementPolicies"; Version = "v1.0"; Uri = "/policies/appManagementPolicies"; Type = "Collection" },
    [PSCustomObject]@{ Name = "defaultAppManagementPolicy"; Version = "v1.0"; Uri = "/policies/defaultAppManagementPolicy"; Type = "Singleton" },
    # roleManagementPolicies: a plain GET is not supported by Graph, the list operation requires the
    # $filter "scopeId eq '/' and scopeType eq 'DirectoryRole'" and Entra ID P2 (PIM). Handled as
    # special type: one paged query incl. $expand=rules, see Export-RoleManagementPolicy.
    [PSCustomObject]@{ Name = "roleManagementPolicies"; Version = "v1.0"; Uri = "/policies/roleManagementPolicies"; Type = "RoleManagement" },
    [PSCustomObject]@{ Name = "activityBasedTimeoutPolicies"; Version = "v1.0"; Uri = "/policies/activityBasedTimeoutPolicies"; Type = "Collection" }
)

# Reads a property from a Graph response object. Invoke-MgGraphRequest returns Hashtables by default,
# but PSObject based responses are supported as well.
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
        $dict = [System.Collections.IDictionary]$GraphObject
        if ($dict.Contains($Name))
        {
            return $dict[$Name]
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

# Builds a stable, file system and git friendly file name for one collection object
function Get-PolicyObjectFileName
{
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$Item,
        [Parameter(Mandatory = $true)]
        [int]$Index,
        [Parameter()]
        [System.Collections.Generic.HashSet[string]]$UsedNames
    )
    $baseName = $null
    foreach ($propertyName in @("displayName", "id", "tenantId"))
    {
        $propertyValue = Get-GraphPropertyValue -GraphObject $Item -Name $propertyName
        if ($null -ne $propertyValue -and -Not [string]::IsNullOrWhiteSpace("$propertyValue"))
        {
            $baseName = "$propertyValue"
            break
        }
    }
    if ([string]::IsNullOrWhiteSpace($baseName))
    {
        $baseName = "object-$($Index)"
    }
    $fileName = MakeFsCompatiblePath "$($baseName).json"
    if (-Not $UsedNames.Add($fileName.ToLowerInvariant()))
    {
        $idValue = Get-GraphPropertyValue -GraphObject $Item -Name "id"
        $suffix = "duplicate-$($Index)"
        if ($null -ne $idValue -and -Not [string]::IsNullOrWhiteSpace("$idValue"))
        {
            $suffix = "$idValue"
        }
        $fileName = MakeFsCompatiblePath "$($baseName)_$($suffix).json"
    }
    return $fileName
}

# Fetches all objects of a paged Graph collection endpoint
function Get-GraphCollection
{
    [CmdletBinding()]
    [OutputType([object[]])]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )
    $items = [System.Collections.Generic.List[object]]::new()
    $nextUri = $Uri
    while (-Not [string]::IsNullOrWhiteSpace($nextUri))
    {
        $response = Invoke-MgGraphRequest -Method "Get" -Uri $nextUri -ErrorAction Stop
        $value = Get-GraphPropertyValue -GraphObject $response -Name "value"
        if ($null -ne $value)
        {
            foreach ($item in @($value))
            {
                $items.Add($item)
            }
        }
        else
        {
            # Endpoints that return a single object although declared as collection
            $items.Add($response)
        }
        $nextUri = $null
        $nextLink = Get-GraphPropertyValue -GraphObject $response -Name "@odata.nextLink"
        if ($null -ne $nextLink -and -Not [string]::IsNullOrWhiteSpace("$nextLink"))
        {
            $nextUri = "$nextLink"
        }
    }
    return $items.ToArray()
}

# Exports the roleManagementPolicies endpoint: a plain GET is not supported by Graph, the list
# operation requires the $filter "scopeId eq '/' and scopeType eq 'DirectoryRole'" (PIM for Entra
# roles; verified against the ALYA tenant and current docs, 07.11.2026 - the formerly documented
# roleDefinitionId filter property no longer exists in the service metadata of v1.0 AND beta).
# All policies are fetched in one paged request including their rules ($expand=rules, with fallback
# without expansion). The policy objects carry no role reference property, therefore the file names
# are derived from the policy id (format DirectoryRole_<tenantId>_<roleDefinitionId>) resolved
# against the directory roleDefinitions. Policies whose embedded id segment matches no current
# roleDefinitionId (legacy canonical ids, e.g. Global Administrator, verified 07.11.2026) are
# resolved via per-role single-item GETs with constructed ids (final fallback: full policy id).
function Export-RoleManagementPolicy
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$EndpointDir,
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        [Parameter(Mandatory = $true)]
        [bool]$ChangedOnly,
        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.List[string]]$GitReadyFiles
    )
    $result = [PSCustomObject]@{
        status           = "error"
        objectCount      = 0
        fileCount        = 0
        skippedUnchanged = 0
        errorMessage     = ""
    }
    # Collect all directory role definitions for the id -> displayName mapping (paged)
    $roleNameById = @{}
    $roleDefinitions = @(Get-GraphCollection -Uri "$AlyaGraphEndpoint/v1.0/roleManagement/directory/roleDefinitions")
    foreach ($roleDefinition in $roleDefinitions)
    {
        $roleDefinitionId = Get-GraphPropertyValue -GraphObject $roleDefinition -Name "id"
        $templateId = Get-GraphPropertyValue -GraphObject $roleDefinition -Name "templateId"
        $roleDisplayName = Get-GraphPropertyValue -GraphObject $roleDefinition -Name "displayName"
        if ($null -ne $roleDefinitionId -and -Not [string]::IsNullOrWhiteSpace("$roleDefinitionId") -and -Not $roleNameById.ContainsKey("$roleDefinitionId"))
        {
            $roleNameById["$roleDefinitionId"] = "$roleDisplayName"
        }
        if ($null -ne $templateId -and -Not [string]::IsNullOrWhiteSpace("$templateId") -and -Not $roleNameById.ContainsKey("$templateId"))
        {
            $roleNameById["$templateId"] = "$roleDisplayName"
        }
    }
    Write-Host "  Found $($roleDefinitions.Count) directory role definition(s), $($roleNameById.Count) name mapping(s)" -ForegroundColor $CommandInfo
    # Fetch all PIM policies for directory roles (paged), preferring expanded rules
    $baseUri = "$AlyaGraphEndpoint/v1.0/policies/roleManagementPolicies?`$filter=scopeId%20eq%20'/'%20and%20scopeType%20eq%20'DirectoryRole'"
    $policies = $null
    try
    {
        $policies = @(Get-GraphCollection -Uri "$baseUri&`$expand=rules")
    }
    catch
    {
        # Quiet retry info line; the full error is reported by the caller catch after this last attempt
        Write-Host "  rules expansion failed, retrying without expansion. Reason: $($_.Exception.Message)" -ForegroundColor $CommandInfo
        $policies = @(Get-GraphCollection -Uri $baseUri)
    }
    Write-Host "  Found $($policies.Count) PIM policy(ies) for directory roles" -ForegroundColor $CommandInfo
    if ($policies.Count -eq 0)
    {
        $result.status = "empty"
        return $result
    }
    # Analyze the id -> role mapping over the FULL list first: the per-role alias lookups below are
    # bounded by the unmatched roles of the full list, independent of the ChangedOnly filter
    $mappedSeg3 = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($policy in $policies)
    {
        $policyId = Get-GraphPropertyValue -GraphObject $policy -Name "id"
        $idParts = "$policyId" -split "_"
        if ($idParts.Count -ge 3 -and $roleNameById.ContainsKey($idParts[2]))
        {
            $null = $mappedSeg3.Add($idParts[2])
        }
    }
    # ChangedOnly: keep only policies with a lastModifiedDateTime value (customized settings);
    # policies without are untouched Microsoft defaults and are skipped
    if ($ChangedOnly -eq $true)
    {
        $allPolicyCount = $policies.Count
        $changedPolicies = [System.Collections.Generic.List[object]]::new()
        foreach ($policy in $policies)
        {
            $lastModified = Get-GraphPropertyValue -GraphObject $policy -Name "lastModifiedDateTime"
            if ($null -ne $lastModified -and -Not [string]::IsNullOrWhiteSpace("$lastModified"))
            {
                $changedPolicies.Add($policy)
            }
        }
        $result.skippedUnchanged = $allPolicyCount - $changedPolicies.Count
        Write-Host "  ChangedOnly: $($changedPolicies.Count) changed policy(ies), $($result.skippedUnchanged) unchanged skipped" -ForegroundColor $CommandInfo
        $policies = $changedPolicies
        if ($policies.Count -eq 0)
        {
            $result.status = "empty"
            return $result
        }
    }
    # Resolve role names for policies whose embedded id segment matches no current roleDefinitionId
    # (legacy canonical ids): per-role single-item GET with the constructed id resolves the alias
    $canonicalRoleNameByPolicyId = @{}
    $unmappedPolicyCount = 0
    foreach ($policy in $policies)
    {
        $policyId = Get-GraphPropertyValue -GraphObject $policy -Name "id"
        $idParts = "$policyId" -split "_"
        if (-Not ($idParts.Count -ge 3 -and $roleNameById.ContainsKey($idParts[2])))
        {
            $unmappedPolicyCount = $unmappedPolicyCount + 1
        }
    }
    if ($unmappedPolicyCount -gt 0)
    {
        $unmatchedRoleIds = @($roleNameById.Keys | Where-Object { -Not $mappedSeg3.Contains($_) })
        Write-Host "  Resolving $($unmappedPolicyCount) unmapped policy(ies) via $($unmatchedRoleIds.Count) per-role lookup(s)" -ForegroundColor $CommandInfo
        $lookupOk = 0
        $lookupFailReason = ""
        foreach ($unmatchedRoleId in $unmatchedRoleIds)
        {
            $constructedId = "DirectoryRole_$($TenantId)_$($unmatchedRoleId)"
            try
            {
                $singlePolicy = Invoke-MgGraphRequest -Method "Get" -Uri "$AlyaGraphEndpoint/v1.0/policies/roleManagementPolicies/$($constructedId)" -ErrorAction Stop
                $canonicalId = Get-GraphPropertyValue -GraphObject $singlePolicy -Name "id"
                if ($null -ne $canonicalId -and -Not [string]::IsNullOrWhiteSpace("$canonicalId"))
                {
                    $canonicalRoleNameByPolicyId["$canonicalId"] = $roleNameById["$unmatchedRoleId"]
                    $lookupOk = $lookupOk + 1
                }
            }
            catch
            {
                # Quiet skip: role has no policy (404) or the lookup is unavailable in this tenant;
                # affected policies keep their policy-id based file name
                if ([string]::IsNullOrWhiteSpace($lookupFailReason))
                {
                    $lookupFailReason = "$($_.Exception.Message)"
                }
            }
        }
        if ($lookupOk -eq 0 -and -Not [string]::IsNullOrWhiteSpace($lookupFailReason))
        {
            Write-Host "  per-role lookups unavailable, keeping policy-id file names. Reason: $($lookupFailReason)" -ForegroundColor $CommandInfo
        }
        else
        {
            Write-Host "  Resolved $($lookupOk) role name(s) via per-role lookup(s)" -ForegroundColor $CommandInfo
        }
    }
    $usedNames = [System.Collections.Generic.HashSet[string]]::new()
    $index = 0
    foreach ($policy in $policies)
    {
        $policyId = Get-GraphPropertyValue -GraphObject $policy -Name "id"
        $baseName = ""
        if ($null -ne $policyId -and -Not [string]::IsNullOrWhiteSpace("$policyId"))
        {
            # Id format: DirectoryRole_<tenantId>_<roleDefinitionId>
            $idParts = "$policyId" -split "_"
            if ($idParts.Count -ge 3 -and $roleNameById.ContainsKey($idParts[2]))
            {
                $baseName = $roleNameById[$idParts[2]]
            }
            elseif ($canonicalRoleNameByPolicyId.ContainsKey("$policyId"))
            {
                $baseName = $canonicalRoleNameByPolicyId["$policyId"]
            }
        }
        if ([string]::IsNullOrWhiteSpace($baseName))
        {
            # No role mapping (e.g. retired role template): fall back to the full policy id
            $baseName = "$policyId"
        }
        if ([string]::IsNullOrWhiteSpace($baseName))
        {
            $baseName = "policy-$($index)"
        }
        $fileName = MakeFsCompatiblePath "$($baseName).json"
        if (-Not $usedNames.Add($fileName.ToLowerInvariant()))
        {
            $fileName = MakeFsCompatiblePath "$($baseName)_duplicate-$($index).json"
            $null = $usedNames.Add($fileName.ToLowerInvariant())
        }
        $filePath = "$EndpointDir\$fileName"
        $policy | ConvertTo-Json -Depth 30 | Set-Content -Path $filePath -Encoding $AlyaUtf8Encoding -Force
        $GitReadyFiles.Add($filePath)
        $result.objectCount = $result.objectCount + 1
        $result.fileCount = $result.fileCount + 1
        $index = $index + 1
    }
    $result.status = "exported"
    return $result
}
# Export directories
$additionalPoliciesRoot = "$AlyaData\security\additionalPolicies"
if (-Not (Test-Path $additionalPoliciesRoot))
{
    New-Item -Path $additionalPoliciesRoot -ItemType Directory -Force | Out-Null
}

$summaryEndpoints = [System.Collections.Generic.List[object]]::new()
$GitReadyFiles = [System.Collections.Generic.List[string]]::new()

foreach ($endpoint in $policyEndpoints)
{
    Write-Host "Exporting $($endpoint.Name) ($($endpoint.Version) $($endpoint.Uri))" -ForegroundColor $CommandInfo
    $fullUri = "$AlyaGraphEndpoint/$($endpoint.Version)$($endpoint.Uri)"
    $status = "error"
    $objectCount = 0
    $fileCount = 0
    $skippedUnchanged = 0
    $errorMessage = ""
    try
    {
        $endpointDir = "$additionalPoliciesRoot\$($endpoint.Name)"
        if (-Not (Test-Path $endpointDir))
        {
            New-Item -Path $endpointDir -ItemType Directory -Force | Out-Null
        }
        if ($endpoint.Type -eq "Singleton")
        {
            $response = Invoke-MgGraphRequest -Method "Get" -Uri $fullUri -ErrorAction Stop
            $filePath = "$endpointDir\$($endpoint.Name).json"
            $response | ConvertTo-Json -Depth 30 | Set-Content -Path $filePath -Encoding $AlyaUtf8Encoding -Force
            $GitReadyFiles.Add($filePath)
            $objectCount = 1
            $fileCount = 1
            $status = "exported"
        }
        elseif ($endpoint.Type -eq "RoleManagement")
        {
            $roleResult = Export-RoleManagementPolicy -EndpointDir $endpointDir -TenantId $tenantId -ChangedOnly $ChangedOnly -GitReadyFiles $GitReadyFiles
            $status = $roleResult.status
            $objectCount = $roleResult.objectCount
            $fileCount = $roleResult.fileCount
            $skippedUnchanged = $roleResult.skippedUnchanged
            $errorMessage = $roleResult.errorMessage
        }
        else
        {
            $items = [System.Collections.Generic.List[object]]::new()
            $nextUri = $fullUri
            while (-Not [string]::IsNullOrWhiteSpace($nextUri))
            {
                $response = Invoke-MgGraphRequest -Method "Get" -Uri $nextUri -ErrorAction Stop
                $value = Get-GraphPropertyValue -GraphObject $response -Name "value"
                if ($null -ne $value)
                {
                    foreach ($item in @($value))
                    {
                        $items.Add($item)
                    }
                }
                else
                {
                    # Endpoints that return a single object although declared as collection
                    $items.Add($response)
                }
                $nextUri = $null
                $nextLink = Get-GraphPropertyValue -GraphObject $response -Name "@odata.nextLink"
                if ($null -ne $nextLink -and -Not [string]::IsNullOrWhiteSpace("$nextLink"))
                {
                    $nextUri = "$nextLink"
                }
            }
            $objectCount = $items.Count
            if ($objectCount -eq 0)
            {
                $status = "empty"
            }
            else
            {
                $usedNames = [System.Collections.Generic.HashSet[string]]::new()
                $index = 0
                foreach ($item in $items)
                {
                    $fileName = Get-PolicyObjectFileName -Item $item -Index $index -UsedNames $usedNames
                    $filePath = "$endpointDir\$fileName"
                    $item | ConvertTo-Json -Depth 30 | Set-Content -Path $filePath -Encoding $AlyaUtf8Encoding -Force
                    $GitReadyFiles.Add($filePath)
                    $fileCount = $fileCount + 1
                    $index = $index + 1
                }
                $status = "exported"
            }
        }
        if ($status -eq "exported" -or $status -eq "empty")
        {
            Write-Host "  $($status): $($objectCount) object(s), $($fileCount) file(s)" -ForegroundColor $CommandSuccess
        }
        else
        {
            Write-Host "  $($status): $($errorMessage)" -ForegroundColor $CommandWarning
        }
    }
    catch
    {
        # Prefer the Graph error body (contains code and message), fall back to the exception message
        $errorBody = "$($_.ErrorDetails.Message)"
        $errorMessage = $errorBody
        if ([string]::IsNullOrWhiteSpace($errorMessage))
        {
            $errorMessage = "$($_.Exception.Message)"
        }
        $errorMessage = $errorMessage -replace "\r?\n", " "
        if ($errorMessage -match "\(404\)" -or $errorMessage -match "NotFound|Request_ResourceNotFound|does not exist|Resource not found for the segment")
        {
            $status = "notAvailable"
        }
        elseif ($errorMessage -match "\(403\)" -or $errorMessage -match "\(401\)" -or $errorMessage -match "Forbidden|Authorization_RequestDenied|Insufficient privileges")
        {
            $status = "forbidden"
        }
        else
        {
            $status = "error"
        }
        Write-Host "  $($status): $($errorMessage)" -ForegroundColor $CommandWarning
    }
    $summaryEndpoints.Add([PSCustomObject]@{
        name             = $endpoint.Name
        version          = $endpoint.Version
        uri              = $endpoint.Uri
        type             = $endpoint.Type
        status           = $status
        objectCount      = $objectCount
        fileCount        = $fileCount
        skippedUnchanged = $skippedUnchanged
        error            = $errorMessage
    })
}

# Writing summary file (contains a timestamp, therefore intentionally not git ready normalized)
$summary = [PSCustomObject]@{
    tenantId          = $tenantId
    exportedAt        = (Get-Date).ToString("yyyy-MM-ddTHH:mm:sszzz")
    exportGitFriendly = $ExportGitFriendly
    changedOnly       = $ChangedOnly
    endpointCount     = $summaryEndpoints.Count
    endpoints         = $summaryEndpoints
}
$summaryFilePath = "$additionalPoliciesRoot\_summary.json"
$summary | ConvertTo-Json -Depth 10 | Set-Content -Path $summaryFilePath -Encoding $AlyaUtf8Encoding -Force
Write-Host "Summary written to $($summaryFilePath)" -ForegroundColor $CommandInfo

# Make JSON git-ready if requested
if ($ExportGitFriendly -eq $true -and $GitReadyFiles.Count -gt 0)
{
    Write-Host "Making $($GitReadyFiles.Count) JSON file(s) git-ready" -ForegroundColor $CommandInfo
    Make-JsonGitReady -Path $GitReadyFiles.ToArray()
}

# Stopping Transcript
Stop-Transcript

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDk+6VjzF/09twj
# n8hL8n0PavWJ2dajCjbY3Q0PgRdJ6qCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
# Qc9vAbjutKlUMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24g
# Um9vdCBDQSAtIFIzMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9i
# YWxTaWduMB4XDTIwMDcyODAwMDAwMFoXDTI5MDMxODAwMDAwMFowUzELMAkGA1UE
# BhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2Jh
# bFNpZ24gQ29kZSBTaWduaW5nIFJvb3QgUjQ1MIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAti3FMN166KuQPQNysDpLmRZhsuX/pWcdNxzlfuyTg6qE9aND
# m5hFirhjV12bAIgEJen4aJJLgthLyUoD86h/ao+KYSe9oUTQ/fU/IsKjT5GNswWy
# KIKRXftZiAULlwbCmPgspzMk7lA6QczwoLB7HU3SqFg4lunf+RuRu4sQLNLHQx2i
# CXShgK975jMKDFlrjrz0q1qXe3+uVfuE8ID+hEzX4rq9xHWhb71hEHREspgH4nSr
# /2jcbCY+6R/l4ASHrTDTDI0DfFW4FnBcJHggJetnZ4iruk40mGtwEd44ytS+ocCc
# 4d8eAgHYO+FnQ4S2z/x0ty+Eo7+6CTc9Z2yxRVwZYatBg/WsHet3DUZHc86/vZWV
# 7Z0riBD++ljop1fhs8+oWukHJZsSxJ6Acj2T3IyU3ztE5iaA/NLDA/CMDNJF1i7n
# j5ie5gTuQm5nfkIWcWLnBPlgxmShtpyBIU4rxm1olIbGmXRzZzF6kfLUjHlufKa7
# fkZvTcWFEivPmiJECKiFN84HYVcGFxIkwMQxc6GYNVdHfhA6RdktpFGQmKmgBzfE
# ZRqqHGsWd/enl+w/GTCZbzH76kCy59LE+snQ8FB2dFn6jW0XMr746X4D9OeHdZrU
# SpEshQMTAitCgPKJajbPyEygzp74y42tFqfT3tWbGKfGkjrxgmPxLg4kZN8CAwEA
# AaOCAXcwggFzMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzAP
# BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQfAL9GgAr8eDm3pbRD2VZQu86WOzAf
# BgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpjmove4t0bvDB6BggrBgEFBQcBAQRuMGww
# LQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL3Jvb3RyMzA7
# BggrBgEFBQcwAoYvaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# cm9vdC1yMy5jcnQwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxz
# aWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggrBgEF
# BQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJ
# KoZIhvcNAQEMBQADggEBAKz3zBWLMHmoHQsoiBkJ1xx//oa9e1ozbg1nDnti2eEY
# XLC9E10dI645UHY3qkT9XwEjWYZWTMytvGQTFDCkIKjgP+icctx+89gMI7qoLao8
# 9uyfhzEHZfU5p1GCdeHyL5f20eFlloNk/qEdUfu1JJv10ndpvIUsXPpYd9Gup7EL
# 4tZ3u6m0NEqpbz308w2VXeb5ekWwJRcxLtv3D2jmgx+p9+XUnZiM02FLL8Mofnre
# kw60faAKbZLEtGY/fadY7qz37MMIAas4/AocqcWXsojICQIZ9lyaGvFNbDDUswar
# AGBIDXirzxetkpNiIHd1bL3IMrTcTevZ38GQlim9wX8wggboMIIE0KADAgECAhB3
# vQ4Ft1kLth1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENv
# ZGUgU2lnbmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAw
# MDBaMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIw
# MAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAy
# MDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj
# /SBerjgSi8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlM
# g7BKRFAEeIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRV
# X5YLEeWatSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV
# 0xHK5s2zBZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEz
# IHXMsdXtHQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMk
# oog28vmfvpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq
# 7rfYrWGlr3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult
# 5a/dm2tjIF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNu
# twFsDeCXpxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYy
# AjIwfLWTyCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofn
# GrhO7izB36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
# FgQUJZ3Q/FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0
# Q9lWULvOljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8v
# b2NzcC5nbG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUH
# MAKGOmh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWdu
# aW5ncm9vdHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJ
# KwYBBAGgMgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24u
# Y29tL3JlcG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJ
# yTm6t6E5iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbV
# YQLFY4/UovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQt
# pFg6bBNJ+KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSX
# hndGKj0jfShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6
# bs+XYXvfcXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nO
# ZNm9/Lws80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOH
# X5OKSBoRHeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dq
# cYC/lt5yA9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0i
# xxnJpsoOqHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7
# qWPLd0jV+mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDCjuDGju
# xOV7dX3H9DANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjEzMTYxODAwWhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAqrm7S5R5kmdYT3Q2wIa1m1BQW5EfmzvCg+WYiBY94XQT
# AxEACqVq4+3K/ahp+8c7stNOJDZzQyLLcZvtLpLmkj4ZqwgwtoBrKBk3ofkEMD/f
# 46P2IukytvmyUxdM4730Vs6mRvQP+Y6CfsUrWQDgJkiGTldCSH25D3d2eO6PeSdY
# TA3E3kMHBiFI3zxgCq3ZgbdcIn1bUz7wnzxjuAqI7aJ/dIBKDmaNR0+iIhrCFvhD
# o6nZ2Iwj1vAQsSHlHc6SwEvWfNX+Adad3cSiWfj0Bo0GPUKHRayf2pkbOW922shL
# 1yf/30OVyct8rPkMrIKzQhog2R9qJrKJ2xUWwEwiSblWX4DRpdxOROS5PcQB45AH
# hviDcudo30gx8pjwTeCVKkG2XgdqEZoxdAa4ospWn3va+Dn6OumYkUQZ1EkVhDfd
# sbCXAJvYNCbOyx5tPzeZEFP19N5edi6MON9MC/5tZjpcLzsQUgIbHqFfZiQTposx
# /j+7m9WSaK0cDBfYKFOVQJF576yeWaAjMul4gEkXBn6meYNiV/iL8pVcRe+U5cid
# mgdUVveoBPexERaIMz/dIZIqVdLBCgBXcHHoQsPgBq975k8fOLwTQP9NeLVKtPgf
# tnoAWlVn8dIRGdCcOY4eQm7G4b+lSili6HbU+sir3M8pnQa782KRZsf6UruQpqsC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBT5XqSepeGcYSU4OKwKELHy/3vC
# oTANBgkqhkiG9w0BAQsFAAOCAgEAlSgt2/t+Z6P9OglTt1+sobomrQT0Mb97lGDQ
# ZpE364hOTSYkbcqxlRXZ+aINgt2WEe7GPFu+6YoZimCPV4sOfk5NZ6I3ZU+uoTso
# VYpQr3IozYLLNMWEK2WswPHcxx34Il6F59V/wP1RdB73g+4ZprkzsYNqQpXMv3yo
# DsPU9IHP/w3jQRx6Maqlrjn4OCaE3f6XVxDRHv/iFnipQfXUqY2dV9gkoiYL3/dQ
# X6ibUXqjXk6trvZBQr20M+fhhFPYkxfLqu1WdK5UGbkg1MHeWyVBP56cnN6IobNp
# HbGY6Eg0RevcNGiYFZsE9csZPp855t8PVX1YPewvDq2v20wcyxmPcqStJYLzeirM
# Jk0b9UF2hHmIMQRuG/pjn2U5xYNp0Ue0DmCI66irK7LXvziQjFUSa1wdi8RYIXnA
# mrVkGZj2a6/Th1Z4RYEIn1Pc/F4yV9OJAPYN1Mu1LuRiaHDdE77MdhhNW2dniOmj
# 3+nmvWbZfNAI17VybYom4MNB1Cy2gm2615iuO4G6S6kdg8fTaABRh78i8DIgT6LL
# /yMvbDOHhREfFUfowgkx9clsBF1dlAG357pYgAsbS/hqTS0K2jzv38VbhMVuWgtH
# dwO39ACaudnXvAKG9w50/N0DgI54YH/HKWxVyYIltzixRLXN1l+O5MCoXhofW4Qh
# trofETAxgiEGMIIhAgIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIDVXx9mf
# eorw5MKcbad6IkHiyJRVEUupYMD/hjNLx+xTMA0GCSqGSIb3DQEBAQUABIICAAVN
# pITDs+fhJggmXEoeNep2p1lY4eV5Nk9ZUIFXufvgNcAmT67Da3DfSSln2bBN4/I4
# sdf0jUAl4VnREK73AoF4rIYKQThxLSfO8J4aoiD+jReV39vtOoWv3ituI8LaUv02
# uHYMbX4NIHRlb7n83/xDSQHROHtkKwE2djgvJNmdjlVC1kgT5+vyxqT1YIyAcQ1b
# QnoaxHEOcwqY6O599TbJJRGWZZyfe0qJiBQoJ9fdXHrwQ4R33auSZ3g+6wb3OKiZ
# NNTaSqPoXyXQDwsYNnyLwghXCfVGt2kA1Bi5E77kBdV2wlkMAhU6TCREnl+oJmCw
# ShThIroSi9LraMOtFxukX9efzQ2V0AZtz2cyqogAWWbrHO1JasYK4Td4hklXn3Lf
# 9m7MZW1emcyq3HakuPY09pwrKbmco6kShGwk6LlG5sYbqQ+zz3P71hkriV5gHjAO
# +4pohBA8DyzEunVn6cdlMgX4G50yLd6KKdCAyJ3oxA+VGpEt1TFqNv5BkIuLDON7
# vKvoixlj6vgCbclBoU5+ArddWgza0e1Cep9WKkE7unQHIu7wVAlfXvMvE/GCq7Ep
# fI/wa5M+rPJXjUUT8zb+cR2RQCEFa+KhWCCuzKho6vE4nM4cLHtnYFVkQ6ZABX9g
# Wg2RSPE3sdQW64iTQDsdf8EW/XGJe24p6jEDqLQjoYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCDPBYxu5c0QBxK8SZovNGIitpsZFRUhm5YZMd8Pun6EcgIUG9th
# TVLx3rjKa+X9e5wYkIRmnbQYDzIwMjYxMTA4MjA0ODU0WjADAgEBoF2kWzBZMQsw
# CQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMm
# R2xvYmFsc2lnbiBSNDUgVFNBIGZvciBDb2RlU2lnbiAyMDI1MTCgghlgMIIGijCC
# BHKgAwIBAgIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcNAQEMBQAwXjELMAkG
# A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0ds
# b2JhbFNpZ24gT2ZmbGluZSBSNDUgVGltZXN0YW1waW5nIENBIDIwMjUwHhcNMjUx
# MDE1MDcyNTA0WhcNMzcwMTEwMDAwMDAwWjBZMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFsc2lnbiBSNDUgVFNB
# IGZvciBDb2RlU2lnbiAyMDI1MTAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQDRSo2hjYZASCijCQSc2RMQPPKojE/xf4Uija2JnsJ7Snl2gDoxKjQ9HcU6
# rVD8pgy1sBKdVxtLLFhY3gzY/PA2iwIs6ZzCnxshtjShsN1RyzRrzc4Fq+0xQx6q
# ADUMn96mqHE/0ok53DPbmpBkkUDytGM79nQfw9WVymYgA+TkbA0/QOmPNNJIZ6Cj
# X0t3wJfhL0caiXthBBMEWKxT5v2U7ZRbCq/DVDXA9oX1iFVBVaBpx57MLL00nyHu
# x0InYS7Rr54M3tNhm7+0maxpyTFa51uY1PHtTJMup/l3RGooQ5YweCH2hDoUNwKO
# C7QkFbklhPdq27EXkueg8qLOnRDmVO1r+B1yMAbl6QuV0L+OPB1SKBAPpmIFklmJ
# 0SoibbUqxsTzejjdI+ywQLUcXilogwKWsJ46h6wjlU5AVqT7FEBYzWCTt6hf7SLQ
# bPGs02Ba8oaaNfo0SL+aApN94luEB/wuE1lgptrckLzbQlCp56OgkAJYpqYuui+T
# fueCIU0CAwEAAaOCAcYwggHCMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAK
# BggrBgEFBQcDCDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQy+tPhB2gnkGsI0j8d
# PIxlNigGGTAfBgNVHSMEGDAWgBR3AjsBMQ8edHfDSMjDB2NViKU7ojCBpQYIKwYB
# BQUHAQEEgZgwgZUwQgYIKwYBBQUHMAGGNmh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24u
# Y29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNTBPBggrBgEFBQcwAoZDaHR0
# cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NvZmZsaW5lcjQ1dGlt
# ZXN0YW1wY2EyMDI1LmNydDBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLmds
# b2JhbHNpZ24uY29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNS5jcmwwVgYD
# VR0gBE8wTTAIBgZngQwBBAIwQQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0
# dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEB
# DAUAA4ICAQCOrnCmj0eGkYpuniz6/WFm91s6KjnhkMKYlbcftgpMBtlhysVniEOf
# BvhcvoFQw4AOHG9NRVvZpkBnag5Dt1HM3Jg21gRVCBwFyP1ET8IDxoflYx5OD4SC
# NLHs6vCg6rFkNT81v9Zy8u0xXy3WboN5iK/SbTmLGqCrAGJihLLrfIhvddwVrdBy
# iHteLxgjugT6JQogCSoBF2JqmH0ZBCl515btbTuWZLrQUs5vvl2o98Mdju9yyJRW
# LzPVcUkRk9d8xBBi638FBOAuo3fcyThGcne7wUOa+TghhwIHbZ3pxTYpgo5cCxEZ
# sH8EXwiTUTwHf0qesssg/2XdcGH7s0AR4TyOJ2QnAayYOAM/XOBxNzURQg4mhMdP
# L/F8VCMKj3koJaVcx2akh0B82le/aBU8q2Oa++OwOwiHF5e+f9m+yhyYbwGSogWI
# V3hgRl+VyKrch8gv35FHr/cVz8n0/CPGRXGiYJZ7P1wOOgYdkMD2iDKVYQby5Ix/
# xCB0/lSKLnqEoFezfmnCJbGgACVswMsxhJEUjtxEcQc9afalne+IOts0v/yCRikJ
# snmVbS0x50Dk2OH+VCiU9s/XyzgfC7WzrtQ5diIdc2Ksi3JMTJm4a0LiEIZWitD5
# +6PokOkQ8+35TsHOwUhs87I/yyJjlIZpAV4Of1/JN8bWVB3Edm4WzjCCBqAwggSI
# oAMCAQICEQCD2oY3t58MhAyUe4QKUngfMA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNV
# BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9i
# YWxTaWduIFRpbWVzdGFtcGluZyBSb290IFI0NTAeFw0yNTA3MTYwMzA1MDRaFw00
# MTA3MTYwMDAwMDBaMF4xCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTQwMgYDVQQDEytHbG9iYWxTaWduIE9mZmxpbmUgUjQ1IFRpbWVzdGFt
# cGluZyBDQSAyMDI1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApHcW
# +O19i+LdAoZFYzS+5X+WYvnWoFqXAfir1hynhUTdH4RW1Db+yOmrQ275jlsQ6bzo
# Z3nN0CMncZX4E0Qhpp6Qvx27+flpfzeMQacD7VciWUiF3TLiu7wT2bBCSENUn3hf
# GMG4PJvYFvO5o4DA1iNvHhG4oSzctodoJfb4c8EjVahCw/NLizB3ra+NWe2gZBSa
# ZKraMxFt676yqx7RcQnjbF4R0OLGovsZt23vU69A5BdoPxdA9zu9rM+qTBsPDVUJ
# exYwEVU0GY7BJ5mUWWniyAPHW0Wv4Azk5t7I0XUIjA3+2OGkr0dVBXVBDyEeGBVr
# YXEdhfVLwuh6HBGJFdIrEY5KoGlpoT+4BBQe4XCH5sv15Uo+M72VKWjPA5Ex3nfF
# JC4P5FW1SR6olCSaIrtnZzc+zgmpSyiD+GcE2udQRQHbDi74enXgazk0+ktpHZ1Z
# 8oTvSaSIREovXSLbH3KC8uFIkXucl7XPH7ZGIrmF9eF4zuoo5FIUnsvV60kLqFDz
# Pk+UbLmgZDUCPlFFBBehaaNvixEymx9ON2KXev+MfK6OZChqGbrOC2wvvAFHyKlT
# ZbVHdqNiu0u5a2T1C9dSTRny1/hxLwcxL9BWPzQLwhsiyXqUzM7uD0lD9+PYMaxU
# YgoVSxqb4xvPCiVqLNabI+WtjEzYfQ0P+6tBTFsCAwEAAaOCAWIwggFeMA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDASBgNVHRMBAf8ECDAGAQH/
# AgEAMB0GA1UdDgQWBBR3AjsBMQ8edHfDSMjDB2NViKU7ojAfBgNVHSMEGDAWgBRG
# shx34XsV8KU5oXDe0cQu6m2y3jCBjgYIKwYBBQUHAQEEgYEwfzA3BggrBgEFBQcw
# AYYraHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vdGltZXN0YW1wcm9vdHI0NTBE
# BggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# dGltZXN0YW1wcm9vdHI0NS5jcnQwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2Ny
# bC5nbG9iYWxzaWduLmNvbS90aW1lc3RhbXByb290cjQ1LmNybDARBgNVHSAECjAI
# MAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggIBADKj7n7RbuRmMZZYXqlMPRJoR6X1
# n//quXGLVfOpFoR9Ya05L94w0ywBjelyGGf+nAB+CZFQ7gUOd2a2bpfpW8Xw5ArM
# +YjPEf8AtC4E6Yr105U1YNjlTSERoWJKc1hkSN5m4dpsYteFykzFQVwX50hYKH3y
# Z6Vcu6Ha0EA5ofzLpi2jK2jbRDCXbFNLi5mO1xKRdB2AzAF0f5C00b4H3d5sCOB8
# njTvAwaTMGEMeTkLWM4Z9Y+3UOtOpo1QuxXbDpXVkLXraG25iL1VtvjxEAy4534n
# UINB9whORicJJSTLba6fOK2f/1QGWEdewWLHAzE+N5oH0QoNRALpJ5JjIfeInvO+
# sQdBidnPuLKJ95HTj7XyMvJhFZjtbHJGlEWx4UgKcuNKLDLXWALfwQDN2Dey3kTf
# d4yw4nQdk1PctLLK3F4L2nnLv94BMkpY+Rfl53oOEN4yTvtwCYP+VDuZrktc7Nac
# oTVxZnKGkv8a1akckdOwQZC+i8Ay1VyzMAX/Tb4+r3c65B7cpAtq3OoUijXUJgvZ
# xci6TX78smL2TYy2tWn+8G4krnXvy2ELR2XYnKEOS4MVmrSCsjM5nxSrghE10VDX
# QbEfa93lhikfFoIuINKzWDLqvu8ZucmxEufxpHjNnnRVXX/Zv5KQq8pu/MQoOz6D
# C74n5+O5bSwvT5sgMIIGozCCBIugAwIBAgIQeEqqgXNmnJAJVOQhyUfrwDANBgkq
# hkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjET
# MBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMDEy
# MDkwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIFRpbWVzdGFt
# cGluZyBSb290IFI0NTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALp0
# M+wn3BI4IRvF02Eo1lq8T9+LzJGEQyRXvGQhvDscHz1PjK0Ht/PF1wLpERSCmqq0
# lHI7cQ0a72hrhXmOr2bqWJgNusF8edL/zbNvMUXQBXQEAHJqJ364Nz86iO2Xg/Wr
# NU0Pn1k79S/fWcV8pTJ2YJbI7e74BH4ZUXKov0RBerx7HjsAm7y64Ja/kP6Nm8Ny
# iwAS+CA6YDj3wcyFivuHeS6hKyDmy6CFkSO2xCgHVCje7BAxT4ryzRQfHt1VHOoo
# MUz5IWqozfOWZ/oBQZvNDwtof7ve8UPqF+Ww3HAis2k2WXRrxuWJKnzlC4Fdqz+P
# uNF2cvN8oqnil0G/zIxF/mHJ9mwHCwAE6BUjT4IqLfbvw/oRNkih0f16OTo0XaMs
# Dpt3UCA0QN2xAzGtX+lih3OWA2H3lLDZXGxP5xTF4fF7DSOczXCMHWreSi2LKrvb
# QhQFB6r7FNwx0/YfbMu+aGZEcE1tF/lx6wVzjpGSdetoXB72RGEYKWLdF2aI7Ci6
# SW/bPnf+uTEfdRwYoqZHvdjuSIU7/bPiDz8qmMaa+oJvsaWlhh1aOvqkbHQPd1Jh
# an+HKd45m4vus0VgMCSXFRIqhTCTJqyWpi3ocG0LqTKtLJsoCnZC8lVhUZiU3u32
# xRdvPBUQsA6tsN7FFvRl0cwvWlYIz5nE8FWRwix5AgMBAAGjggF4MIIBdDAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDwYDVR0TAQH/BAUwAwEB
# /zAdBgNVHQ4EFgQURrIcd+F7FfClOaFw3tHELuptst4wHwYDVR0jBBgwFoAUrmwF
# o5MT4qLn4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEEbzBtMC4GCCsGAQUFBzABhiJo
# dHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsGAQUFBzAChi9o
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAi0i6Nlc8csXadfnvMvWGvdwSKOOILk82XyaZ7A8BIRCWkjjGcGtt867UDr0l
# 74Z/4omNlaV+KUQDTaqYqPG33OopYyHc7c2ICssQaWF5KUIMI7zpxe9SHi8zN9VP
# ZnpmqUdUM7HdFvLYZHGjMZTlb/ZNS+KEbNDJJWdPyEvQzksF1j37fUH6irHAIeB+
# CLDZZCv56vLHCvTPLgw0YO5su5LwP/F7UhJod1mB9RwupDqMOQMN7eXMr2ZIeWPV
# Sbj/S9IlT0hOkzuTd7CaSGy2oB2zdJ5fvSIEO3w3DYW1w5q73ZxaA420DZ9MdjTV
# ha1Fe7Wfuy6Ju6zIv5JjSMY/yheqDbwAEV+L6ONDhIpDNM39O8Cie9sfuGfIjBXe
# P6Z/xyjvoW9vskHPAiLrAfhLyNJ2byXfXtpoaD17RATCQW5JO6eYVgTt0SYrBJTb
# 5O1mjj2AnaSkVXlQXuP4Gh/AFm+QFTyKpkihDHu6KuCxqYcFRpvtJVU9N2mY7UaZ
# mIVHCh5i2/2c5cFDQo69z2/2jJH9guSf7K3jlVUF80kvbTT3/2fumUC705qAQkDa
# I4lgH4NxkrXp5soK+d3HbLJYQZxmjZsqbx9vVwRDXINdO2mc3jn6hE0183sbbYvx
# bwPBKVLilL97VIvfQHoLcAJ3Py+IBwIAddKvxtYiMhmjO+gwggWDMIIDa6ADAgEC
# Ag5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9i
# YWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
# AxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwx
# IDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9i
# YWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRv
# f+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJ
# f094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcx
# BsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQ
# Bzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5d
# RC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWq
# RfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX8
# 5mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjpl
# llnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R
# /98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFl
# tr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEA
# AaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE
# FK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tyt
# ok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7
# jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh
# 4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR
# 3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6
# fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgb
# KCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglI
# WYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Q
# v4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98
# i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU
# 4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzW
# AtcKZ4MFWsmkEDGCA2EwggNdAgEBMHMwXjELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNpZ24gT2ZmbGluZSBS
# NDUgVGltZXN0YW1waW5nIENBIDIwMjUCEQCEcj/BlcwW8dsrovZg3yvkMAsGCWCG
# SAFlAwQCAqCCAUEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMCsGCSqGSIb3
# DQEJNDEeMBwwCwYJYIZIAWUDBAICoQ0GCSqGSIb3DQEBDAUAMD8GCSqGSIb3DQEJ
# BDEyBDCgxXSESEQjWpOX7vYTBWZZU4Yzgzt+q1HMrQx04ISevieyukzcPME74o6u
# 7Vv3v6AwgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGAzhYf7tRHiaeCzerWnIgvg7iq0v/Ups73Qy40s8cCM2Tj
# NqTZM5MdZtCxIluVlsXjJFFsDOzuGzwxPk2zwTeanQquklopaOSEhUvSSRUDEBoo
# 78Z2FPgyaWuTWccNK7+Q6kC1eqwK91aYwpDIt7jFkyKxeQhRWRZlw4XE/0dSERB2
# L5w8x7XcGwRLR/enAh0qME4wV+oMdtCBKLuHRS9xljeiLYl1AW6lFVIvrGKkmiRw
# fuancR4/EPdJH/XXd8Gt2/F9uEkU8CqxJBNw17J7U6GZ1FbqVeOEEQhVtcw9PV2G
# eK3jgxjQ/Kqw8A8HBpuKAgrz0SU8sPvbz9lgn5b2vY+LE+fnLww6UzTmRvnO4ZyV
# gHb4Ny6/IRFPSlUY+weYgZVFFppYF4n8AFHYwmeW4AverTXuf/qMG6y3ydQw18fU
# V/wNeQj4kG8wG6sElAoc/ei1kFv5EfVo+W/bLjie5lhhrprMRV/lIovTLNIoTvhr
# EFRyQAACwp2VuXf0pxWM
# SIG # End signature block
