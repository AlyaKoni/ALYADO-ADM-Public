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
    08.11.2026 Konrad Brunner       Initial Version
    08.11.2026 Konrad Brunner       ExcludeTargets default derived from data/ConfigureEnv.ps1
                                    ($AlyaMfaDisabledGroupName), parameter acts as override only

#>

<#
.SYNOPSIS
Configures the Entra ID authentication methods registration campaign (registrationEnforcement) of a tenant.

.DESCRIPTION
The Configure-RegistrationCampaign.ps1 script configures the tenant wide registration campaign
(registrationEnforcement / authenticationMethodsRegistrationCampaign) on the Microsoft Graph resource
policies/authenticationMethodsPolicy. Every property of the campaign is settable via a parameter and no
parameter is mandatory. Defaults reflect the Microsoft standard campaign configuration: State enabled,
all_users included, Microsoft Authenticator (microsoftAuthenticator) as targeted authentication method,
14 days snooze duration and enforceRegistrationAfterAllowedSnoozes disabled.

The script is idempotent: it reads the current campaign state, prints it, applies the desired configuration
via a Graph PATCH and verifies the result with a fresh GET (read-back). The effective (Ist) and the desired
(Soll) configuration are compared property by property; any deviation after the write is reported as a loud
error including the differing properties. Graph errors are reported with the original Graph error body.

API version: the script uses Graph beta for policies/authenticationMethodsPolicy (GET and PATCH), the same
version the export script Export-AuthenticationMethods.ps1 uses. Reason (verified against the ALYA tenant
on 08.11.2026): the v1.0 GET response OMITS the enforceRegistrationAfterAllowedSnoozes property completely,
so a v1.0 based read-back verification of that property is impossible; beta returns all campaign properties.
If a tenant does not return registrationEnforcement on beta, the script automatically falls back to v1.0
and reports which version was used.

Exclude targets (ConfigureEnv default): following the Alya script convention, the default behavior is
derived from data/ConfigureEnv.ps1. If $AlyaMfaDisabledGroupName has a value and that value is not
'PleaseSpecify', the group named by $AlyaMfaDisabledGroupName is automatically excluded from the campaign
(no parameter needed). If $AlyaMfaDisabledGroupName is empty, unset or 'PleaseSpecify', the default is an
EMPTY exclude list. An explicitly passed -ExcludeTargets parameter OVERRIDES this ConfigureEnv default
(the override is detected via $PSBoundParameters, so also an intentionally empty override like
-ExcludeTargets '' is recognized and disables the automatic exclusion).

Exclude target values: -ExcludeTargets accepts a list of group object ids and/or group display names.
Display names are resolved to object ids via an exact Graph group lookup (a display name matching more
than one group or no group at all is an error; this also applies to the group named by
$AlyaMfaDisabledGroupName - a not resolvable ConfigureEnv group is a loud error, the script never
continues silently without it). ATTENTION: because the campaign is written as a whole, an empty effective
exclude list OVERWRITES the exclude list of the campaign with an empty list: any currently excluded group
loses its exclusion and its members will be nagged by the campaign. The script prints a warning listing
the existing exclude targets that will be removed. Use -Preview $true to inspect the current state and
the planned changes without writing anything.

.PARAMETER State
State of the registration campaign. Valid values: enabled, disabled. Default: enabled.

.PARAMETER IncludeTarget
Id of the include target of the campaign. Either the special value all_users, a group object id or a group
display name (resolved via Graph). Default: all_users.

.PARAMETER IncludeTargetType
Target type of the include target. Only group is supported by Graph for campaign targets. Default: group.

.PARAMETER Method
Targeted authentication method of the campaign (targetedAuthenticationMethod of the include target).
Valid values: microsoftAuthenticator (Microsoft Authenticator), passkey. Default: microsoftAuthenticator.

.PARAMETER ExcludeTargets
List of groups to exclude from the campaign, as group object ids and/or group display names (display names
are resolved via an exact Graph group lookup). Pass all values as ONE comma separated token when invoking
the script non-interactively (e.g. -ExcludeTargets "id1,GroupName2"). This parameter is an OVERRIDE only:
if it is not passed, the exclude list defaults to the group named by $AlyaMfaDisabledGroupName in
data/ConfigureEnv.ps1 (provided the variable has a value other than 'PleaseSpecify'); if the variable is
empty/'PleaseSpecify', the default is an empty exclude list which OVERWRITES existing exclude targets of
the campaign (see .DESCRIPTION). Passing the parameter (even with an empty value like -ExcludeTargets '')
replaces the ConfigureEnv default completely.

.PARAMETER SnoozeDurationInDays
Number of days a user can snooze the campaign registration prompt. Graph allows 0 to 180. Default: 14.

.PARAMETER EnforceRegistrationAfterAllowedSnoozes
If true, the user must register the targeted authentication method after the allowed number of snoozes
(no further skip is possible). If false, the user can skip indefinitely. Default: false.

.PARAMETER Preview
If true, the script only reads and prints the current campaign state and the planned (desired) state,
resolves all exclude targets and performs NO write operation. Default: false.

.PARAMETER PassThru
If true, the script returns a result object (tenantId, apiVersion, before, desired, after, verified,
changed, preview). By default the script returns nothing. Default: false.

.INPUTS
None. The script does not accept any pipeline input.

.OUTPUTS
None by default. With -PassThru $true a result object describing the configuration run.
Produces a transcript log file in the logs directory.

.EXAMPLE
PS> .\Configure-RegistrationCampaign.ps1 -Preview $true

Shows the current registration campaign and the state the defaults would produce, without writing anything.

.EXAMPLE
PS> .\Configure-RegistrationCampaign.ps1

Configures the campaign with the defaults: enabled, all_users, microsoftAuthenticator, snooze 14 days,
no enforced registration and the exclude list derived from data/ConfigureEnv.ps1: the group named by
$AlyaMfaDisabledGroupName is excluded automatically (empty exclude list if the variable is unset or
'PleaseSpecify', which overwrites existing excludes - warning is printed).

.EXAMPLE
PS> .\Configure-RegistrationCampaign.ps1 -ExcludeTargets ''

Intentional empty override: disables the automatic $AlyaMfaDisabledGroupName exclusion and writes an
EMPTY exclude list (existing excludes are removed, warning is printed).

.EXAMPLE
PS> .\Configure-RegistrationCampaign.ps1 -State enabled -IncludeTarget all_users -Method microsoftAuthenticator -ExcludeTargets "35296cc5-baac-4fe5-a966-3a797dd2afa2" -SnoozeDurationInDays 8 -EnforceRegistrationAfterAllowedSnoozes $true

Recommended hardening configuration: enforce the Microsoft Authenticator registration for all users after
8 snooze days, excluding one group (by object id; a display name like "ALYASG-ADM-MFADISABLED" works too).

.EXAMPLE
PS> .\Configure-RegistrationCampaign.ps1 -ExcludeTargets "ALYASG-ADM-MFADISABLED,SomeOtherGroup" -SnoozeDurationInDays 8 -EnforceRegistrationAfterAllowedSnoozes $true

Exclude targets given as display names, resolved to group object ids via Graph.

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [ValidateSet("enabled", "disabled")]
    [string]$State = "enabled",
    [string]$IncludeTarget = "all_users",
    [ValidateSet("group")]
    [string]$IncludeTargetType = "group",
    [ValidateSet("microsoftAuthenticator", "passkey")]
    [string]$Method = "microsoftAuthenticator",
    [string[]]$ExcludeTargets = @(),
    [ValidateRange(0, 180)]
    [int]$SnoozeDurationInDays = 14,
    [bool]$EnforceRegistrationAfterAllowedSnoozes = $false,
    [bool]$Preview = $false,
    [bool]$PassThru = $false
)

# Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transcript
Start-Transcript -Path "$($AlyaLogs)\scripts\security\Configure-RegistrationCampaign-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"

# Logins
LoginTo-MgGraph -Scopes @("Policy.ReadWrite.AuthenticationFlows","Group.Read.All")

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Configure-RegistrationCampaign | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Override detection: only an explicitly passed -ExcludeTargets overrides the ConfigureEnv default
# (an intentionally empty override like -ExcludeTargets '' counts as explicit as well)
$excludeTargetsExplicitlySet = $PSBoundParameters.ContainsKey("ExcludeTargets")

# Normalizing array parameters: accept ONE comma separated token (pwsh -File/Wrapper mode binds
# space separated values to the FOLLOWING parameters, see PowerShell conventions)
$ExcludeTargets = @($ExcludeTargets | ForEach-Object { $_ -split "," } | ForEach-Object { $_.Trim() } | Where-Object { -Not [string]::IsNullOrEmpty($_) })

# ExcludeTargets default from data/ConfigureEnv.ps1: if $AlyaMfaDisabledGroupName has a value other than
# 'PleaseSpecify', the group named by it is excluded automatically (Alya convention: ConfigureEnv defines
# the default, parameters are overrides only)
$excludeTargetsSource = "parameter (explicit override)"
if (-Not $excludeTargetsExplicitlySet)
{
    if (-Not [string]::IsNullOrWhiteSpace("$AlyaMfaDisabledGroupName") -and "$AlyaMfaDisabledGroupName" -ne "PleaseSpecify")
    {
        $ExcludeTargets = @("$AlyaMfaDisabledGroupName")
        $excludeTargetsSource = 'data/ConfigureEnv.ps1 ($AlyaMfaDisabledGroupName)'
        Write-Host "ExcludeTargets not passed: using the ConfigureEnv default, excluding group '$AlyaMfaDisabledGroupName' (`$AlyaMfaDisabledGroupName)" -ForegroundColor $CommandInfo
    }
    else
    {
        $excludeTargetsSource = 'none (parameter not passed and $AlyaMfaDisabledGroupName is empty or PleaseSpecify)'
        Write-Host "ExcludeTargets not passed and `$AlyaMfaDisabledGroupName is empty or 'PleaseSpecify': no automatic exclusions" -ForegroundColor $CommandInfo
    }
}
else
{
    Write-Host "ExcludeTargets explicitly passed: overriding the ConfigureEnv default (`$AlyaMfaDisabledGroupName)" -ForegroundColor $CommandInfo
}

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

# Resolves a campaign target (all_users, a group object id or a group display name) to a group object id
function Resolve-CampaignTargetId
{
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Value,
        [Parameter(Mandatory = $true)]
        [string]$ApiVersion
    )
    $trimmed = $Value.Trim()
    if ($trimmed -eq "all_users")
    {
        return "all_users"
    }
    $parsedGuid = $trimmed -as [System.Guid]
    if ($null -ne $parsedGuid)
    {
        return $parsedGuid.ToString()
    }
    # Display name: exact Graph group lookup
    $filter = "displayName eq '$($trimmed -replace "'", "''")'"
    $uri = "$AlyaGraphEndpoint/$ApiVersion/groups?`$filter=$([uri]::EscapeDataString($filter))&`$select=id,displayName"
    Write-Host "  Resolving group '$($trimmed)' via Graph ($ApiVersion)" -ForegroundColor $CommandInfo
    try
    {
        $response = Invoke-MgGraphRequest -Method "Get" -Uri $uri -ErrorAction Stop
    }
    catch
    {
        $errorBody = "$($_.ErrorDetails.Message)"
        if ([string]::IsNullOrWhiteSpace($errorBody))
        {
            $errorBody = "$($_.Exception.Message)"
        }
        throw "Not able to resolve group '$($trimmed)': $($errorBody)"
    }
    $groups = @(Get-GraphPropertyValue -GraphObject $response -Name "value")
    if ($groups.Count -eq 0)
    {
        throw "Group with display name '$($trimmed)' not found in this tenant"
    }
    if ($groups.Count -gt 1)
    {
        $foundIds = @($groups | ForEach-Object { "$(Get-GraphPropertyValue -GraphObject $_ -Name "id")" }) -join ", "
        throw "Group display name '$($trimmed)' is ambiguous ($($groups.Count) groups found: $($foundIds)). Use the group object id instead."
    }
    $groupId = "$(Get-GraphPropertyValue -GraphObject $groups[0] -Name "id")"
    Write-Host "  Group '$($trimmed)' resolved to id $($groupId)" -ForegroundColor $CommandInfo
    return $groupId
}

# Extracts the registration campaign out of a policies/authenticationMethodsPolicy response
function Get-RegistrationCampaign
{
    [CmdletBinding()]
    Param(
        [Parameter()]
        [AllowNull()]
        [object]$PolicyResponse
    )
    $registrationEnforcement = Get-GraphPropertyValue -GraphObject $PolicyResponse -Name "registrationEnforcement"
    if ($null -eq $registrationEnforcement)
    {
        return $null
    }
    return Get-GraphPropertyValue -GraphObject $registrationEnforcement -Name "authenticationMethodsRegistrationCampaign"
}

# Builds a flat, comparable and printable string representation of a campaign
function Get-CampaignComparable
{
    [CmdletBinding()]
    [OutputType([string[]])]
    Param(
        [Parameter()]
        [AllowNull()]
        [object]$Campaign
    )
    if ($null -eq $Campaign)
    {
        return @("state=<not configured>")
    }
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("state=$(Get-GraphPropertyValue -GraphObject $Campaign -Name "state")")
    $snoozeValue = Get-GraphPropertyValue -GraphObject $Campaign -Name "snoozeDurationInDays"
    if ($null -eq $snoozeValue -or [string]::IsNullOrWhiteSpace("$snoozeValue"))
    {
        $snoozeValue = 14
    }
    $lines.Add("snoozeDurationInDays=$([int]$snoozeValue)")
    # Defensive normalization: a missing/empty enforceRegistrationAfterAllowedSnoozes value (Graph can
    # omit the property in GET responses, e.g. v1.0) is treated as False for the comparison
    $enforceValue = Get-GraphPropertyValue -GraphObject $Campaign -Name "enforceRegistrationAfterAllowedSnoozes"
    if ($null -eq $enforceValue -or [string]::IsNullOrWhiteSpace("$enforceValue"))
    {
        $enforceValue = $false
    }
    $lines.Add("enforceRegistrationAfterAllowedSnoozes=$([bool]$enforceValue)")
    $includeTargets = @(Get-GraphPropertyValue -GraphObject $Campaign -Name "includeTargets")
    if ($includeTargets.Count -eq 0)
    {
        $lines.Add("includeTargets=<none>")
    }
    foreach ($includeTarget in $includeTargets)
    {
        $lines.Add("includeTargets=$(Get-GraphPropertyValue -GraphObject $includeTarget -Name "targetType")|$(Get-GraphPropertyValue -GraphObject $includeTarget -Name "id")|$(Get-GraphPropertyValue -GraphObject $includeTarget -Name "targetedAuthenticationMethod")")
    }
    $excludeTargets = @(Get-GraphPropertyValue -GraphObject $Campaign -Name "excludeTargets")
    if ($excludeTargets.Count -eq 0)
    {
        $lines.Add("excludeTargets=<none>")
    }
    foreach ($excludeTarget in $excludeTargets)
    {
        $lines.Add("excludeTargets=$(Get-GraphPropertyValue -GraphObject $excludeTarget -Name "targetType")|$(Get-GraphPropertyValue -GraphObject $excludeTarget -Name "id")")
    }
    return @($lines | Sort-Object)
}

function Write-Campaign
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Title,
        [Parameter()]
        [AllowNull()]
        [object]$Campaign
    )
    Write-Host $Title -ForegroundColor $CommandInfo
    foreach ($line in (Get-CampaignComparable -Campaign $Campaign))
    {
        Write-Host "  $($line)"
    }
}

# Reading the current campaign state, preferring beta (v1.0 GET omits
# enforceRegistrationAfterAllowedSnoozes, so the read-back verification requires beta)
$apiVersion = "beta"
$currentPolicy = $null
$currentCampaign = $null
try
{
    $currentPolicy = Invoke-MgGraphRequest -Method "Get" -Uri "$AlyaGraphEndpoint/beta/policies/authenticationMethodsPolicy" -ErrorAction Stop
    $currentCampaign = Get-RegistrationCampaign -PolicyResponse $currentPolicy
    if ($null -eq (Get-GraphPropertyValue -GraphObject $currentPolicy -Name "registrationEnforcement"))
    {
        Write-Host "Graph beta does not return registrationEnforcement in this tenant, falling back to v1.0 (WARNING: v1.0 GET omits enforceRegistrationAfterAllowedSnoozes, read-back verification of this property is not possible)" -ForegroundColor $CommandWarning
        $apiVersion = "v1.0"
        $currentPolicy = Invoke-MgGraphRequest -Method "Get" -Uri "$AlyaGraphEndpoint/v1.0/policies/authenticationMethodsPolicy" -ErrorAction Stop
        $currentCampaign = Get-RegistrationCampaign -PolicyResponse $currentPolicy
    }
}
catch
{
    $errorBody = "$($_.ErrorDetails.Message)"
    if ([string]::IsNullOrWhiteSpace($errorBody))
    {
        $errorBody = "$($_.Exception.Message)"
    }
    throw "Not able to read the current authentication methods policy ($apiVersion): $($errorBody)"
}
Write-Host "Using Graph API version $($apiVersion) for policies/authenticationMethodsPolicy" -ForegroundColor $CommandInfo
Write-Campaign -Title "Current registration campaign (Ist):" -Campaign $currentCampaign

# Resolving the desired targets
Write-Host "Resolving desired campaign targets" -ForegroundColor $CommandInfo
$includeTargetId = Resolve-CampaignTargetId -Value $IncludeTarget -ApiVersion $apiVersion
$excludeTargetIds = [System.Collections.Generic.List[string]]::new()
foreach ($excludeTarget in $ExcludeTargets)
{
    $resolvedExcludeId = Resolve-CampaignTargetId -Value $excludeTarget -ApiVersion $apiVersion
    if (-Not $excludeTargetIds.Contains($resolvedExcludeId))
    {
        $excludeTargetIds.Add($resolvedExcludeId)
    }
}

# Empty effective exclude list: the campaign exclude list will be OVERWRITTEN with an empty list
if ($excludeTargetIds.Count -eq 0)
{
    $currentExcludeTargets = @(Get-GraphPropertyValue -GraphObject $currentCampaign -Name "excludeTargets")
    Write-Host "NOTE: no exclude targets resulted (source: $($excludeTargetsSource)). The exclude list of the campaign is written as an EMPTY list." -ForegroundColor $CommandWarning
    if ($currentExcludeTargets.Count -gt 0)
    {
        Write-Host "WARNING: the following $($currentExcludeTargets.Count) existing exclude target(s) will be REMOVED from the campaign:" -ForegroundColor $CommandWarning
        foreach ($currentExcludeTarget in $currentExcludeTargets)
        {
            Write-Host "  $(Get-GraphPropertyValue -GraphObject $currentExcludeTarget -Name "targetType")|$(Get-GraphPropertyValue -GraphObject $currentExcludeTarget -Name "id")" -ForegroundColor $CommandWarning
        }
    }
}

# Building the desired campaign
$desiredExcludeTargets = [System.Collections.Generic.List[object]]::new()
foreach ($excludeTargetId in $excludeTargetIds)
{
    $desiredExcludeTargets.Add(@{
        "@odata.type" = "#microsoft.graph.featureTarget"
        "id"          = $excludeTargetId
        "targetType"  = "group"
    })
}
$desiredCampaign = @{
    "state"                                = $State
    "includeTargets"                       = @(@{
        "@odata.type"                = "#microsoft.graph.featureTarget"
        "id"                         = $includeTargetId
        "targetType"                 = $IncludeTargetType
        "targetedAuthenticationMethod" = $Method
    })
    "excludeTargets"                       = @($desiredExcludeTargets)
    "snoozeDurationInDays"                 = $SnoozeDurationInDays
    "enforceRegistrationAfterAllowedSnoozes" = $EnforceRegistrationAfterAllowedSnoozes
}
Write-Campaign -Title "Desired registration campaign (Soll):" -Campaign $desiredCampaign

# Comparing current and desired state
$currentComparable = Get-CampaignComparable -Campaign $currentCampaign
$desiredComparable = Get-CampaignComparable -Campaign $desiredCampaign
$diffs = @(Compare-Object -ReferenceObject $desiredComparable -DifferenceObject $currentComparable)
$alreadyCompliant = ($diffs.Count -eq 0)
if ($alreadyCompliant)
{
    Write-Host "The current campaign already matches the desired configuration (idempotent run)" -ForegroundColor $CommandSuccess
}

if ($Preview -eq $true)
{
    Write-Host "Preview mode: no changes were written to the tenant" -ForegroundColor $CommandSuccess
    $result = [PSCustomObject]@{
        tenantId  = "$AlyaTenantId"
        apiVersion = $apiVersion
        preview   = $true
        changed   = $false
        verified  = $alreadyCompliant
        before    = $currentComparable
        desired   = $desiredComparable
        after     = $currentComparable
    }
    Stop-Transcript
    if ($PassThru -eq $true)
    {
        $result
    }
    return
}

# Writing the desired campaign (PATCH is applied even when already compliant: it is idempotent and
# proves the write path on every run)
Write-Host "Writing registration campaign via PATCH ($apiVersion)" -ForegroundColor $CommandInfo
$patchBody = @{
    "registrationEnforcement" = @{
        "authenticationMethodsRegistrationCampaign" = $desiredCampaign
    }
} | ConvertTo-Json -Depth 10
try
{
    $null = Invoke-MgGraphRequest -Method "Patch" -Uri "$AlyaGraphEndpoint/$apiVersion/policies/authenticationMethodsPolicy" -Body $patchBody -ContentType "application/json" -ErrorAction Stop
}
catch
{
    $errorBody = "$($_.ErrorDetails.Message)"
    if ([string]::IsNullOrWhiteSpace($errorBody))
    {
        $errorBody = "$($_.Exception.Message)"
    }
    throw "PATCH of the registration campaign failed ($apiVersion): $($errorBody)"
}
Write-Host "PATCH succeeded" -ForegroundColor $CommandSuccess

# Read-back verification with a fresh GET
Write-Host "Verifying configuration with a fresh GET (read-back)" -ForegroundColor $CommandInfo
try
{
    $afterPolicy = Invoke-MgGraphRequest -Method "Get" -Uri "$AlyaGraphEndpoint/$apiVersion/policies/authenticationMethodsPolicy" -ErrorAction Stop
}
catch
{
    $errorBody = "$($_.ErrorDetails.Message)"
    if ([string]::IsNullOrWhiteSpace($errorBody))
    {
        $errorBody = "$($_.Exception.Message)"
    }
    throw "Read-back GET of the authentication methods policy failed ($apiVersion): $($errorBody)"
}
$afterCampaign = Get-RegistrationCampaign -PolicyResponse $afterPolicy
Write-Campaign -Title "Registration campaign after configuration (Ist):" -Campaign $afterCampaign
$afterComparable = Get-CampaignComparable -Campaign $afterCampaign
$readBackDiffs = @(Compare-Object -ReferenceObject $desiredComparable -DifferenceObject $afterComparable)
if ($readBackDiffs.Count -gt 0)
{
    Write-Host "ERROR: read-back verification FAILED, the tenant state does not match the desired configuration:" -ForegroundColor Red
    foreach ($readBackDiff in $readBackDiffs)
    {
        $side = if ($readBackDiff.SideIndicator -eq "=>") { "tenant (Ist)" } else { "desired (Soll)" }
        Write-Host "  only in $($side): $($readBackDiff.InputObject)" -ForegroundColor Red
    }
    throw "Read-back verification of the registration campaign failed, see differences above"
}
Write-Host "Read-back verification succeeded: tenant state matches the desired configuration" -ForegroundColor $CommandSuccess

$result = [PSCustomObject]@{
    tenantId   = "$AlyaTenantId"
    apiVersion = $apiVersion
    preview    = $false
    changed    = -Not $alreadyCompliant
    verified   = $true
    before     = $currentComparable
    desired    = $desiredComparable
    after      = $afterComparable
}

# Stopping Transcript
Stop-Transcript

if ($PassThru -eq $true)
{
    $result
}

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAlKDF8fO++Ueeo
# vVeKI6fCkgcbhbNjcZKKwGzJriLDQqCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEID4PeddM
# mYqgUbatHgiE8r6i8sfwbfWBvRGc5q9Lmt2bMA0GCSqGSIb3DQEBAQUABIICAChj
# qBBzUDgCitbqDyEXx7WAJiOUwiNKJtOk81ZxuJZD5f8vUkMyxlqKs4XI0UdZVKTf
# ers4WbHUm52FknEmCTJ/3tua5/lQHIoMTwec440EMcnODAdQ4O2EGUfbmRjJMdBb
# Hr0+toJdUDfSCOywj5K8q3d0HEIAydqe0YBOxEuPJ4YQ2lL1luyji60c1ErabXSA
# zJUotgvPhKD80kQJATJQ6IpptriFA7f+iR6YvdtBqU2IqqQTop8/tupTnVfdTtg5
# T2/v/UuH97WifKO8XVKa3A8V8Z9SlCU5eKLn04U85dOyXMQnH5xqawkhJnRCBV9S
# 3/ryiSI/mVn6Ko1kWVsuKMIB/4z4WH0Ylzwu3Q6J66Ukf7TOLjttBZ5Pbhttz+6v
# e2UZiQPVvl1qH/sI4Qx3Or4xF1vCriKvZa+VWQ1bGiU7XCzQLDvwwhCLAk8hEwZy
# qanx5PCcS2MGU0TyV7jFpVIQjv2Mx9kQfH82a7erhrbIY6r4tLFT+KJHf3zB77HC
# uVJC8wxUzjfrowO8PvXTkYquDMII5DUT006l9k9e1pCySRE4p1VoMRJzXXJRSINg
# ijyEiVjs1uL8OMvlasHt2uwKorAvBTEnBH+zHcf2D6dJc+4oeS3/+L9MMJ7A2SHi
# 93FmwGYbHk1EascHAZ9EAxmD4LBCADWVps4oJ8i6oYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCBaRDFuRdatZ8kSBgSRGwS1Vpzt97xUDad25I3XSpYuhgIUaKwW
# QCwoBhRmuWv0wKXRd4KfGvAYDzIwMjYxMTA4MjA0ODUyWjADAgEBoF2kWzBZMQsw
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
# BDEyBDBPg7QzmdRnSO71EoagQGIl+bZ7xJ4iJ15Ov4vgmWhELl7OYoyf5fac/5mn
# japc7UkwgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGAJcDs1OcjXZulG4+Hcj89o00MhR+RxHf1kVQ2qlu/eoQv
# C5kdqwSjmX1J1vxf5HvLKcoguxNyJhD5npz775PRhzmhop4rO0fZYMOHmUOuD/mS
# lAf1HjKgNoQFmZNalGz1/AOLgtv0ML6ZAIFY9P3c67GKU1dKq9zpjwmZFX0dd4am
# OFLRi5Pik2V10kkXAFmgNh9teaCM9AVosl28UwDOTr6dmPmF4YTZQBohBzOu1sCS
# dZsg8KGSh61QBonNGwv1Duxq9KSsjlt4aKMBbu4UkSrazLwX4z4eHML4wa97OT0M
# 8EnfQ46LIaPCWvrSIErHAbFnvp09TSYjXCXMiMnX8rdj5HmHZLoPK9dFwAami7iR
# ksOonjcABnWsIB0Y3b2gxzAAF2yVclJuuv5UAMPD9rWPg2qUScdaVKzwApoaDpdZ
# SwbCHDlwr5JA7PiL8kPlS4sfnIfxiTcIQpEt4muWSrA1mXfjv0GHgy5nErCLyUK7
# d1cBhcAfDnf50oEIRkHO
# SIG # End signature block
