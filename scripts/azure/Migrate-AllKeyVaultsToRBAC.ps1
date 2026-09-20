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
    12.02.2026 Konrad Brunner       Initial Version
    15.09.2026 Konrad Brunner       Fixed role permission evaluation for Az.Resources 10
    16.09.2026 Konrad Brunner       Fixed parameter set error of Get-AzRoleAssignment with Az.Resources 10 (ExpandPrincipalGroups is only allowed with ObjectId)
    16.09.2026 Konrad Brunner       Support service principal logins (management app) when checking own key vault access
    16.09.2026 Konrad Brunner       Skip access policies of principals that no longer exist and surface New-AzRoleAssignment errors instead of swallowing them
    16.09.2026 Konrad Brunner       Detect own permissions inherited from management group scopes when checking key vault access

#>

<#
.SYNOPSIS
Migrates all Azure Key Vaults in specified or all subscriptions to RBAC authorization.

.DESCRIPTION
This script checks one or multiple Azure subscriptions for existing Key Vaults and migrates each vault from access policies to RBAC authorization if not already enabled. It maps existing access policies to suitable built-in Azure roles and assigns them at the Key Vault scope. The script supports optional processing of a single Key Vault by name and can target a specific subscription if desired. It automatically handles Azure module installation and authentication, and logs its operations.

.PARAMETER processOnlyKeyVaultsWithName
Specifies the name of a single Key Vault to be migrated. If not provided, all Key Vaults in the selected subscriptions are processed.

.PARAMETER subscriptionName
Specifies the name of a single subscription to process. If not provided, all subscriptions defined in the configuration are processed.

.PARAMETER dryRun
If set to $true, no changes are made; the script only reports what would be done.

.PARAMETER handleStoragePermissions
If set to $true, storage permissions in Key Vault access policies are also migrated.

.INPUTS
None. The script does not accept pipeline input.

.OUTPUTS
None. The script writes status messages and logs actions to a transcript file.

.EXAMPLE
PS> .\Migrate-AllKeyVaultsToRBAC.ps1 -subscriptionName "Production" -processOnlyKeyVaultsWithName "mykeyvault001" -dryRun $false

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [string]$processOnlyKeyVaultsWithName = $null,
    [string]$subscriptionName = $null,
    [bool]$dryRun = $true,
    [bool]$handleStoragePermissions = $false
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transcript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\Migrate-AllKeyVaultsToRBAC-$($AlyaTimeString).log" | Out-Null

# Members
$permissionMap = @(
    @{Group="Key";Access="GET";Permissions=@("Microsoft.KeyVault/vaults/keys/read")},
    @{Group="Key";Access="LIST";Permissions=@("Microsoft.KeyVault/vaults/keys/read")},
    @{Group="Key";Access="UPDATE";Permissions=@("Microsoft.KeyVault/vaults/keys/update/action")},
    @{Group="Key";Access="CREATE";Permissions=@("Microsoft.KeyVault/vaults/keys/create/action")},
    @{Group="Key";Access="IMPORT";Permissions=@("Microsoft.KeyVault/vaults/keys/import/action")},
    @{Group="Key";Access="DELETE";Permissions=@("Microsoft.KeyVault/vaults/keys/delete")},
    @{Group="Key";Access="RECOVER";Permissions=@("Microsoft.KeyVault/vaults/keys/recover/action")},
    @{Group="Key";Access="BACKUP";Permissions=@("Microsoft.KeyVault/vaults/keys/backup/action")},
    @{Group="Key";Access="RESTORE";Permissions=@("Microsoft.KeyVault/vaults/keys/restore/action")},
    @{Group="Key";Access="DECRYPT";Permissions=@("Microsoft.KeyVault/vaults/keys/decrypt/action")},
    @{Group="Key";Access="ENCRYPT";Permissions=@("Microsoft.KeyVault/vaults/keys/encrypt/action")},
    @{Group="Key";Access="UNWRAPKEY";Permissions=@("Microsoft.KeyVault/vaults/keys/unwrap/action")},
    @{Group="Key";Access="WRAPKEY";Permissions=@("Microsoft.KeyVault/vaults/keys/wrap/action")},
    @{Group="Key";Access="VERIFY";Permissions=@("Microsoft.KeyVault/vaults/keys/verify/action")},
    @{Group="Key";Access="SIGN";Permissions=@("Microsoft.KeyVault/vaults/keys/sign/action")},
    @{Group="Key";Access="PURGE";Permissions=@("Microsoft.KeyVault/vaults/keys/purge/action")},
    @{Group="Key";Access="RELEASE";Permissions=@("Microsoft.KeyVault/vaults/keys/release/action")},
    @{Group="Key";Access="ROTATE";Permissions=@("Microsoft.KeyVault/vaults/keys/rotate/action")},
    @{Group="Key";Access="GETROTATIONPOLICY";Permissions=@("Microsoft.KeyVault/vaults/keyrotationpolicies/read")},
    @{Group="Key";Access="SETROTATIONPOLICY";Permissions=@("Microsoft.KeyVault/vaults/keyrotationpolicies/write")},
    @{Group="Key";Access="ALL";Permissions=@("Microsoft.KeyVault/vaults/keys/read","Microsoft.KeyVault/vaults/keys/read","Microsoft.KeyVault/vaults/keys/update/action","Microsoft.KeyVault/vaults/keys/create/action","Microsoft.KeyVault/vaults/keys/import/action","Microsoft.KeyVault/vaults/keys/delete","Microsoft.KeyVault/vaults/keys/recover/action","Microsoft.KeyVault/vaults/keys/backup/action","Microsoft.KeyVault/vaults/keys/restore/action","Microsoft.KeyVault/vaults/keys/decrypt/action","Microsoft.KeyVault/vaults/keys/encrypt/action","Microsoft.KeyVault/vaults/keys/unwrap/action","Microsoft.KeyVault/vaults/keys/wrap/action","Microsoft.KeyVault/vaults/keys/verify/action","Microsoft.KeyVault/vaults/keys/sign/action","Microsoft.KeyVault/vaults/keys/purge/action","Microsoft.KeyVault/vaults/keys/release/action","Microsoft.KeyVault/vaults/keys/rotate/action","Microsoft.KeyVault/vaults/keyrotationpolicies/read","Microsoft.KeyVault/vaults/keyrotationpolicies/write")},
    @{Group="Certificate";Access="GET";Permissions=@("Microsoft.KeyVault/vaults/certificates/read")},
    @{Group="Certificate";Access="LIST";Permissions=@("Microsoft.KeyVault/vaults/certificates/read")},
    @{Group="Certificate";Access="UPDATE";Permissions=@("Microsoft.KeyVault/vaults/certificates/update/action")},
    @{Group="Certificate";Access="CREATE";Permissions=@("Microsoft.KeyVault/vaults/certificates/create/action")},
    @{Group="Certificate";Access="IMPORT";Permissions=@("Microsoft.KeyVault/vaults/certificates/import/action")},
    @{Group="Certificate";Access="DELETE";Permissions=@("Microsoft.KeyVault/vaults/certificates/delete")},
    @{Group="Certificate";Access="RECOVER";Permissions=@("Microsoft.KeyVault/vaults/certificates/recover/action")},
    @{Group="Certificate";Access="BACKUP";Permissions=@("Microsoft.KeyVault/vaults/certificates/backup/action")},
    @{Group="Certificate";Access="RESTORE";Permissions=@("Microsoft.KeyVault/vaults/certificates/restore/action")},
    @{Group="Certificate";Access="MANAGECONTACTS";Permissions=@("Microsoft.KeyVault/vaults/certificatecontacts/write")},
    @{Group="Certificate";Access="MANAGEISSUERS";Permissions=@("Microsoft.KeyVault/vaults/certificatecas/write")},
    @{Group="Certificate";Access="GETISSUERS";Permissions=@("Microsoft.KeyVault/vaults/certificatecas/read")},
    @{Group="Certificate";Access="LISTISSUERS";Permissions=@("Microsoft.KeyVault/vaults/certificatecas/read")},
    @{Group="Certificate";Access="SETISSUERS";Permissions=@("Microsoft.KeyVault/vaults/certificatecas/write")},
    @{Group="Certificate";Access="DELETEISSUERS";Permissions=@("Microsoft.KeyVault/vaults/certificatecas/delete")},
    @{Group="Certificate";Access="PURGE";Permissions=@("Microsoft.KeyVault/vaults/certificates/purge/action")},
    @{Group="Certificate";Access="ALL";Permissions=@("Microsoft.KeyVault/vaults/certificates/read","Microsoft.KeyVault/vaults/certificates/read","Microsoft.KeyVault/vaults/certificates/update/action","Microsoft.KeyVault/vaults/certificates/create/action","Microsoft.KeyVault/vaults/certificates/import/action","Microsoft.KeyVault/vaults/certificates/delete","Microsoft.KeyVault/vaults/certificates/recover/action","Microsoft.KeyVault/vaults/certificates/backup/action","Microsoft.KeyVault/vaults/certificates/restore/action","Microsoft.KeyVault/vaults/certificatecontacts/write","Microsoft.KeyVault/vaults/certificatecas/write","Microsoft.KeyVault/vaults/certificatecas/read","Microsoft.KeyVault/vaults/certificatecas/read","Microsoft.KeyVault/vaults/certificatecas/write","Microsoft.KeyVault/vaults/certificatecas/delete","Microsoft.KeyVault/vaults/certificates/purge/action")},
    @{Group="Secret";Access="GET";Permissions=@("Microsoft.KeyVault/vaults/secrets/getSecret/action")},
    @{Group="Secret";Access="LIST";Permissions=@("Microsoft.KeyVault/vaults/secrets/readMetadata/action")},
    @{Group="Secret";Access="SET";Permissions=@("Microsoft.KeyVault/vaults/secrets/setSecret/action","Microsoft.KeyVault/vaults/secrets/update/action")},
    @{Group="Secret";Access="DELETE";Permissions=@("Microsoft.KeyVault/vaults/secrets/delete")},
    @{Group="Secret";Access="RECOVER";Permissions=@("Microsoft.KeyVault/vaults/secrets/recover/action")},
    @{Group="Secret";Access="BACKUP";Permissions=@("Microsoft.KeyVault/vaults/secrets/backup/action")},
    @{Group="Secret";Access="RESTORE";Permissions=@("Microsoft.KeyVault/vaults/secrets/restore/action")},
    @{Group="Secret";Access="PURGE";Permissions=@("Microsoft.KeyVault/vaults/secrets/purge/action")},
    @{Group="Secret";Access="ALL";Permissions=@("Microsoft.KeyVault/vaults/secrets/getSecret/action","Microsoft.KeyVault/vaults/secrets/readMetadata/action","Microsoft.KeyVault/vaults/secrets/setSecret/action","Microsoft.KeyVault/vaults/secrets/update/action","Microsoft.KeyVault/vaults/secrets/delete","Microsoft.KeyVault/vaults/secrets/recover/action","Microsoft.KeyVault/vaults/secrets/backup/action","Microsoft.KeyVault/vaults/secrets/restore/action","Microsoft.KeyVault/vaults/secrets/purge/action")},
    @{Group="Storage";Access="GET";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/read")},
    @{Group="Storage";Access="LIST";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/read")},
    @{Group="Storage";Access="DELETE";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/delete")},
    @{Group="Storage";Access="SET";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/set/action")},
    @{Group="Storage";Access="UPDATE";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/set/action")},
    @{Group="Storage";Access="REGENERATEKEY";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/regeneratekey/action")},
    @{Group="Storage";Access="GETSAS";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/sas/read")},
    @{Group="Storage";Access="LISTSAS";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/sas/read")},
    @{Group="Storage";Access="DELETESAS";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/sas/delete")},
    @{Group="Storage";Access="SETSAS";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/sas/set/action")},
    @{Group="Storage";Access="RECOVER";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/recover/action")},
    @{Group="Storage";Access="BACKUP";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/backup/action")},
    @{Group="Storage";Access="RESTORE";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/restore/action")},
    @{Group="Storage";Access="PURGE";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/purge/action")},
    @{Group="Storage";Access="ALL";Permissions=@("Microsoft.KeyVault/vaults/storageaccounts/read","Microsoft.KeyVault/vaults/storageaccounts/read","Microsoft.KeyVault/vaults/storageaccounts/delete","Microsoft.KeyVault/vaults/storageaccounts/set/action","Microsoft.KeyVault/vaults/storageaccounts/set/action","Microsoft.KeyVault/vaults/storageaccounts/regeneratekey/action","Microsoft.KeyVault/vaults/storageaccounts/sas/read","Microsoft.KeyVault/vaults/storageaccounts/sas/read","Microsoft.KeyVault/vaults/storageaccounts/sas/delete","Microsoft.KeyVault/vaults/storageaccounts/sas/set/action","Microsoft.KeyVault/vaults/storageaccounts/recover/action","Microsoft.KeyVault/vaults/storageaccounts/backup/action","Microsoft.KeyVault/vaults/storageaccounts/restore/action","Microsoft.KeyVault/vaults/storageaccounts/purge/action")}
)

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.KeyVault"

# Logins
LoginTo-Az -SubscriptionName ([string]::IsNullOrEmpty($subscriptionName) ? $AlyaSubscriptionName : $subscriptionName)

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Monitor | Migrate-AllKeyVaultsToRBAC | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Getting all key vault roles
Write-Host "Getting all key vault roles" -ForegroundColor $CommandInfo
$allRoles = Get-AzRoleDefinition
$roles = $allRoles | Where-Object { $_.Name -like "Key Vault*" } | Sort-Object { 
    $s = 0
    if ($_.Name.Contains("User")) { $s += 1 }
    if ($_.Name.Contains("Officer")) { $s += 3 }
    if ($_.Name.Contains("Operator")) { $s += 5 }
    if ($_.Name.Contains("Contributor")) { $s += 7 }
    if ($_.Name.Contains("Reader")) { $s += 9 }
    if ($_.Name.Contains("Administrator")) { $s += 11 }
    if ($_.Name.Contains("Crypto")) { $s += 1 }
    if ($_.Name.Contains("Data")) { $s -= 1 }
    $s
}
$roles.Name

# Functions
function Get-RolePermissionEntry($role)
{
    $permissionsProperty = $role.PSObject.Properties["Permissions"]
    if ($null -ne $permissionsProperty -and $null -ne $permissionsProperty.Value)
    {
        return @($permissionsProperty.Value)
    }

    return @($role)
}

function Get-RolePermissionValue($role, $propertyName)
{
    $values = @()
    foreach($permissionEntry in (Get-RolePermissionEntry -role $role))
    {
        $property = $permissionEntry.PSObject.Properties[$propertyName]
        if ($null -ne $property -and $null -ne $property.Value)
        {
            foreach($value in $property.Value)
            {
                if ($values -notcontains $value)
                {
                    $values += $value
                }
            }
        }
    }

    return $values
}

function Test-RoleAllowsPermission($role, $permission, $dataAction = $false)
{
    $allowedPropertyName = $dataAction ? "DataActions" : "Actions"
    $deniedPropertyName = $dataAction ? "NotDataActions" : "NotActions"

    foreach($permissionEntry in (Get-RolePermissionEntry -role $role))
    {
        $allowed = $false
        $allowedProperty = $permissionEntry.PSObject.Properties[$allowedPropertyName]
        if ($null -ne $allowedProperty -and $null -ne $allowedProperty.Value)
        {
            foreach($allowedPermission in $allowedProperty.Value)
            {
                if ($permission -like $allowedPermission)
                {
                    $allowed = $true
                    break
                }
            }
        }
        if (-Not $allowed)
        {
            continue
        }

        $denied = $false
        $deniedProperty = $permissionEntry.PSObject.Properties[$deniedPropertyName]
        if ($null -ne $deniedProperty -and $null -ne $deniedProperty.Value)
        {
            foreach($deniedPermission in $deniedProperty.Value)
            {
                if ($permission -like $deniedPermission)
                {
                    $denied = $true
                    break
                }
            }
        }
        if (-Not $denied)
        {
            return $true
        }
    }

    return $false
}

function Is-RoleContainedInRole($checkRole, $containedInRole)
{
    if ((Get-RolePermissionValue -role $containedInRole -propertyName "NotDataActions").Count -gt 0)
    {
        return $false
    }

    foreach($action in (Get-RolePermissionValue -role $checkRole -propertyName "DataActions"))
    {
        if (-Not (Test-RoleAllowsPermission -role $containedInRole -permission $action -dataAction $true))
        {
            return $false
        }
    }

    return $true
}

function Find-RoleByPermissions($allKvRoles, $allPerms)
{
    $rert = $null
    foreach($role in $allKvRoles)
    {
        $allFnd = $true
        foreach($perm in $allPerms) {
            if (-Not (Test-RoleAllowsPermission -role $role -permission $perm -dataAction $true)) {
                $allFnd = $false
                break
            }
        }
        if ($allFnd) {
            $rert = $role
            break
        }
    }
    return $rert
}

# Checking subscriptions
foreach ($AlyaSubscriptionName in (([string]::IsNullOrEmpty($subscriptionName) ? $AlyaAllSubscriptions : @($subscriptionName)) | Select-Object -Unique))
{
    Write-Host "Checking subscription $AlyaSubscriptionName" -ForegroundColor $MenuColor
  
    # Switching to subscription
    $sub = Get-AzSubscription -SubscriptionName $AlyaSubscriptionName
    $null = Set-AzContext -Subscription $sub.Id
    $Context = Get-AzContext

    # Resolving the management group ancestry of the subscription. Management group scopes are logical
    # ancestors of everything below them, but not string prefixes of their resource ids. Therefore,
    # assignments inherited from management groups need the extra matching in the scope filter below.
    $mgAncestorScopes = @()
    try {
        $ancestryResponse = Invoke-AzRestMethod -Method Get -Path "/subscriptions/$($sub.Id)/providers/Microsoft.Management/managementGroups?api-version=2023-04-01"
        if ($ancestryResponse.StatusCode -eq 200) {
            $mgAncestorScopes = @(($ancestryResponse.Content | ConvertFrom-Json).value | ForEach-Object { $_.id.TrimEnd("/") })
        }
        else {
            Write-Warning "  Can't resolve management group ancestry (status $($ancestryResponse.StatusCode)), assignments inherited from management groups will not be detected!"
        }
    }
    catch {
        Write-Warning "  Can't resolve management group ancestry ($($_.Exception.Message)), assignments inherited from management groups will not be detected!"
    }

    $KeyVaults = Get-AzKeyVault
    foreach ($KeyVault in $KeyVaults)
    {
        $KeyVaultName = $KeyVault.VaultName
        if (-Not [string]::IsNullOrEmpty($processOnlyKeyVaultsWithName) -and $processOnlyKeyVaultsWithName -ne $KeyVaultName)
        {
            continue
        }

        Write-Host "Checking key vault $KeyVaultName" -ForegroundColor $CommandInfo
        $KeyVault = Get-AzKeyVault -VaultName $KeyVault.VaultName -ResourceGroupName $KeyVault.ResourceGroupName
        if ($KeyVault.EnableRbacAuthorization)
        {
            Write-Host "  Already using RBAC authorization, skipping."
        }
        else
        {
            # Checking own key vault access
            Write-Host "Checking own key vault access" -ForegroundColor $CommandInfo
            $user = Get-CurrentAzAdPrincipal
            # Note: ExpandPrincipalGroups is only supported for user principals (service principals fail with
            # "ExpandPrincipalGroups is only supported for a User principal"), therefore it is only used for users.
            $expandPrincipalGroups = $null -ne $user.PSObject.Properties["UserPrincipalName"]
            # Note: Since Az.Resources 10, ExpandPrincipalGroups is only allowed in the pure ObjectId parameter set.
            # Therefore, all assignments of the principal are fetched and filtered by scope (including inherited scopes) locally.
            $allUserAssignments = $expandPrincipalGroups ? @(Get-AzRoleAssignment -ObjectId $user.Id -ExpandPrincipalGroups) : @(Get-AzRoleAssignment -ObjectId $user.Id)
            $RoleAssignments = @($allUserAssignments | Where-Object {
                $normalizedScope = $_.Scope.TrimEnd("/")
                $KeyVault.ResourceId.Equals($_.Scope, [System.StringComparison]::OrdinalIgnoreCase) -or $KeyVault.ResourceId.StartsWith("$normalizedScope/", [System.StringComparison]::OrdinalIgnoreCase) -or ($mgAncestorScopes -contains $normalizedScope)
            })
            $fndAss = $false
            $fndKv = $false
            foreach($RoleAssignment in $RoleAssignments)
            {
                $roleDefinitionId = ($RoleAssignment.RoleDefinitionId -split "/")[-1]
                $role = $allRoles | Where-Object { ($_.Id -split "/")[-1] -eq $roleDefinitionId }
                if ($null -ne $role)
                {
                    if (Test-RoleAllowsPermission -role $role -permission "Microsoft.Authorization/roleAssignments/write") {
                        $fndAss = $true
                    }
                    if (Test-RoleAllowsPermission -role $role -permission "Microsoft.KeyVault/vaults/write") {
                        $fndKv = $true
                    }
                }
            }   
            if (-Not $fndAss -or -Not $fndKv) {
                if (-Not $dryRun) {
                    Write-Error "  No permissions to set role assignments or update key vaults, skipping migration of this key vault!"
                    exit 1
                }
                else {
                    Write-Warning "  No permissions to set role assignments or update key vaults, skipping migration of this key vault!"
                }
            }

            Write-Host "  Migrating to RBAC authorization..."
            $KeyVault = Get-AzKeyVault -ResourceGroupName $KeyVault.ResourceGroupName -VaultName $KeyVaultName
            Write-Host "    Checking migration"
            foreach($AccessPolicy in $KeyVault.AccessPolicies)
            {
                #$AccessPolicy = $KeyVault.AccessPolicies[0]
                $prcplId = $AccessPolicy.ObjectId
                $isApplicationId = $false
                if ($null -ne $AccessPolicy.ApplicationId)
                {
                    if ($null -ne $prcplId)
                    {
                        throw "Not yet implemented handling of access policies with both object id and application id set! ObjectId: $($AccessPolicy.ObjectId) ApplicationId: $($AccessPolicy.ApplicationId)"
                    }
                    $prcplId = $AccessPolicy.ApplicationId
                    $isApplicationId = $true
                }
                # Checking that the principal still exists in the tenant. Stale access policies of deleted
                # principals can't be migrated, New-AzRoleAssignment would fail with PrincipalNotFound.
                $prcpl = $null
                if ($isApplicationId)
                {
                    $prcpl = Get-AzAdServicePrincipal -ApplicationId $prcplId -ErrorAction SilentlyContinue
                    if ($null -ne $prcpl)
                    {
                        # Use the real object id of the service principal for the role assignments below
                        $prcplId = $prcpl.Id
                    }
                }
                else
                {
                    $prcpl = Get-AzAdUser -ObjectId $prcplId -ErrorAction SilentlyContinue
                    if ($null -eq $prcpl)
                    {
                        $prcpl = Get-AzAdServicePrincipal -ObjectId $prcplId -ErrorAction SilentlyContinue
                    }
                    if ($null -eq $prcpl)
                    {
                        $prcpl = Get-AzAdGroup -ObjectId $prcplId -ErrorAction SilentlyContinue
                    }
                }
                if ($null -eq $prcpl)
                {
                    Write-Warning "      Access policy for object id $($prcplId) points to a principal that no longer exists in the tenant, skipping!"
                    continue
                }
                Write-Host "      Access policy for object id $($prcplId) with permissions to"
                Write-Host "          keys: $($AccessPolicy.PermissionsToKeys -join ",")"
                Write-Host "          secrets: $($AccessPolicy.PermissionsToSecrets -join ",")"
                Write-Host "          certificates: $($AccessPolicy.PermissionsToCertificates -join ",")"
                if ($handleStoragePermissions) {
                    Write-Host "          storage: $($AccessPolicy.PermissionsToStorage -join ",")"
                }
                $allPerms = @()
                $migRoles = @()
                if ($AccessPolicy.PermissionsToKeys.Count -gt 0)
                {
                    $perms = @()
                    foreach($acc in $AccessPolicy.PermissionsToKeys)
                    {
                        $permMap = $permissionMap | Where-Object { $_.Group -eq "Key" -and $_.Access -eq $acc.ToUpper() }
                        if (-Not $permMap) {
                            Write-Error "No permission mapping found for access '$acc' in group Key, skipping!" -ErrorAction Continue
                            exit
                        }
                        foreach($perm in $permMap.Permissions) {
                            if ($perms -notcontains $perm) {
                                $perms += $perm
                            }
                        }
                    }
                    $fndRole = Find-RoleByPermissions -allKvRoles $roles -allPerms $perms
                    if ($fndRole) {
                        Write-Host "        Keys: Possible migration to $($fndRole.Name)"
                        if ($migRoles -notcontains $fndRole) {
                            $migRoles += $fndRole
                        }
                    }
                    else {
                        foreach($perm in $perms) {
                            if ($allPerms -notcontains $perm) {
                                $allPerms += $perm
                            }
                        }
                    }
                }
                if ($AccessPolicy.PermissionsToSecrets.Count -gt 0)
                {
                    $perms = @()
                    foreach($acc in $AccessPolicy.PermissionsToSecrets)
                    {
                        $permMap = $permissionMap | Where-Object { $_.Group -eq "Secret" -and $_.Access -eq $acc.ToUpper() }
                        if (-Not $permMap) {
                            Write-Error "No permission mapping found for access '$acc' in group Secret, skipping!" -ErrorAction Continue
                            exit
                        }
                        foreach($perm in $permMap.Permissions) {
                            if ($perms -notcontains $perm) {
                                $perms += $perm
                            }
                        }
                    }
                    $fndRole = Find-RoleByPermissions -allKvRoles $roles -allPerms $perms
                    if ($fndRole) {
                        Write-Host "        Secrets: Possible migration to $($fndRole.Name)"
                        if ($migRoles -notcontains $fndRole) {
                            $migRoles += $fndRole
                        }
                    }
                    else {
                        foreach($perm in $perms) {
                            if ($allPerms -notcontains $perm) {
                                $allPerms += $perm
                            }
                        }
                    }
                }
                if ($AccessPolicy.PermissionsToCertificates.Count -gt 0)
                {
                    $perms = @()
                    foreach($acc in $AccessPolicy.PermissionsToCertificates)
                    {
                        $permMap = $permissionMap | Where-Object { $_.Group -eq "Certificate" -and $_.Access -eq $acc.ToUpper() }
                        if (-Not $permMap) {
                            Write-Error "No permission mapping found for access '$acc' in group Certificate, skipping!" -ErrorAction Continue
                            exit
                        }
                        if ($permMap.Access -eq "ALL")
                        {
                            $aa = $permMap.Permissions
                        }
                        foreach($perm in $permMap.Permissions) {
                            if ($perms -notcontains $perm) {
                                $perms += $perm
                            }
                        }
                    }
                    $fndRole = Find-RoleByPermissions -allKvRoles $roles -allPerms $perms
                    if ($fndRole) {
                        Write-Host "        Certificates: Possible migration to $($fndRole.Name)"
                        if ($migRoles -notcontains $fndRole) {
                            $migRoles += $fndRole
                        }
                    }
                    else {
                        foreach($perm in $perms) {
                            if ($allPerms -notcontains $perm) {
                                $allPerms += $perm
                            }
                        }
                    }
                }
                if ($handleStoragePermissions) {
                    if ($AccessPolicy.PermissionsToStorage.Count -gt 0)
                    {
                        $perms = @()
                        foreach($acc in $AccessPolicy.PermissionsToStorage)
                        {
                            $permMap = $permissionMap | Where-Object { $_.Group -eq "Storage" -and $_.Access -eq $acc.ToUpper() }
                            if (-Not $permMap) {
                                Write-Error "No permission mapping found for access '$acc' in group Storage, skipping!" -ErrorAction Continue
                                exit
                            }
                            foreach($perm in $permMap.Permissions) {
                                if ($perms -notcontains $perm) {
                                    $perms += $perm
                                }
                            }
                        }
                        $fndRole = Find-RoleByPermissions -allKvRoles $roles -allPerms $perms
                        if ($fndRole) {
                            Write-Host "        Storage: Possible migration to $($fndRole.Name)"
                            if ($migRoles -notcontains $fndRole) {
                                $migRoles += $fndRole
                            }
                        }
                        else {
                            foreach($perm in $perms) {
                                if ($allPerms -notcontains $perm) {
                                    $allPerms += $perm
                                }
                            }
                        }
                    }
                }
                if ($allPerms.Count -gt 0)
                {
                    $fndRole = Find-RoleByPermissions -allKvRoles $roles -allPerms $allPerms
                    if ($fndRole) {
                        Write-Host "        All: Possible migration to $($fndRole.Name)"
                        if ($migRoles -notcontains $fndRole) {
                            $migRoles += $fndRole
                        }
                        $allPerms = $null
                    }
                }
                foreach($checkRole in $migRoles) {
                    foreach($containedInRole in $migRoles) {
                        if ($checkRole.Name -ne $containedInRole.Name) {
                            if (Is-RoleContainedInRole -checkRole $checkRole -containedInRole $containedInRole) {
                                Write-Host "        Role $($checkRole.Name) is contained in role $($containedInRole.Name), removing it from list."
                                $migRoles = $migRoles | Where-Object { $_.Name -ne $checkRole.Name }
                                break
                            }
                        }
                    }
                }
                if ($migRoles.Count -eq 0) {
                    Write-Warning "        No suitable built-in role found for migration, skipping!"
                    continue
                }
                Write-Host "        Roles to assign: $($migRoles.Name -join ", ")"

                foreach($migRole in $migRoles) {
                    Write-Host "          Checking: $($migRole.Name)"
                    $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName $migRole.Name -ObjectId $prcplId -Scope $KeyVault.ResourceId -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq $KeyVault.ResourceId }
                    if ($RoleAssignment)
                    {
                        Write-Host "            Role assignment already exists, skipping."
                        continue
                    }
                    Write-Host "            Role assignment not found, creating..." -ForegroundColor $CommandWarning
                    if (-Not $dryRun -and $fndAss -and $fndKv) {
                        $Retries = 0;
                        $lastError = $null
                        While ($null -eq $RoleAssignment -and $Retries -le 6)
                        {
                            try {
                                $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName $migRole.Name -ObjectId $prcplId -scope $KeyVault.ResourceId -ErrorAction Stop
                            }
                            catch {
                                # Surface the real error instead of swallowing it. Non-retryable errors abort
                                # immediately, transient errors (e.g. propagation delays) are retried below.
                                $lastError = $_.Exception.Message
                                if ($lastError -match "PrincipalNotFound|AuthorizationFailed|InvalidPrincipalId|PrincipalTypeNotSupported") {
                                    throw "Was not able to set role assignment '$($migRole.Name)' for object $prcplId on scope $($KeyVault.ResourceId): $($lastError)"
                                }
                                Write-Host "              Attempt $($Retries + 1) failed: $($lastError)" -ForegroundColor $CommandWarning
                            }
                            if ($null -eq $RoleAssignment) {
                                Start-Sleep -s 10
                                $RoleAssignment = Get-AzRoleAssignment -RoleDefinitionName $migRole.Name -ObjectId $prcplId -scope $KeyVault.ResourceId -ErrorAction SilentlyContinue | Where-Object { $_.Scope -eq $KeyVault.ResourceId }
                            }
                            $Retries++;
                        }
                        if ($Retries -gt 6)
                        {
                            throw "Was not able to set role assignment '$($migRole.Name)' for object $prcplId on scope $($KeyVault.ResourceId). Last error: $($lastError)"
                        }
                    }
                }

            }

            Write-Host "  Migration completed, enabling RBAC authorization on key vault."
            if (-Not $dryRun -and $fndAss -and $fndKv) {
                Update-AzKeyVault -ResourceGroupName $KeyVault.ResourceGroupName -VaultName $KeyVaultName -DisableRbacAuthorization $false
            }
        }
    }
}

# Stopping Transcript
Stop-Transcript

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCJwiflhb3gQSNo
# rgbvjj+Ey75uaQyMuJR209/6+YmkF6CCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g6
# 04YfM/tV5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD
# 4ED6gVYDU/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S
# /gJXhZrh0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp
# 8nKmrVa46Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqt
# f2phU7+yR2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJ
# QWTEE/bP0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKX
# vYkPbEdx+QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4
# yMYgcMKb9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmY
# F8T4xO2k6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2
# mMIVpqWCZ1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7
# spNY6rQb3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd
# 2jANBgkqhkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy
# /fAHsVv1RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW
# 2H3Bh6zNXULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0
# MP6pBPKOL6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/
# pFL9zlcctWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcex
# U0bcV0hLQ4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf
# 6AMOGaM56A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzEC
# p9LnR+34c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9m
# UF5qE6YwQqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+Ku
# aJRsz+cnZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/Jl
# N6m6GM1jEhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutof
# dgNBzMUxgiEGMIIhAgIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJ7nswgo
# +o2xWmAbnYOOuHhFQHgqCH9VT9JiFGS3ZLbYMA0GCSqGSIb3DQEBAQUABIICABxv
# 09bwZ1EVl22lScOGG0mtzvdzUGWBRI0kwR+Cl5ts26Xu3gvBFgN9BY6K18RcyaFh
# 3gk/QOYwhfwyPawG5KK6zdMRYZIFlI5yDUq+GZP1KbS+Pqf2D+Itae3PHtnJaUdD
# snYgeBIEes4d2y97Fd/t08jBAdx5DCujY73LGy/UMFuHfWBmdd39SiRkxiTbCUNO
# 2c8b+xEXeLPxTnFOuzAuGyds9oJRUdi+j2JxpDjdVk5Fugz4bi5fd5IE0uPfBQPE
# SXPkpXFKDejhChy9Y3OKvB1XtjrYGin5Gl/0c3uXSYa5FV1emhiOGKjIjf8vASeK
# Fso4NviI7lCPt+0SWyLY70HlxfAZKDgypcjw6/2tjJwUVykl/friseL2iQd9IIa1
# IteT3za0Nb/gfxvh2IVqnXJFsMYJpFR7kDgwNGgVlRYkKAfZ0kCjHMh54PPuYLuA
# qPTKxrNG2qaxQLlmZ30AGuIL33j4zskNljhE+5yNYRQluecsjLQQemswkotYtTbn
# y0mGyiGYXrjIxhbguAUYvX0FRP/46OgM+Ck/8F7nVxfXNX8N7IlNYX0MMLSIBFAV
# utL0ta9qGBmMD9KsQgXIKk0Vi4RZMHe72bJ7Vimv4Q6UzhhozDNtfmT0qFI5Nz0E
# FFXCbpV7EPqUjVPXVwwebmqe/IQ1nfGhC6beR3FUoYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCB8zc5X2y19HJVUCUyiFFJTY5WnRbO5Hbc7wHihoX+bKAIUF8XX
# OL90xgGssYTjZRbn0KefEJQYDzIwMjYwODI5MTUxOTEzWjADAgEBoF2kWzBZMQsw
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
# BDEyBDDHIypPZrAe5eXGpJJUYxKLTIaEIRsZQ9JvPlqzCn1vKad9Sk7LGsS9XCXl
# JcFfL10wgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGAqCpBEEUzIMO6rNVayQ4loNIvlqy6IofbgVXIWvdH5bZl
# CkF3zHDArU4U31eG7ijtQ9fDU2GAfTUZKe9uuZ02sKxVDUAQxsoHatgBYSITsX9u
# oUL8F+XiyVB7Xi/XF+CaytwSWTRA905gq8qOA49jGIipd00IpOUAcuoyYZVEEY2q
# /+u0DXyM8+8CDd/+fdahQgKKp8uBoMj2y16AioA/YJ+BMKgtrhgxMh2+nP3zIzXS
# xheqJBe0op/U4kbrqPbaUhqZPj1MhNy/S2+WDWFz0S16SCyUjVgkD2KIrxnvxb4B
# qeZDlJvvNkZsjctE4XH0kVwEdP5J+Jw7EysMGCDsy3lacR9J78G3MRA1AYg3Edhm
# 95eR2zKuTcq5TWNmEjeRA9eMa5dFQXQ0zSpyJ9JMmZrlrSU1W7JMrD8KW0KajhAI
# rGzrDNDoU9OJBV+jcMPSqC+54b6pN2ZJPllwMllGQ3grSe0H8eiamLXOmwnaqZEF
# zJFsGuB80rOyoNRIXpDu
# SIG # End signature block
