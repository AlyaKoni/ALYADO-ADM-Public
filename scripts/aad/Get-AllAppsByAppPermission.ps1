#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2021

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
    23.08.2021 Konrad Brunner       Initial Version


    Source from: https://github.com/microsoft/AzureADGraphApps/blob/main/Get-AzureADGraphApps.ps1

#>

[CmdletBinding()]
Param(
    [string]$permissionAppId = "00000002-0000-0000-c000-000000000000" #Azure Active Directory Graph API
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Get-AllAppsByAppPermission-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "AzureAdPreview"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Get-AllAppsByAppPermission | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# An in-memory cache of objects by {object ID} andy by {object class, object ID} 
$script:ObjectByObjectId = @{}
$script:ObjectByObjectClassId = @{}

# An in-memory cache of found non MS apps 
$script:NonMSAppsDelegated = @{}
$script:NonMSAppsApplication = @{}

# Function to add an object to the cache
function CacheObject($Object) {
    if ($Object) {
        if (-not $script:ObjectByObjectClassId.ContainsKey($Object.ObjectType)) {
            $script:ObjectByObjectClassId[$Object.ObjectType] = @{}
        }
        $script:ObjectByObjectClassId[$Object.ObjectType][$Object.ObjectId] = $Object
        $script:ObjectByObjectId[$Object.ObjectId] = $Object
    }
}

# Function to retrieve an object from the cache (if it's there), or from Azure AD (if not).
function GetObjectByObjectId($ObjectId) {
    if (-not $script:ObjectByObjectId.ContainsKey($ObjectId)) {
        Write-Verbose ("Querying Azure AD for object '{0}'" -f $ObjectId)
        try {
            $object = Get-AzureADObjectByObjectId -ObjectId $ObjectId
            CacheObject -Object $object
        } catch { 
            Write-Verbose "Object not found."
        }
    }
    return $script:ObjectByObjectId[$ObjectId]
}
   
# Get all ServicePrincipal objects and add to the cache
Write-Host "Retrieving Service Principal objects. Please wait..." -ForegroundColor $CommandInfo
$servicePrincipals = Get-AzureADServicePrincipal -All $true 
    
$Oauth2PermGrants = @()

$count = 0
foreach ($sp in $servicePrincipals)
{
    CacheObject -Object $sp
    $spPermGrants = Get-AzureADServicePrincipalOAuth2PermissionGrant -ObjectId $sp.ObjectId -All $true
    $Oauth2PermGrants += $spPermGrants
    $count++
    Write-Host "Service Principal $($sp.ObjectId)"

    if($sp.AppId -eq $permissionAppId)
    {
        $aadAppSp = $sp
    }
}  

# Get all existing OAuth2 permission grants, get the client, resource and scope details
Write-Host "Checking Delegated Permission Grants..." -ForegroundColor $CommandInfo
foreach ($grant in $Oauth2PermGrants)
{
    if ($grant.ResourceId -eq $aadAppSp.ObjectId -and $grant.Scope) 
    {
        $grant.Scope.Split(" ") | Where-Object { $_ } | ForEach-Object {
            $scope = $_
            $client = GetObjectByObjectId -ObjectId $grant.ClientId
            $ownerUPN = (Get-AzureADServicePrincipalOwner -ObjectId $client.ObjectId -Top 1).UserPrincipalName

            Write-Host "Checking Delegate Permissions - $($client.DisplayName)"

            # Determine if the object comes from the Microsoft Services tenant, and flag it if true
            $MicrosoftRegisteredClientApp = $false
            if ($client.AppOwnerTenantId -eq "f8cdef31-a31e-4b4a-93e4-5f571e91255a" -or $client.AppOwnerTenantId -eq "72f988bf-86f1-41af-91ab-2d7cd011db47") {
                $MicrosoftRegisteredClientApp = $true
            }

            $resource = GetObjectByObjectId -ObjectId $grant.ResourceId

            if ($grant.ConsentType -eq "AllPrincipals") {
                $simplifiedgranttype = "Delegated-AllPrincipals"
            } elseif ($grant.ConsentType -eq "Principal") {
                $simplifiedgranttype = "Delegated-Principal"
            }

            $app = New-Object PSObject -Property ([ordered]@{
                "ObjectId" = $grant.ClientId
                "DisplayName" = $client.DisplayName
                "ApplicationId" = $client.AppId
                "PermissionType" = $simplifiedgranttype
                "Resource" = $resource.DisplayName
                "Permission" = $scope
                "MicrosoftApp" = $MicrosoftRegisteredClientApp
                "Owner" = $ownerUPN
            })
            $app

            if (-Not $MicrosoftRegisteredClientApp)
            {
                $id = $client.AppId+"|"+$grant.ClientId
                $script:NonMSAppsDelegated[$id] = $app
            }
        }
    }
}
    
# Iterate over all ServicePrincipal objects and get app permissions
Write-Host "Getting Application Permission Grants..." -ForegroundColor $CommandInfo
$script:ObjectByObjectClassId['ServicePrincipal'].GetEnumerator() | ForEach-Object {
    $sp = $_.Value
    Write-Host "Checking Application Permissions - $($sp.DisplayName)"

    Get-AzureADServiceAppRoleAssignedTo -ObjectId $sp.ObjectId  -All $true `
    | Where-Object { $_.PrincipalType -eq "ServicePrincipal" -and $_.ResourceId -eq $aadAppSp.ObjectId} | ForEach-Object {
        $assignment = $_
            
        $client = GetObjectByObjectId -ObjectId $assignment.PrincipalId
            
        $ownerUPN = (Get-AzureADServicePrincipalOwner -ObjectId $client.ObjectId -Top 1).UserPrincipalName
        # Determine if the object comes from the Microsoft Services tenant, and flag it if true
        $MicrosoftRegisteredClientApp = $false
        if ($client.AppOwnerTenantId -eq "f8cdef31-a31e-4b4a-93e4-5f571e91255a" -or $client.AppOwnerTenantId -eq "72f988bf-86f1-41af-91ab-2d7cd011db47") {
            $MicrosoftRegisteredClientApp = $true
        }

        $resource = GetObjectByObjectId -ObjectId $assignment.ResourceId            
        $appRole = $resource.AppRoles | Where-Object { $_.Id -eq $assignment.Id }

        $app = New-Object PSObject -Property ([ordered]@{
            "ObjectId" = $assignment.PrincipalId
            "DisplayName" = $client.DisplayName
            "ApplicationId" = $client.AppId
            "PermissionType" = "Application"
            "Resource" = $resource.DisplayName
            "Permission" = $appRole.Value
            "MicrosoftApp" = $MicrosoftRegisteredClientApp
            "Owner" = $ownerUPN
        })
        $app

        if (-Not $MicrosoftRegisteredClientApp)
        {
            $id = $client.AppId+"|"+$grant.ClientId
            $script:NonMSAppsApplication[$id] = $app
        }
    }
}

Write-Host "Non Microsoft Apps with Delegated Permission Grants..." -ForegroundColor $CommandInfo
$script:NonMSAppsDelegated.Values.DisplayName
$script:NonMSAppsDelegated.Values

Write-Host "Non Microsoft Apps with Application Permission Grants..." -ForegroundColor $CommandInfo
$script:NonMSAppsApplication.Values.DisplayName
$script:NonMSAppsApplication.Values

#Stopping Transscript
Stop-Transcript