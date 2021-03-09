#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

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
    27.02.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\tenant\Set-ConditionalAccessPolicies-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"
$CompName = Make-PascalCase($AlyaCompanyNameShort)
$ConditionalAccessAppName = "$($CompName)ConditionalAccessApp"
$ExternalGroupsToExclude = $AlyaMfaDisabledForGroups

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "AzureAdPreview"
Install-ModuleIfNotInstalled "MSOnline"
    
# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad
LoginTo-Msol

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Tenant | Set-ConditionalAccessPolicies | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking ressource group
Write-Host "Checking ressource group" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    Write-Warning "Ressource Group not found. Creating the Ressource Group $ResourceGroupName"
    $ResGrp = New-AzResourceGroup -Name $ResourceGroupName -Location $AlyaLocation -Tag @{displayName="Main Infrastructure Services";ownerEmail=$Context.Account.Id}
}

# Checking key vault
Write-Host "Checking key vault" -ForegroundColor $CommandInfo
$KeyVault = Get-AzKeyVault -ResourceGroupName $ResourceGroupName -VaultName $KeyVaultName -ErrorAction SilentlyContinue
if (-Not $KeyVault)
{
    Write-Warning "Key Vault not found. Creating the Key Vault $KeyVaultName"
    $KeyVault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $ResourceGroupName -Location $AlyaLocation -Sku Standard -Tag @{displayName="Main Infrastructure Keyvault"}
    if (-Not $KeyVault)
    {
        Write-Error "Key Vault $KeyVaultName creation failed. Please fix and start over again" -ErrorAction Continue
        Exit 1
    }
}

# Checking application
Write-Host "Checking application" -ForegroundColor $CommandInfo
$AzureAdApplication = Get-AzADApplication -DisplayName $ConditionalAccessAppName -ErrorAction SilentlyContinue
if (-Not $AzureAdApplication)
{
    Write-Warning "Azure AD Application not found. Creating the Azure AD Application $ConditionalAccessAppName"

    #Creating application and service principal
    $KeyId = [Guid]::NewGuid()
    $HomePageUrl = "https://portal.azure.com/#blade/Microsoft_AAD_IAM/ConditionalAccessBlade"
    $AzureAdApplication = New-AzADApplication -DisplayName $ConditionalAccessAppName -HomePage $HomePageUrl -ReplyUrls "https://login.microsoftonline.com/common/oauth2/nativeclient" -IdentifierUris ("http://" + $KeyId)
    $AzureAdServicePrincipal = New-AzADServicePrincipal -ApplicationId $AzureAdApplication.ApplicationId

    #Create credential 
    $startDate = Get-Date
    $endDate = $startDate.AddYears(99)
    $ConditionalAccessAppPassword = "$" + [Guid]::NewGuid().ToString() + "!"
    $ConditionalAccessAppPasswordSave = ConvertTo-SecureString $ConditionalAccessAppPassword -AsPlainText -Force
    $ConditionalAccessAppSecret = New-AzADAppCredential -ApplicationId $AzureAdApplication.ApplicationId -StartDate $startDate -EndDate $endDate -Password $ConditionalAccessAppPasswordSave

    #Granting permissions
    <#To check existing permissions
    LoginTo-Ad
    $AdAzureAdApplication = Get-AzureADApplication -Filter "AppId eq '$($AzureAdApplication.ApplicationId)'"
    $AdAzureAdApplication.RequiredResourceAccess
    ($AdAzureAdApplication.RequiredResourceAccess | where { $_.ResourceAppId -eq '00000003-0000-0000-c000-000000000000'}).ResourceAccess
    $AdAzureAdApplication.RequiredResourceAccess.ResourceAppId
    $AdAzureAdApplication.RequiredResourceAccess.ResourceAccess
    #>
    $AppPermissionGraph1 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "af2819c9-df71-4dd3-ade7-4d7c9dc653b7","Scope"
    $AppPermissionGraph2 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "06da0dbc-49e2-44d2-8312-53f166ab848a","Scope"
    $AppPermissionGraph3 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "572fea84-0151-49b2-9301-11cb16974376","Scope"
    $AppPermissionGraph4 = New-Object -TypeName "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList "ad902697-1014-4ef5-81ef-2b4301988e8c","Scope"
    $RequiredResourceAccessGraph = New-Object -TypeName "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
    $RequiredResourceAccessGraph.ResourceAppId = "00000003-0000-0000-c000-000000000000"
    $RequiredResourceAccessGraph.ResourceAccess = $AppPermissionGraph1, $AppPermissionGraph2, $AppPermissionGraph3, $AppPermissionGraph4

    Set-AzureADApplication -ObjectId $AzureAdApplication.ObjectId -RequiredResourceAccess $RequiredResourceAccessGraph
    $tmp = Get-AzureADApplication -ObjectId $AzureAdApplication.ObjectId
    while ($tmp.RequiredResourceAccess.Count -ne 1)
    {
        Start-Sleep -Seconds 10
        $tmp = Get-AzureADApplication -ObjectId $AdAzureAdApplication.ObjectId
    }
    Start-Sleep -Seconds 60 # Looks like there is some time issue for admin consent #TODO 60 seconds enough

    #Admin consent
    $apiToken = Get-AzAccessToken
    if (-Not $apiToken)
    {
        Write-Warning "Can't aquire an access token. Please give admin consent to application '$($ConditionalAccessAppName)' in the portal!"
        pause
    }
    else
    {
        $header = @{'Authorization'='Bearer '+$apiToken;'X-Requested-With'='XMLHttpRequest';'x-ms-client-request-id'=[guid]::NewGuid();'x-ms-correlation-id'=[guid]::NewGuid();}
        $url = "https://main.iam.ad.ext.azure.com/api/RegisteredApplications/$($AzureAdApplication.ApplicationId)/Consent?onBehalfOfAll=true"
        Invoke-RestMethod -Uri $url -Headers $header -Method POST -ErrorAction Stop
    }
}
else
{
    $AzureAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $ConditionalAccessAppName
}

# Checking azure key vault secret
Write-Host "Checking azure key vault secret" -ForegroundColor $CommandInfo
$ConditionalAccessAppAssetName = "$($CompName)ConditionalAccessAppKey"
$AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $ConditionalAccessAppAssetName -ErrorAction SilentlyContinue
if (-Not $AzureKeyVaultSecret)
{
    Write-Warning "Key Vault secret not found. Creating the secret $ConditionalAccessAppAssetName"
    if (-Not $ConditionalAccessAppPasswordSave)
    {
        $ConditionalAccessAppPasswordSave = Read-Host -Prompt "Please specify the $($ConditionalAccessAppAssetName) password" -AsSecureString
        $ConditionalAccessAppPassword = (New-Object PSCredential $ConditionalAccessAppAssetName,$ConditionalAccessAppPasswordSave).GetNetworkCredential().Password
    }
    $AzureKeyVaultSecret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $ConditionalAccessAppAssetName -SecretValue $ConditionalAccessAppPasswordSave
}
else
{
    $ConditionalAccessAppPassword = ($AzureKeyVaultSecret.SecretValue | foreach { [System.Net.NetworkCredential]::new("", $_).Password })
    $ConditionalAccessAppPasswordSave = ConvertTo-SecureString $ConditionalAccessAppPassword -AsPlainText -Force
}

# Getting graph access token
$AccessToken = Connect-MsGraphAsDelegated -ClientID $AzureAdServicePrincipal.ApplicationId -ClientSecret $ConditionalAccessAppPassword

# Checking no mfa group
Write-Host "Checking MFA exclude group" -ForegroundColor $CommandInfo
if (-Not $AlyaMfaDisabledGroupName)
{
    $NoMfaGroupName = Read-Host -Prompt "Please specify NoMfaGroupName (Hit return for SGNOMFA)"
    if ([string]::IsNullOrEmpty($NoMfaGroupName))
    {
        $NoMfaGroupName = "SGNOMFA"
    }
}
else
{
    $NoMfaGroupName = $AlyaMfaDisabledGroupName
}
$Uri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$NoMfaGroupName'"
$GrpRslt = Get-MsGraph -AccessToken $AccessToken -Uri $Uri
if ($GrpRslt.GetType().Name -eq "PSCustomObject")
{
    $ExcludeGroupId = $GrpRslt.id
}
else
{
    $ExcludeGroupId = ($GrpRslt | Where-Object { $_.displayName -eq $NoMfaGroupName }).id
}
if (-Not $ExcludeGroupId)
{
    Write-Warning "No MFA group not found. Creating the No MFA group $NoMfaGroupName"
    $NoMfaGroup = New-MsolGroup -DisplayName $NoMfaGroupName -Description "MFA is disabled for members in this group"
}

# Getting role assignments
Write-Host "Getting role assignments" -ForegroundColor $CommandInfo
$roleDefs = @{"Company Administrator"=$null;"Exchange Administrator"=$null;"Teams Administrator"=$null;"SharePoint Administrator"=$null;"Privileged Role Administrator"=$null}
$roleDefKeys = ($roleDefs.Clone()).Keys
$ExcludeRoleIds = ""
foreach($roleName in $roleDefKeys)
{
    $role = Get-MsolRole -RoleName $roleName
    $roleDefs[$roleName] = Get-MsolRoleMember -RoleObjectId $role.ObjectId
    $ExcludeRoleIds += "`"" + $role.ObjectId + "`","
}
$syncrole = Get-MsolRole -RoleName "Directory synchronization accounts"
$ExcludeRoleIds += "`"" + $syncrole.ObjectId + "`","
$ExcludeRoleIds = $ExcludeRoleIds.TrimEnd(",")

# Getting actual access policies
Write-Host "Getting actual access policies" -ForegroundColor $CommandInfo
$Uri = "https://graph.microsoft.com/beta/conditionalAccess/policies"
$ActPolicies = Get-MsGraph -AccessToken $AccessToken -Uri $Uri

# Checking access policies
#   with help from https://danielchronlund.com/2019/11/07/automatic-deployment-of-conditional-access-with-powershell-and-microsoft-graph/
Write-Host "Checking access policies" -ForegroundColor $CommandInfo
function Update-MfaPolicy
{
    param (
        [parameter(Mandatory = $true)]
        $RoleName,
        [parameter(Mandatory = $true)]
        $PolicyName
    )
    $MfaGlobalAdmin = $ActPolicies | where { $_.displayName -eq $PolicyName }
    $UserIds = ""
    foreach($user in $roleDefs[$RoleName])
    {
        $UserIds += "`"" + $user.ObjectId + "`","
    }
    $UserIds = $UserIds.TrimEnd(",")
    if (-Not $MfaGlobalAdmin)
    {
        Write-Warning "Conditional access policy not found. Creating the policy $PolicyName"
        if ($roleDefs[$RoleName].Count -eq 0)
        {
            Write-Warning "  - skipped! No users assigned to that role"
            continue
        }
        $ConditionalAccessPolicy = @"
        {
            "displayName": "$PolicyName",
            "state": "enabled",
            "conditions": {
                "users": {
                    "includeUsers": [
                        $UserIds
                    ],
                    "excludeGroups": [
                        "$ExcludeGroupId"
                    ]
                },
                "applications": {
                    "includeApplications": [
                        "All"
                    ]
                }
            },
            "grantControls": {
                "operator": "OR",
                "builtInControls": [
                    "mfa"
                ]
            }
        }
"@
        $Uri = 'https://graph.microsoft.com/beta/conditionalAccess/policies'
        Post-MsGraph -AccessToken $AccessToken -Uri $Uri -Body $ConditionalAccessPolicy
    }
    else
    {
        if ($MfaGlobalAdmin.state -eq "disabled")
        {
            Write-Warning "Conditional access policy is disabled. Enabling the policy $PolicyName"
            $ConditionalAccessPolicy = @"
            {
                "state": "enabled",
                "conditions": {
                    "users": {
                        "includeUsers": [
                            $UserIds
                        ]
                    }
                }
            }
"@
        }
        else
        {
            $ConditionalAccessPolicy = @"
            {
                "conditions": {
                    "users": {
                        "includeUsers": [
                            $UserIds
                        ]
                    }
                }
            }
"@
        }
        $Uri = 'https://graph.microsoft.com/beta/conditionalAccess/policies/{0}' -f $MfaGlobalAdmin.id
        Patch-MsGraph -AccessToken $AccessToken -Uri $Uri -Body $ConditionalAccessPolicy
    }
}

foreach($roleName in $roleDefKeys)
{
    Update-MfaPolicy -RoleName $roleName -PolicyName "MFA: Required for $roleName"
}

# Checking external groups to exclude
Write-Host "Checking external groups to exclude" -ForegroundColor $CommandInfo
$ExcludeGroupIds = ""
foreach($groupName in $ExternalGroupsToExclude)
{
    $Uri = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$groupName'"
    $GrpRslt = Get-MsGraph -AccessToken $AccessToken -Uri $Uri
    if ($GrpRslt.GetType().Name -eq "PSCustomObject")
    {
        $ExcludeGroupIds += "`"" + $GrpRslt.id + "`","
    }
    else
    {
        $ExcludeGroupIds += "`"" + ($GrpRslt | Where-Object { $_.displayName -eq $NoMfaGroupName }).id + "`","
    }
}
$ExcludeGroupIds += "`"" + $ExcludeGroupId + "`"," #NOMFAGroup
$ExcludeGroupIds = $ExcludeGroupIds.TrimEnd(",")

# Checking all users access policy
Write-Host "Checking all users access policy" -ForegroundColor $CommandInfo
$MfaAllUsers = $ActPolicies | where { $_.displayName -eq "MFA: Required for all users" }
if (-Not $MfaAllUsers)
{
    Write-Warning "Conditional access policy not found. Creating the policy MFA: Required for all users"
    $ConditionalAccessPolicy = @"
    {
        "displayName": "MFA: Required for all users",
        "state": "enabled",
        "conditions": {
            "users": {
                "includeUsers": [
                    "All"
                ],
                "excludeGroups": [
                    $ExcludeGroupIds
                ],
                "excludeRoles": [
                    $ExcludeRoleIds
                ]
            },
            "applications": {
                "includeApplications": [
                    "All"
                ]
            }
        },
        "grantControls": {
            "operator": "OR",
            "builtInControls": [
                "mfa"
            ]
        }
    }
"@
    $Uri = 'https://graph.microsoft.com/beta/conditionalAccess/policies'
    Post-MsGraph -AccessToken $AccessToken -Uri $Uri -Body $ConditionalAccessPolicy
}
else
{
    if ($MfaAllUsers.state -eq "disabled")
    {
        Write-Warning "Conditional access policy is disabled. Enabling the policy MFA: Required for all users"
        $ConditionalAccessPolicy = @"
        {
            "state": "enabled",
            "conditions": {
                "users": {
                    "includeUsers": [
                        "All"
                    ],
                    "excludeGroups": [
                        $ExcludeGroupIds
                    ],
                    "excludeRoles": [
                        $ExcludeRoleIds
                    ]
                }
            }
        }
"@
    }
    else
    {
        $ConditionalAccessPolicy = @"
        {
            "conditions": {
                "users": {
                    "includeUsers": [
                        "All"
                    ],
                    "excludeGroups": [
                        $ExcludeGroupIds
                    ],
                    "excludeRoles": [
                        $ExcludeRoleIds
                    ]
                }
            }
        }
"@
    }
    $Uri = 'https://graph.microsoft.com/beta/conditionalAccess/policies/{0}' -f $MfaAllUsers.id
    Patch-MsGraph -AccessToken $AccessToken -Uri $Uri -Body $ConditionalAccessPolicy
}

# Disabling security defaults
Write-Host "Disabling security defaults" -ForegroundColor $CommandInfo
Write-Host "You have now to disable the security defaults. Pleas browse to"
Write-Host "  https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Properties"
Write-Host "hit 'Manage Security defaults' at the bottom of the page and disable security defaults!"
Write-Host "Please select 'My organization is using Conditional Access'."
pause
start https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Properties

#Stopping Transscript
Stop-Transcript