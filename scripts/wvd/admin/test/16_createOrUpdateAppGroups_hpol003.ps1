#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

    This unpublished material is proprietary to Alya Consulting.
    All rights reserved. The methods and techniques described
    herein are considered trade secrets and/or confidential. 
    Reproduction or distribution, in whole or in part, is 
    forbidden except by express written permission of Alya Consulting.

    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    12.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\test\16_createOrUpdateAppGroups_hpol003-$($AlyaTimeString).log" | Out-Null

# Constants
$HostPoolName = "$($AlyaNamingPrefixTest)hpol003"
$AppGroupName = "Desktop Application Group"
$AdGroupName = "ALYASG-ADM-APPTDSKTP"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "Microsoft.RDInfra.RDPowershell"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | 11_createOrUpdateAppGroups_hpol001 | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error -Message "Can't get Az context! Not logged in?"
    Exit 1
}

# Checking application
Write-Host "Checking application" -ForegroundColor $CommandInfo
$AzureAdApplication = Get-AzADApplication -DisplayName $AlyaWvdServicePrincipalNameTest -ErrorAction SilentlyContinue
if (-Not $AzureAdApplication)
{
    throw "Azure AD Application not found. Please create the Azure AD Application $AlyaWvdServicePrincipalNameTest"
}
$AzureAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $AlyaWvdServicePrincipalNameTest

# Checking azure key vault secret
Write-Host "Checking azure key vault secret" -ForegroundColor $CommandInfo
$AlyaWvdServicePrincipalAssetName = "$($AlyaWvdServicePrincipalNameTest)Key"
$AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $AlyaWvdServicePrincipalAssetName -ErrorAction SilentlyContinue
if (-Not $AzureKeyVaultSecret)
{
    throw "Key Vault secret not found. Please create the secret $AlyaWvdServicePrincipalAssetName"
}
$AlyaWvdServicePrincipalPassword = $AzureKeyVaultSecret.SecretValueText
$AlyaWvdServicePrincipalPasswordSave = ConvertTo-SecureString $AlyaWvdServicePrincipalPassword -AsPlainText -Force

# Login to WVD
if (-Not $Global:RdsContext)
{
	Write-Host "Logging in to wvd" -ForegroundColor $CommandInfo
	$rdsCreds = New-Object System.Management.Automation.PSCredential($AzureAdServicePrincipal.ApplicationId, $AlyaWvdServicePrincipalPasswordSave)
	$Global:RdsContext = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $rdsCreds -ServicePrincipal -AadTenantId $AlyaTenantId
	#LoginTo-Wvd -AppId $AzureAdServicePrincipal.ApplicationId -SecPwd $AlyaWvdServicePrincipalPasswordSave
}

# Main
Write-Host "Updating App group $($AppGroupName)" -ForegroundColor $CommandInfo
$appGrp = Get-RdsAppGroup -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -Name $AppGroupName -ErrorAction SilentlyContinue
$grpUsers = Get-RdsAppGroupUser $AlyaWvdTenantNameTest $HostPoolName $AppGroupName
$allMembs = @()
foreach ($admin in $AlyaWvdAdmins)
{
    if (-Not $allMembs.Contains($admin))
    {
        $allMembs += $admin
    }
    $grpUser = $grpUsers | where { $_.UserPrincipalName -eq $admin }
    if (-Not $grpUser)
    {
        Write-Host "   - Adding user $($admin)"
        Add-RdsAppGroupUser $AlyaWvdTenantNameTest $HostPoolName $AppGroupName -UserPrincipalName $admin
    }
}
Write-Host " - Access for $($AdGroupName)"
$grp = Get-AzADGroup -SearchString $AdGroupName | Select-Object -First 1
$membs = Get-AzADGroupMember -GroupObject $grp
foreach ($memb in $membs)
{
    if (-Not $allMembs.Contains($memb.UserPrincipalName))
    {
        $allMembs += $memb.UserPrincipalName
    }
    $grpUser = $grpUsers | where { $_.UserPrincipalName -eq $memb.UserPrincipalName }
    if (-Not $grpUser)
    {
        Write-Host "   - Adding user $($memb.UserPrincipalName)"
        Add-RdsAppGroupUser $AlyaWvdTenantNameTest $HostPoolName $AppGroupName -UserPrincipalName $memb.UserPrincipalName
    }
}
foreach ($grpUser in $grpUsers)
{
    $memb = $allMembs | where { $_ -eq $grpUser.UserPrincipalName }
    if (-Not $memb)
    {
        Write-Host " - Removing user $($grpUser.UserPrincipalName)"
        Remove-RdsAppGroupUser $AlyaWvdTenantNameTest $HostPoolName $AppGroupName -UserPrincipalName $grpUser.UserPrincipalName
    }
}

#Stopping Transscript
Stop-Transcript
