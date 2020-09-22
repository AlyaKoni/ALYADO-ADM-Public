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
    02.04.2020 Konrad Brunner       Initial Version

#>

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\test\40_listRds-$($AlyaTimeString).log" | Out-Null

# Constants
$ErrorActionPreference = "Stop"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "Microsoft.RDInfra.RDPowershell"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# WVD stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | 40_listRds | WVD" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

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

#Main
Write-Host "Listing WVD tenant" -ForegroundColor $CommandInfo
Write-Host "* Tenant: $($AlyaWvdTenantNameTest)"
    
Write-Host " + Role assigments"
$roleAsss = Get-RdsRoleAssignment -TenantGroupName $AlyaWvdTenantGroupName -TenantName $AlyaWvdTenantNameTest
foreach ($roleAss in $roleAsss)
{
    Write-Host "   - $($roleAss.SignInName)$($roleAss.AppId): $($roleAss.RoleDefinitionName)"
}
$hpools = Get-RdsHostPool -TenantName $AlyaWvdTenantNameTest
foreach ($hpool in $hpools)
{
    Write-Host " + HostPool: $($hpool.HostPoolName)"
    Write-Host "   - ValidationEnv: $($hpool.ValidationEnv)"
    Write-Host "   - LoadBalancerType: $($hpool.LoadBalancerType)"
    Write-Host "   - MaxSessionLimit: $($hpool.MaxSessionLimit)"
    $appGrps = Get-RdsAppGroup -TenantName $AlyaWvdTenantNameTest -HostPoolName $hpool.HostPoolName
    foreach ($appGrp in $appGrps)
    {
        Write-Host "   # AppGroup: $($appGrp.AppGroupName)"
        if ($appGrp.AppGroupName -ne "Desktop Application Group") 
        {
            $appGrpApps = Get-RdsRemoteApp -TenantName $AlyaWvdTenantNameTest -HostPoolName $hpool.HostPoolName -AppGroupName $appGrp.AppGroupName
            foreach ($app in $appGrpApps)
            {
                Write-Host "     - App $($app.RemoteAppName)"
            }
        }
        Write-Host "     - User assigments"
        $grpUsers = Get-RdsAppGroupUser -TenantName $AlyaWvdTenantNameTest -HostPoolName $hpool.HostPoolName -AppGroupName $appGrp.AppGroupName
        foreach ($grpUser in $grpUsers)
        {
            Write-Host "       > $($grpUser.UserPrincipalName)"
        }
    }
    Write-Host "   - Hosts"
    $hosts = Get-RdsSessionHost -TenantName $AlyaWvdTenantNameTest -HostPoolName $hpool.HostPoolName
    foreach ($hosti in $hosts)
    {
        Write-Host "     - $($hosti.SessionHostName) AllowNew:$($hosti.AllowNewSession) Status:$($hosti.Status) LastHeartBeat:$($hosti.LastHeartBeat)" -ForegroundColor $CommandSuccess
        Write-Host "       Agents: AgentVersion: $($hosti.AgentVersion) SxSStackVersion:$($hosti.SxSStackVersion)"
        Write-Host "       Update: UpdateState: $($hosti.UpdateState) LastUpdateTime:$($hosti.LastUpdateTime) UpdateErrorMessage:$($hosti.UpdateErrorMessage)"
    }
    Write-Host "   - Sessions"
    $sessns = Get-RdsUserSession -TenantName $AlyaWvdTenantNameTest -HostPoolName $hpool.HostPoolName
    foreach ($sessn in $sessns)
    {
        Write-Host "     - $($sessn.SessionState) $($sessn.AdUserName) on $($sessn.SessionHostName)"
    }
}

#Get-RdsRoleAssignment -TenantGroupName "Default Tenant Group" -TenantName "ALYA-Test"

#Stopping Transscript
Stop-Transcript
