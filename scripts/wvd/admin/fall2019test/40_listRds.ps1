#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2024

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
    02.04.2020 Konrad Brunner       Initial Version

#>

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\fall2019test\40_listRds-$($AlyaTimeString).log" | Out-Null

# Constants
$ErrorActionPreference = "Stop"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.KeyVault"
Install-ModuleIfNotInstalled "Microsoft.RDInfra.RDPowershell"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionNameTest

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
$AlyaWvdServicePrincipalPasswordSave = $AzureKeyVaultSecret.SecretValue
Clear-Variable -Name AlyaWvdServicePrincipalPassword -Force -ErrorAction SilentlyContinue
Clear-Variable -Name AzureKeyVaultSecret -Force -ErrorAction SilentlyContinue

# Login to WVD
if (-Not $Global:RdsContext)
{
	Write-Host "Logging in to wvd" -ForegroundColor $CommandInfo
	$rdsCreds = New-Object System.Management.Automation.PSCredential($AzureAdServicePrincipal.AppId, $AlyaWvdServicePrincipalPasswordSave)
	$Global:RdsContext = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $rdsCreds -ServicePrincipal -AadTenantId $AlyaTenantId
	#LoginTo-Wvd -AppId $AzureAdServicePrincipal.AppId -SecPwd $AlyaWvdServicePrincipalPasswordSave
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
