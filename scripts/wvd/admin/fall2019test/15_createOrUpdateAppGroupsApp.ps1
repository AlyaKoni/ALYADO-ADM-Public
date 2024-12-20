﻿#Requires -Version 2.0

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
    12.03.2020 Konrad Brunner       Initial Version
    10.10.2020 Konrad Brunner       Added parameters and generalized

#>

[CmdletBinding()]
Param(
    $HostPoolName,
    $appDefs,
    $appsToGroup,
    $availableIcons
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\fall2019test\15_createOrUpdateAppGroupsApp-$($AlyaTimeString).log" | Out-Null

# Constants
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"
$AppGroupNameToDelete = "Desktop Application Group"
$BasePath = "C:\$($AlyaCompanyName)\WvdIcons"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.KeyVault"
Install-ModuleIfNotInstalled "Microsoft.RDInfra.RDPowershell"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionNameTest

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | 15_createOrUpdateAppGroupsApp | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
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

# Deleting app group
Write-Host "Deleting app group $AppGroupNameToDelete" -ForegroundColor $CommandInfo
$appToDelete = Get-RdsAppGroup -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName | Where-Object { $_.AppGroupName -eq $AppGroupNameToDelete }
if ($appToDelete)
{
    Remove-RdsAppGroup -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -Name $AppGroupNameToDelete
}

# Building app groups
Write-Host "Building app groups" -ForegroundColor $CommandInfo
foreach($appGrp in $appsToGroup)
{
    $appGrpName = $appGrp[0]
    Write-Host "App group $($appGrpName)"
    $appsFromGrp = $appGrp[1]
    $accessToGrp = $appGrp[2]
    $appGrp = Get-RdsAppGroup -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -Name $appGrpName -ErrorAction SilentlyContinue
    if (-Not $appGrp)
    {
        Write-Host " - Adding app group $($appGrpName)"
        $appGrp = New-RdsAppGroup -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -Name $appGrpName
    }
    $appGrpApps = Get-RdsRemoteApp -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -AppGroupName $appGrpName
    foreach ($appName in $appsFromGrp)
    {
        $existApp = $appGrpApps | Where-Object { $_.RemoteAppName -eq $appName }
        if (-Not $existApp)
        {
            Write-Host " - Adding app $($appName)"
            $wasDefinedApp = $false
            foreach ($appDef in $appDefs)
            {
                if ($appDef[0] -eq $appName)
                {
                    $wasDefinedApp = $true
                    $params = $appDef[1]
                    if ($params[1] -ne $null -and $params[1].Length -gt 0)
                    {
                        New-RdsRemoteApp -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -AppGroupName $appGrpName -Name $appName -FilePath $params[0] -RequiredCommandLine $params[1] -CommandLineSetting Require -IconPath $params[2] -IconIndex $params[3]
                    }
                    else
                    {
                        New-RdsRemoteApp -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -AppGroupName $appGrpName -Name $appName -FilePath $params[0] -IconPath $params[2] -IconIndex $params[3]
                    }
                    break
                }
            }
            if (-Not $wasDefinedApp)
            {
                $iconPath = $BasePath + "\" + $appName + ".Ico"
                if ($availableIcons -contains $appName)
                {
                    New-RdsRemoteApp -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -AppGroupName $appGrpName -AppAlias $appName -Name $appName -IconPath $iconPath -IconIndex 0
                }
                else
                {
                    New-RdsRemoteApp -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -AppGroupName $appGrpName -AppAlias $appName -Name $appName
                }
            }
        }
    }
    $appGrpApps = Get-RdsRemoteApp -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -AppGroupName $appGrpName
    foreach ($existApp in $appGrpApps)
    {
        $missingApp = $appsFromGrp | Where-Object { $_ -eq $existApp.RemoteAppName }
        if (-Not $missingApp)
        {
            Write-Host " - Removing app $($existApp.RemoteAppName)"
            Remove-RdsRemoteApp -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -AppGroupName $appGrpName -Name $existApp.RemoteAppName
        }
    }
    $grpUsers = Get-RdsAppGroupUser $AlyaWvdTenantNameTest $HostPoolName $appGrpName
    $allMembs = @()
    Write-Host " - Access for admins"
    foreach ($admin in $AlyaWvdAdmins)
    {
        if (-Not $allMembs.Contains($admin))
        {
            $allMembs += $admin
        }
        $grpUser = $grpUsers | Where-Object { $_.UserPrincipalName -eq $admin }
        if (-Not $grpUser)
        {
            Write-Host "   - Adding user $($admin)"
            Add-RdsAppGroupUser $AlyaWvdTenantNameTest $HostPoolName $appGrpName -UserPrincipalName $admin
        }
    }
    foreach ($accessGrp in $accessToGrp)
    {
        Write-Host " - Access for $($accessGrp)"
        $grp = Get-AzADGroup -SearchString $accessGrp | Select-Object -First 1
        $membs = Get-AzADGroupMember -GroupObject $grp
        foreach ($memb in $membs)
        {
            if (-Not $allMembs.Contains($memb.UserPrincipalName))
            {
                $allMembs += $memb.UserPrincipalName
            }
            $grpUser = $grpUsers | Where-Object { $_.UserPrincipalName -eq $memb.UserPrincipalName }
            if (-Not $grpUser)
            {
                Write-Host "   - Adding user $($memb.UserPrincipalName)"
                Add-RdsAppGroupUser $AlyaWvdTenantNameTest $HostPoolName $appGrpName -UserPrincipalName $memb.UserPrincipalName
            }
        }
    }
    foreach ($grpUser in $grpUsers)
    {
        $memb = $allMembs | Where-Object { $_ -eq $grpUser.UserPrincipalName }
        if (-Not $memb)
        {
            Write-Host " - Removing user $($grpUser.UserPrincipalName)"
            Remove-RdsAppGroupUser $AlyaWvdTenantNameTest $HostPoolName $appGrpName -UserPrincipalName $grpUser.UserPrincipalName
        }
    }
}


#Get-RdsStartMenuApp -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -AppGroupName "Desktop Application Group" | Select-Object AppAlias
#(Get-RdsRemoteApp -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -AppGroupName "Standard Apps").FriendlyName
#Remove-RdsRemoteApp -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -AppGroupName "Standard Apps" -Name "DynamicsCRM"
#Get-RdsRemoteApp -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -AppGroupName "Standard Apps" -Name "Quorum"
#Set-RdsRemoteApp -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -AppGroupName "Standard Apps" -Name "Explorer" -CommandLineSetting Allow
#Set-RdsRemoteApp -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -AppGroupName "Standard Apps" -Name "Explorer" -IconPath "C:\SSV\WvdIcons\Explorer.Ico" -IconIndex 0


#Stopping Transscript
Stop-Transcript
