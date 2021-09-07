#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2020-2021

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
    12.03.2020 Konrad Brunner       Initial Version
    10.10.2020 Konrad Brunner       Added parameters and generalized

#>

[CmdletBinding()]
Param(
    [string]$HostPoolName,
    [string]$AppGroupName,
    [string]$AdGroupName
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\fall2019test\15_createOrUpdateAppGroupsRdp-$($AlyaTimeString).log" | Out-Null

# Constants
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
Write-Host "WVD | 15_createOrUpdateAppGroupsRdp | AZURE" -ForegroundColor $CommandInfo
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
$AzureAdApplication = Get-AzADApplication -DisplayName $AlyaWvdServicePrincipalNameProd -ErrorAction SilentlyContinue
if (-Not $AzureAdApplication)
{
    throw "Azure AD Application not found. Please create the Azure AD Application $AlyaWvdServicePrincipalNameProd"
}
$AzureAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $AlyaWvdServicePrincipalNameProd

# Checking azure key vault secret
Write-Host "Checking azure key vault secret" -ForegroundColor $CommandInfo
$AlyaWvdServicePrincipalAssetName = "$($AlyaWvdServicePrincipalNameProd)Key"
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
	$rdsCreds = New-Object System.Management.Automation.PSCredential($AzureAdServicePrincipal.ApplicationId, $AlyaWvdServicePrincipalPasswordSave)
	$Global:RdsContext = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $rdsCreds -ServicePrincipal -AadTenantId $AlyaTenantId
	#LoginTo-Wvd -AppId $AzureAdServicePrincipal.ApplicationId -SecPwd $AlyaWvdServicePrincipalPasswordSave
}

# Main
Write-Host "Updating App group $($AppGroupName)" -ForegroundColor $CommandInfo
$appGrp = Get-RdsAppGroup -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -Name $AppGroupName -ErrorAction SilentlyContinue
$grpUsers = Get-RdsAppGroupUser $AlyaWvdTenantNameProd $HostPoolName $AppGroupName
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
        Add-RdsAppGroupUser $AlyaWvdTenantNameProd $HostPoolName $AppGroupName -UserPrincipalName $admin
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
        Add-RdsAppGroupUser $AlyaWvdTenantNameProd $HostPoolName $AppGroupName -UserPrincipalName $memb.UserPrincipalName
    }
}
foreach ($grpUser in $grpUsers)
{
    $memb = $allMembs | where { $_ -eq $grpUser.UserPrincipalName }
    if (-Not $memb)
    {
        Write-Host " - Removing user $($grpUser.UserPrincipalName)"
        Remove-RdsAppGroupUser $AlyaWvdTenantNameProd $HostPoolName $AppGroupName -UserPrincipalName $grpUser.UserPrincipalName
    }
}

#Stopping Transscript
Stop-Transcript
