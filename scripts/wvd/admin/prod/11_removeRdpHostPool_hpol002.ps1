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
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\prod\11_removeRdpHostPool_hpol002-$($AlyaTimeString).log" | Out-Null

# Constants
$ErrorActionPreference = "Stop"
$HostPoolName = "$($AlyaNamingPrefix)hpol002"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"
$ResourceGroupName = "$($AlyaNamingPrefix)resg052"

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
Write-Host "WVD | 11_removeRdpHostPool_hpol002 | AZURE" -ForegroundColor $CommandInfo
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

# Getting members
Write-Host "Getting members" -ForegroundColor $CommandInfo
$RootDir = "$AlyaRoot\scripts\wvd\admin\prod"

# Removing hostpool
try
{
    & "$RootDir\33_removeAllSessions.ps1" -HostPoolName $HostPoolName
} catch {
    Write-Error $_.Exception.Message
}
try
{
    & "$RootDir\30_removeAppGroups.ps1" -HostPoolName $HostPoolName
} catch {
    Write-Error $_.Exception.Message
}
try
{
    & "$RootDir\31_removeSessionHosts.ps1" -HostPoolName $HostPoolName
} catch {
    Write-Error $_.Exception.Message
}
Write-Host "Removing hostpool '$($HostPoolName)'" -ForegroundColor $CommandInfo
try
{
    Remove-RdsHostPool -TenantName $AlyaWvdTenantNameProd -Name $HostPoolName
} catch {
    Write-Error $_.Exception.Message
}

$pool = Get-RdsHostPool -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -ErrorAction SilentlyContinue
if ($pool)
{
    Write-Error "Not able to remove the host pool"
    exit
}

# Checking locks on resource group
Write-Host "Checking locks on resource group '$($ResourceGroupName)'" -ForegroundColor $CommandInfo
$actLocks = Get-AzResourceLock -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
foreach($actLock in $actLocks)
{
    if ($actLock.Properties.level -eq "CanNotDelete")
    {
        Write-Host "Removing lock $($actLock.Name)"
        $tmp = $actLock | Remove-AzResourceLock -Force
    }
}

# Cleaning ressource group
Write-Host "Cleaning ressource group" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if ($ResGrp)
{
    $vms = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType "Microsoft.Compute/virtualMachines"
    foreach($vm in $vms)
    {
        Remove-AzResource -ResourceId $vm.ResourceId -Force
    }
    $lbs = Get-AzResource -ResourceGroupName $ResourceGroupName -ResourceType "Microsoft.Network/loadBalancers"
    foreach($lb in $lbs)
    {
        Remove-AzResource -ResourceId $lb.ResourceId -Force
    }
    $others = Get-AzResource -ResourceGroupName $ResourceGroupName
    foreach($other in $others)
    {
        if ($other.ResourceType -ne "Microsoft.Network/publicIPAddresses")
        {
            Remove-AzResource -ResourceId $other.ResourceId -Force
        }
    }
    <#
    Write-Warning -Message "Deleting ressource group $ResourceGroupName"
    Remove-AzResourceGroup -Name $ResourceGroupName -Force
    while ($ResGrp)
    {
        $ResGrp = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 60
    }
    Write-Warning -Message "Ressource group successfully deleted"
    #>
}

#Stopping Transscript
Stop-Transcript