#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2023

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
    13.03.2020 Konrad Brunner       Initial Version
    10.10.2020 Konrad Brunner       Added parameters and generalized

#>

[CmdletBinding()]
Param(
    [string]$HostPoolName,
    [string]$ResourceGroupName
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\fall2019test\10_removeHostPool-$($AlyaTimeString).log" | Out-Null

# Constants
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
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | 10_removeHostPool | AZURE" -ForegroundColor $CommandInfo
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

# Getting members
Write-Host "Getting members" -ForegroundColor $CommandInfo
$RootDir = "$AlyaScripts\wvd\admin\fall2019test"

# Removing hostpool
try
{
    & "$RootDir\33_removeAllSessions.ps1" -HostPoolName $HostPoolName
} catch {
    try { Write-Error ($_.Exception | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}
	Write-Error ($_.Exception) -ErrorAction Continue
}
try
{
    & "$RootDir\30_removeAppGroups.ps1" -HostPoolName $HostPoolName
} catch {
    try { Write-Error ($_.Exception | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}
	Write-Error ($_.Exception) -ErrorAction Continue
}
try
{
    & "$RootDir\31_removeSessionHosts.ps1" -HostPoolName $HostPoolName
} catch {
    try { Write-Error ($_.Exception | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}
	Write-Error ($_.Exception) -ErrorAction Continue
}
Write-Host "Removing hostpool '$($HostPoolName)'" -ForegroundColor $CommandInfo
try
{
    Remove-RdsHostPool -TenantName $AlyaWvdTenantNameTest -Name $HostPoolName
} catch {
    try { Write-Error ($_.Exception | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}
	Write-Error ($_.Exception) -ErrorAction Continue
}

$pool = Get-RdsHostPool -TenantName $AlyaWvdTenantNameTest -HostPoolName $HostPoolName -ErrorAction SilentlyContinue
if ($pool)
{
    Write-Error "Not able to remove the host pool" -ErrorAction Continue
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
        $null = $actLock | Remove-AzResourceLock -Force
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
    Write-Warning "Deleting ressource group $ResourceGroupName"
    Remove-AzResourceGroup -Name $ResourceGroupName -Force
    while ($ResGrp)
    {
        $ResGrp = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 60
    }
    Write-Warning "Ressource group successfully deleted"
    #>
}

#Stopping Transscript
Stop-Transcript
