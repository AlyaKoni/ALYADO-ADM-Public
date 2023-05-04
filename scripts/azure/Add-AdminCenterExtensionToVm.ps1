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
    09.08.2021 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    $ResourceGroupName,
    [Parameter(Mandatory=$true)]
    $VMName,
    [Parameter(Mandatory=$true)]
    $KeyVaultName,
    $WacPort = "6516"
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\Add-AdminCenterExtensionToVm-$($AlyaTimeString).log" -IncludeInvocationHeader -Force | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.KeyVault"
Install-ModuleIfNotInstalled "Az.Compute"
Install-ModuleIfNotInstalled "Az.Network"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Infrastructure | Add-AdminCenterExtensionToVm | AZURE" -ForegroundColor $CommandInfo
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
    throw "Ressource Group not found. Please create the Ressource Group $ResourceGroupName"
}

# Checking key vault
Write-Host "Checking key vault" -ForegroundColor $CommandInfo
$KeyVault = Get-AzKeyVault -ResourceGroupName $ResourceGroupName -VaultName $KeyVaultName -ErrorAction SilentlyContinue
if (-Not $KeyVault)
{
    Write-Warning "Key Vault not found. Creating the Key Vault $KeyVaultName"
    $KeyVault = New-AzKeyVault -VaultName $KeyVaultName -ResourceGroupName $ResourceGroupName -Location $AlyaLocation -Sku Standard
    if (-Not $KeyVault)
    {
        Write-Error "Key Vault $KeyVaultName creation failed. Please fix and start over again" -ErrorAction Continue
        Exit 1
    }
}

# Setting own key vault access
Write-Host "Setting own key vault access" -ForegroundColor $CommandInfo
$user = Get-AzAdUser -UserPrincipalName $Context.Account.Id
Set-AzKeyVaultAccessPolicy -VaultName $KeyVaultName -ObjectId $user.Id -PermissionsToCertificates "All" -PermissionsToSecrets "All" -PermissionsToKeys "All" -PermissionsToStorage "All"

# Checking azure key vault secret
Write-Host "Checking azure key vault secret" -ForegroundColor $CommandInfo
$VMCredentialAssetName = "$($VMName)WacSalt"
$AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $VMCredentialAssetName -ErrorAction SilentlyContinue
if (-Not $AzureKeyVaultSecret)
{
    Write-Warning "Key Vault secret not found. Creating the secret $VMCredentialAssetName"
    $WacSalt = "-" + [Guid]::NewGuid().ToString() + "-"
    $WacSaltSec = ConvertTo-SecureString $WacSalt -AsPlainText -Force
    $AzureKeyVaultSecret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $VMCredentialAssetName -SecretValue $WacSaltSec
}
else
{
    $WacSalt = ($AzureKeyVaultSecret.SecretValue | Foreach-Object { [System.Net.NetworkCredential]::new("", $_).Password })
}
Clear-Variable -Name AzureKeyVaultSecret -Force -ErrorAction SilentlyContinue

# Checking vm
Write-Host "Checking vm" -ForegroundColor $CommandInfo
$Vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -Status -ErrorAction SilentlyContinue
if (-Not $Vm)
{
    throw "VM not found. Please create the VM $VMName"
}
if (-Not ($VM.Statuses | Where-Object { $_.Code -eq "PowerState/running"}))
{
    Write-Warning "Starting VM $VMName"
    Start-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName
}

# Checking network security rules
Write-Host "Checking network security rules" -ForegroundColor $CommandInfo
$Vm = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName
foreach($netIface in $Vm.NetworkProfile.NetworkInterfaces)
{
    $netIfaceDef = Get-AzNetworkInterface -ResourceId $netIface.Id
    $secGrp = $null
    if ($netIfaceDef.NetworkSecurityGroup)
    {
        $secGrp = $netIfaceDef.NetworkSecurityGroup
    }
    else
    {
        foreach($ipConf in $netIfaceDef.IpConfigurations)
        {
            $sNet = Get-AzVirtualNetworkSubnetConfig -ResourceId $ipConf.Subnet.Id
            if ($sNet.NetworkSecurityGroup)
            {
                $secGrp = $netIfaceDef.NetworkSecurityGroup
                break
            }
        }
    }
    if ($secGrp)
    {
        $secGrp | Add-AzNetworkSecurityRuleConfig -Name "PortForWACService" -Access "Allow" -Direction "Outbound" -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "WindowsAdminCenter" -DestinationPortRange "443" -Priority 100 -Protocol Tcp | Set-AzNetworkSecurityGroup
        # use SourceAddressPrefix=* for internet access
        $secGrp | Add-AzNetworkSecurityRuleConfig -Name "PortForWAC" -Access "Allow" -Direction "Inbound" -SourceAddressPrefix "VirtualNetwork" -SourcePortRange "*" -DestinationAddressPrefix "*" -DestinationPortRange $WacPort -Priority 100 -Protocol Tcp | Set-AzNetworkSecurityGroup
    }
}

# Checking AdminCenter vm extension
Write-Host "Checking AdminCenter vm extension" -ForegroundColor $CommandInfo
$VmExtName = "$($VMName)AdminCenter"
$VmExt = Get-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -Name $VmExtName -ErrorAction SilentlyContinue
if (-Not $VmExt)
{
    Write-Warning "AdminCenter extension on vm not found. Installing AdminCenter on vm $VMName"
    #Get-AzVmImagePublisher -Location $AlyaLocation | Get-AzVMExtensionImageType | Get-AzVMExtensionImage | Select-Object Type, Version
    #$Extension = Get-AzVMExtensionImage -Location $AlyaLocation -PublisherName "Microsoft.Azure.Security" -Type "IaaSAntimalware" | Select-Object -last 1
    $wacSettings = @"
        {
            "port": $WacPort,
            "salt": $WacSalt
        }
"@
    $typeHandlerVer = (Get-AzVMExtensionImage -Location $AlyaLocation -PublisherName "Microsoft.AdminCenter" -Type "AdminCenter" | %{ new-object System.Version ($_.Version) } | Sort | Select-Object -Last 1).ToString()
    $typeHandlerVerMjandMn = $typeHandlerVer.split(".")
    $typeHandlerVerMjandMn = $typeHandlerVerMjandMn[0] + "." + $typeHandlerVerMjandMn[1]
    $VmExt = Set-AzVMExtension -ResourceGroupName $ResourceGroupName -VMName $VMName -Location $AlyaLocation `
        -Publisher "Microsoft.Azure.Security" -ExtensionType "IaaSAntimalware" -Name $VmExtName `
        -SettingString $wacSettings -TypeHandlerVersion $typeHandlerVerMjandMn
}

#ToDo WinRM configuration

#Stopping Transscript
Stop-Transcript
