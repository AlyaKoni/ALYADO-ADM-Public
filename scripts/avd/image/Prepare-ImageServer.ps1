#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2025

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
    07.03.2022 Konrad Brunner       AVD Version
    16.11.2022 Konrad Brunner       Customer merges

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\avd\image\Prepare-ImageServer-$($AlyaTimeString).log" | Out-Null

# Constants
$VmToImage = "$($AlyaNamingPrefix)avdi$($AlyaResIdAvdImageServer)"
$VmResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAvdImageResGrp)"
$ImageName = "$($VmToImage)_ImageServer"
$ImageResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAvdImageResGrp)"
$DiagnosticResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
$DiagnosticStorageName = "$($AlyaNamingPrefix)strg$($AlyaResIdDiagnosticStorage)"
$KeyVaultResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"
$DateString = (Get-Date -Format "_yyyyMMdd_HHmmss")
$VMDiskName = "$($VmToImage)osdisk"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Compute"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "ImageHost | Prepare-ImageServer | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking ressource group
Write-Host "Checking vm ressource group" -ForegroundColor $CommandInfo
$ResGrpVm = Get-AzResourceGroup -Name $VmResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrpVm)
{
    Write-Warning "Ressource Group not found. Creating the Ressource Group $VmResourceGroupName"
    $ResGrpVm = New-AzResourceGroup -Name $VmResourceGroupName -Location $AlyaLocation -Tag @{displayName="Image Host";ownerEmail=$Context.Account.Id}
}

# Checking ressource group
Write-Host "Checking image ressource group" -ForegroundColor $CommandInfo
$ResGrpImage = Get-AzResourceGroup -Name $ImageResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrpImage)
{
    Write-Warning "Ressource Group not found. Creating the Ressource Group $ImageResourceGroupName"
    $ResGrpImage = New-AzResourceGroup -Name $ImageResourceGroupName -Location $AlyaLocation -Tag @{displayName="Image";ownerEmail=$Context.Account.Id}
}

# Checking locks on resource group
Write-Host "Checking locks on resource group '$($VmResourceGroupName)'" -ForegroundColor $CommandInfo
$actLocks = Get-AzResourceLock -ResourceGroupName $VmResourceGroupName -ErrorAction SilentlyContinue
foreach($actLock in $actLocks)
{
    if ($actLock.Properties.level -eq "CanNotDelete")
    {
        Write-Host "Removing lock $($actLock.Name)"
        $null = $actLock | Remove-AzResourceLock -Force
    }
}

# Checking the source vm
Write-Host "Checking the source vm '$VmToImage'" -ForegroundColor $CommandInfo
$Vm = Get-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage -ErrorAction SilentlyContinue
if (-Not $Vm)
{
    throw "VM not found. Please create the VM $VmToImage"
}
$Vm | Export-CliXml -Path "$AlyaData\avd\image\$VmToImage.cliXml" -Depth 20 -Force -Encoding $AlyaUtf8Encoding

# Stopping the source vm
Write-Host "Stopping the source vm '$VmToImage'" -ForegroundColor $CommandInfo
Stop-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage -Force

# Creating new VM Disk Snapshot
Write-Host "Creating new VM Disk Snapshot" -ForegroundColor $CommandInfo
$SnapshotName = $VmToImage + "-snapshot"
$Snapshot = Get-AzSnapshot -SnapshotName $SnapshotName -ResourceGroupName $VmResourceGroupName -ErrorAction SilentlyContinue
if ($Snapshot)
{
    Write-Warning "Deleting existing snapshot $SnapshotName"
    Remove-AzSnapshot -SnapshotName $SnapshotName -ResourceGroupName $VmResourceGroupName -Force
}
$SnapshotConfig = New-AzSnapshotConfig -SourceUri $Vm.StorageProfile.OsDisk.ManagedDisk.Id -Location $AlyaLocation -CreateOption "Copy"
$Snapshot = New-AzSnapshot -Snapshot $SnapshotConfig -SnapshotName $SnapshotName -ResourceGroupName $VmResourceGroupName

# Starting the source vm
Write-Host "Starting the source vm '$VmToImage'" -ForegroundColor $CommandInfo
Start-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage

# Preparing the source vm
Write-Host "Please prepare now the source host ($VmToImage):"
Write-Host '  - Start a PowerShell as Administrator'
Write-Host '  - Run commands:'
Write-Host '      sfc.exe /scannow'
Write-Host '      pause'
Write-Host '      Set-TimeZone -Id "UTC"'
#Write-Host '      Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation -Name RealTimeIsUniversal -Value 1 -Type DWord -Force'
#Write-Host '      Set-Service -Name w32time -StartupType Automatic'
#Write-Host '      Remove-Item -Path C:\Windows\Panther -Recurse -Force'
Write-Host '      $state = (Get-ItemProperty -Path HKLM:\SYSTEM\Setup\Status\SysprepStatus -Name GeneralizationState).GeneralizationState'
Write-Host '      if ($state -ne 7) { throw "wrong GeneralizationState" }'
Write-Host '      for ($i=0; $i -le 2; $i++) {'
Write-Host '      Get-AppxPackage -AllUser | where {$_.PackageFullName -like "Microsoft.LanguageExperiencePack*"} | Remove-AppxPackage -ErrorAction Continue'
Write-Host '      Get-AppxPackage -AllUser | where {$_.PackageFullName -like "AdobeNotificationClient_*"} | Remove-AppxPackage -ErrorAction Continue'
Write-Host '      Get-AppxPackage -AllUser | where {$_.PackageFullName -like "Adobe.CC.XD_*"} | Remove-AppxPackage -ErrorAction Continue'
Write-Host '      Get-AppxPackage -AllUser | where {$_.PackageFullName -like "Adobe.Fresco_*" } | Remove-AppxPackage -ErrorAction Continue'
Write-Host '      Get-AppxPackage -AllUser | where {$_.PackageFullName -like "InputApp_*" } | Remove-AppxPackage -ErrorAction Continue'
Write-Host '      Get-AppxPackage -AllUser | where {$_.PackageFullName -like "Microsoft.PPIProjection_*" } | Remove-AppxPackage -ErrorAction Continue'
Write-Host '      Get-AppxProvisionedPackage -Online | where {$_.PackageName -like "Microsoft.LanguageExperiencePack*"} | Remove-AppxProvisionedPackage -Online -ErrorAction Continue'
Write-Host '      Get-AppxProvisionedPackage -Online | where {$_.PackageName -like "AdobeNotificationClient_*"} | Remove-AppxProvisionedPackage -Online -ErrorAction Continue'
Write-Host '      Get-AppxProvisionedPackage -Online | where {$_.PackageName -like "Adobe.CC.XD_*"} | Remove-AppxProvisionedPackage -Online -ErrorAction Continue'
Write-Host '      Get-AppxProvisionedPackage -Online | where {$_.PackageName -like "Adobe.Fresco_*" } | Remove-AppxProvisionedPackage -Online -ErrorAction Continue'
Write-Host '      Get-AppxProvisionedPackage -Online | where {$_.PackageName -like "InputApp_*" } | Remove-AppxProvisionedPackage -Online -ErrorAction Continue'
Write-Host '      Get-AppxProvisionedPackage -Online | where {$_.PackageName -like "Microsoft.PPIProjection_*" } | Remove-AppxProvisionedPackage -Online -ErrorAction Continue'
Write-Host '      }'
Write-Host '      & "$Env:SystemRoot\system32\sysprep\sysprep.exe" /generalize /oobe /shutdown'
Write-Host '      while($true) {'
Write-Host '        $imageState = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State).ImageState'
Write-Host '        Write-Output $imageState'
Write-Host '        if ($imageState -eq "IMAGE_STATE_GENERALIZE_RESEAL_TO_OOBE") { break }'
Write-Host '        Start-Sleep -s 5'
Write-Host '      }'
Write-Host '  - Wait until the vm has stopped state'
Write-Host '  - In case of troubles, follow this guide: https://learn.microsoft.com/en-us/azure/virtual-machines/windows/prepare-for-upload-vhd-image'
<#
Bei Fehler Logdatei untersuchen:
%WINDIR%\System32\Sysprep\Panther\setupact.log
Unter Umständen müssen Packages entfernt werden. Siehe hierzu cleanImage.ps1
#>
pause

# Checking if source vm is stopped
Write-Host "Checking if source vm $($VmToImage) is stopped" -ForegroundColor $CommandInfo
$isStopped = $false
while (-Not $isStopped)
{
    $Vm = Get-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage -Status -ErrorAction SilentlyContinue
    foreach ($VmStat in $Vm.Statuses)
    { 
        if($VmStat.Code -eq "PowerState/stopped" -or $VmStat.Code -eq "PowerState/deallocated")
        {
            $isStopped = $true
            break
        }
    }
    if (-Not $isStopped)
    {
        Write-Host "Please stop the VM $($VmToImage)"
        Start-Sleep -Seconds 15
    }
}

# Preparing the source vm
Write-Host "Preparing the source vm '$($VmToImage)'" -ForegroundColor $CommandInfo
Stop-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage -Force
Set-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage -Generalized  

# Deleting existing image (for update)
Write-Host "Deleting existing image if present" -ForegroundColor $CommandInfo
$image = Get-AzImage -ResourceGroupName $VmResourceGroupName -ImageName $ImageName -ErrorAction SilentlyContinue
if ($image)
{
    Write-Warning "Deleting existing image $ImageName"
    Remove-AzImage -ResourceGroupName $VmResourceGroupName -ImageName $ImageName -Force
}

# Saving the source vm as image
Write-Host "Saving the source vm '$($VmToImage)' as template to $($ImageName)" -ForegroundColor $CommandInfo
$Vm = Get-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage
$tags = (Get-AzResource -ResourceGroupName $VmResourceGroupName -Name $VmToImage -ResourceType "Microsoft.Compute/virtualMachines" -ErrorAction SilentlyContinue).Tags
$image = New-AzImageConfig -Location $AlyaLocation -SourceVirtualMachineId $Vm.ID -HyperVGeneration $AlyaAvdHypervisorVersion
New-AzImage -Image $image -ImageName $ImageName -ResourceGroupName $ImageResourceGroupName -ErrorAction Stop

# Checking key vault
Write-Host "Checking key vault" -ForegroundColor $CommandInfo
$KeyVault = Get-AzKeyVault -ResourceGroupName $KeyVaultResourceGroupName -VaultName $KeyVaultName -ErrorAction SilentlyContinue
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

# Checking azure key vault secret
Write-Host "Checking azure key vault secret" -ForegroundColor $CommandInfo
$CompName = Make-PascalCase($AlyaCompanyNameShort)
$ImageHostCredentialAssetName = "$($VmToImage)AdminCredential"
$AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $ImageHostCredentialAssetName -ErrorAction SilentlyContinue
if (-Not $AzureKeyVaultSecret)
{
    Write-Warning "Key Vault secret not found. Creating the secret $ImageHostCredentialAssetName"
    $VMPassword = "$" + [Guid]::NewGuid().ToString() + "!"
    $VMPasswordSec = ConvertTo-SecureString $VMPassword -AsPlainText -Force
    $AzureKeyVaultSecret = Set-AzKeyVaultSecret -VaultName $KeyVaultName -Name $ImageHostCredentialAssetName -SecretValue $VMPasswordSec
}
else
{
    $VMPasswordSec = $AzureKeyVaultSecret.SecretValue
}
Clear-Variable -Name VMPassword -Force -ErrorAction SilentlyContinue
Clear-Variable -Name AzureKeyVaultSecret -Force -ErrorAction SilentlyContinue

# Deleting source vm
Write-Host "Deleting source vm '$($VmToImage)'" -ForegroundColor $CommandInfo
Remove-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage -Force
Remove-AzDisk -ResourceGroupName $VmResourceGroupName -DiskName $Vm.StorageProfile.OsDisk.Name -Force
#$Vm = Import-CliXml -Path "$AlyaData\avd\image\$VmToImage.cliXml"

# Recreating source vm
Write-Host "Recreating source vm '$($VmToImage)'" -ForegroundColor $CommandInfo
$VMCredential = New-Object System.Management.Automation.PSCredential ("$($VmToImage)admin", $VMPasswordSec)
$netIfaceName = $Vm.NetworkProfile.NetworkInterfaces[0].Id.Substring($Vm.NetworkProfile.NetworkInterfaces[0].Id.LastIndexOf("/") + 1)
$netIface = Get-AzNetworkInterface -ResourceGroupName $VmResourceGroupName -Name $netIfaceName
if ($Vm.AvailabilitySetReference)
{
    #TODO -LicenseType $AlyaVmLicenseType if server and hybrid benefit
    $VmConfig = New-AzVMConfig -AvailabilitySetId $Vm.AvailabilitySetReference.Id -VMName $VmToImage -VMSize $Vm.HardwareProfile.VmSize
    $VmConfig | Set-AzVMOperatingSystem -Windows -ComputerName $VmToImage -Credential $VMCredential
}
else
{
    #TODO -LicenseType $AlyaVmLicenseType if server and hybrid benefit
    $VmConfig = New-AzVMConfig -VMName $VmToImage -VMSize $Vm.HardwareProfile.VmSize
    $VmConfig | Set-AzVMOperatingSystem -Windows -ComputerName $VmToImage -Credential $VMCredential
}
$image = Get-AzImage -ImageName $ImageName -ResourceGroupName $ImageResourceGroupName
$VmConfig | Set-AzVMSourceImage -Id $image.Id | Out-Null
$VmConfig | Add-AzVMNetworkInterface -Id $netIface.Id | Out-Null
$VmConfig | Set-AzVMBootDiagnostic -Enable -ResourceGroupName $DiagnosticResourceGroupName -StorageAccountName $DiagnosticStorageName | Out-Null
$VmConfig | Set-AzVMOSDisk -Name $VMDiskName -CreateOption FromImage -Caching ReadWrite -DiskSizeInGB $Vm.StorageProfile.OsDisk.DiskSizeGB | Out-Null
$newVm = New-AzVM -ResourceGroupName $VmResourceGroupName -Location $Vm.Location -VM $VmConfig -DisableBginfoExtension

# Setting tags
Write-Host "Setting tags" -ForegroundColor $CommandInfo
if (-Not $tags) { $tags = @{} }
if (-Not $tags.ContainsKey("displayName"))
{
    $tags["displayName"] = "AVD Server Image"
}
if (-Not $tags.ContainsKey("stopTime"))
{
    $tags["stopTime"] = $AlyaAvdStopTime
}
if (-Not $tags.ContainsKey("ownerEmail"))
{
    $tags["ownerEmail"] = $Context.Account.Id
}
Set-AzResource -ResourceGroupName $VmResourceGroupName -Name $VmToImage -ResourceType "Microsoft.Compute/VirtualMachines" -Tag $tags -Force

$tags = (Get-AzResource -ResourceGroupName $ImageResourceGroupName -Name $ImageName -ResourceType "Microsoft.Compute/images" -ErrorAction SilentlyContinue).Tags
if (-Not $tags) { $tags = @{} }
if (-Not $tags.ContainsKey("displayName"))
{
    $tags["displayName"] = "AVD Server Image"
}
if (-Not $tags.ContainsKey("ownerEmail"))
{
    $tags["ownerEmail"] = $Context.Account.Id
}
Set-AzResource -ResourceGroupName $ImageResourceGroupName -Name $ImageName -ResourceType "Microsoft.Compute/images" -Tag $tags -Force

# Stopping VM
Write-Host "Stopping VM" -ForegroundColor $CommandInfo
Stop-AzVM -ResourceGroupName $VmResourceGroupName -Name $VmToImage -Force

# Restoring locks on resource group
Write-Host "Restoring locks on resource group '$($VmResourceGroupName)'" -ForegroundColor $CommandInfo
foreach($actLock in $actLocks)
{
    if ($actLock.Properties.level -eq "CanNotDelete")
    {
        Write-Host "Adding lock $($actLock.Name)"
        $null = Set-AzResourceLock -ResourceGroupName $VmResourceGroupName -LockName $actLock.Name -LockLevel CanNotDelete -LockNotes $actLock.Properties.notes -Force
    }
}

<# In case, the image was not generalized, delete the VM and recreate it with:

$failedVmDisk = Get-AzDisk -ResourceGroupName $VmResourceGroupName -Name $Vm.StorageProfile.OsDisk.Name
$VmConfig = New-AzVMConfig -AvailabilitySetId $Vm.AvailabilitySetReference.Id -VMName $VmToImage -VMSize $Vm.HardwareProfile.VmSize -LicenseType "Windows_Server"
$VmConfig = Set-AzVMOSDisk -VM $VmConfig -ManagedDiskId $failedVmDisk.Id -CreateOption Attach -Windows
$VmConfig = Add-AzVMNetworkInterface -VM $VmConfig -Id $netIface.Id
$newVm = New-AzVM -ResourceGroupName $VmResourceGroupName -Location $Vm.Location -VM $VmConfig

#> 

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA4ISyoGWD0zt9d
# 7IfMXAmz9GVq+L6RoVsx2SVDHUYSFqCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
# th1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAwMDBaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# EylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj/SBerjgS
# i8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlMg7BKRFAE
# eIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRVX5YLEeWa
# tSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV0xHK5s2z
# BZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEzIHXMsdXt
# HQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMkoog28vmf
# vpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq7rfYrWGl
# r3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult5a/dm2tj
# IF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNutwFsDeCX
# pxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYyAjIwfLWT
# yCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofnGrhO7izB
# 36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJZ3Q
# /FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lWULvO
# ljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5ncm9v
# dHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJKwYBBAGg
# MgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3Jl
# cG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJyTm6t6E5
# iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbVYQLFY4/U
# ovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQtpFg6bBNJ
# +KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSXhndGKj0j
# fShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6bs+XYXvf
# cXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nOZNm9/Lws
# 80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOHX5OKSBoR
# HeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dqcYC/lt5y
# A9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0ixxnJpsoO
# qHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7qWPLd0jV
# +mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72f1LiSY25
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g604YfM/tV
# 5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD4ED6gVYD
# U/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S/gJXhZrh
# 0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp8nKmrVa4
# 6Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqtf2phU7+y
# R2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJQWTEE/bP
# 0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKXvYkPbEdx
# +QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4yMYgcMKb
# 9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmYF8T4xO2k
# 6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2mMIVpqWC
# Z1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7spNY6rQb
# 3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd2jANBgkq
# hkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy/fAHsVv1
# RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW2H3Bh6zN
# XULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0MP6pBPKO
# L6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/pFL9zlcc
# tWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcexU0bcV0hL
# Q4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf6AMOGaM5
# 6A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzECp9LnR+34
# c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9mUF5qE6Yw
# QqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+KuaJRsz+cn
# ZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/JlN6m6GM1j
# EhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutofdgNBzMUx
# ghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFoIq+CKDONUYBJc
# f0FalwKDUOFbLvw8K4zlWqYPfRuLMA0GCSqGSIb3DQEBAQUABIICAE1ZmLcBv0zy
# QYgtpvMQe5vnNZIg/o/gCWC5vEelG26SgYi+WY5p5Ciy1Us3W1OBTdB3L1hwUKAz
# M3mUkeEXzbrHEdr2zbkZKlug7IRso9n/E3SMoLZBwkjMFfsK7+56nJ/rafsMv3U6
# wgrjrlMXnSc1cZGjX1/G47wgEZ4Z1OepD4sZy7o/PaegvGkGyeNzaNIaowITE44H
# 4wlzn62GjmnRDNdam36TNkJoschSqB58Fd2GOPKIZuBkT8KFLq4ryXQoe8EgGz8q
# Z/t86gzTMw616sTAAJjNLsfZ0oJWISvmiGTAHYrjAXwMsvzb4lUgsX8bYbp7k4jP
# XbB5yPVVTuOItkJNG4cYzLZSmY2+0mdYsyawZ1TTKCmtKryvG+WOkcE7yKASgX6P
# p3hV3AinnxzFdcvZInurijyx9mGpRHdwUGGAvU8BZg495ert90tFz8sDkVqTUyl+
# qVLxDxH2u6uAIMjUSVI2+9Z2UlHIlkgPmFggF+uHxFuZG/uSyj7tJ/bTcR/zvD+b
# bm6LM3GEmqoNnwPNHXteakUNcchpV/EDLCyQah1misK7wOpX/fySYnUzJizbSlSe
# t3YPZ67kwzxE0aLMC3Iwn1rqlGg3Lvo+Bndv3y6i6QlSj5eshVWIYJQgfcNK9Oe0
# Gy7yTUbR1j1BVRBZa63MY7w2VvV6THu0oYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCC72ZfK8ROQ9PsYRU3X08q5NwI54lCcpEbFKWPSZrftJQIUedfe9tgE8yqG
# P7iQeLo/uNTtab0YDzIwMjUxMjE5MDkwNzQzWjADAgEBoFikVjBUMQswCQYDVQQG
# EwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFs
# c2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMCAQICEAEA
# CyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5WhcNMzQx
# MjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBu
# di1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4PuCF6+aq
# Cj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb5gk0Xydy
# 3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJScRV1W6/6e
# fi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy5RJY+o1N
# WhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY0Lie04Du
# KbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2ZwbI6yiFH
# aS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYhKUlrMH9+
# 2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5sWtX1qvCz
# k6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGoMIIBpDAO
# BgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYE
# FIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQCMEEGCSsG
# AQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNv
# bS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5
# BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2Fj
# YXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24u
# Y29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn
# 48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xv
# YmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG9w0BAQwF
# AAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26IFq7fQMI
# rN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76TkvL+v2f4mH
# olGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftPttS+G/Mh
# NUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIlS3Ki74CU
# 15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt8DT4RQj9
# LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5lgJkgXEc
# 1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD9hQchjiG
# kyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71yzGKWnbA
# WQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGLZtJFJzGJ
# D7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVAGXCqHsh6
# 2QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZMIIEQaAD
# AgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0ds
# b2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYD
# VQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAwMDAwMFow
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOvdYNfqUdS
# x2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt0ShKwSy7
# uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrE
# iPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64
# VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16ZevRVqku
# vftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv
# +GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm19m1W/ood
# CT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIGbxsY1Tbq
# ZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMDAd6ZJflx
# bumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/MiyTdtk8EWf
# usE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9GbCX6oxQ
# kW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGGMBIGA1Ud
# EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDDvWWWMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAu
# BggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYWaxlASSUI
# HuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCyz+zCVmUd
# vX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W
# 8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWz
# Alcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59eodaZzul9
# S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8oMWsr1EG
# 8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1If5iEO0d
# MPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDU
# Y6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+
# PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+
# gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIIDa6ADAgEC
# Ag5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9i
# YWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
# AxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwx
# IDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9i
# YWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRv
# f+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJ
# f094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcx
# BsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQ
# Bzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5d
# RC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWq
# RfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX8
# 5mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjpl
# llnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R
# /98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFl
# tr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEA
# AaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE
# FK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tyt
# ok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7
# jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh
# 4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR
# 3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6
# fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgb
# KCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglI
# WYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Q
# v4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98
# i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU
# 4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzW
# AtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJYIZIAWUD
# BAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0
# MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcNAQkEMSIE
# IJj6qdBMUZAUeWO+iXen0NeioaGmwu+G7XjDjwUcBvMfMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAaPcWK5PUHX7H
# SIx0CVxL6JCr7vC2IW/XY7zlyE/p6cczJZZ/+cJ1FQJ6hhpiiw7UUIXdd6LcJrbQ
# Iz61YFn3jjgUTSfvoi0+tDk5ozLzxri3lVoW3E0EoudKlSspWYkMt2PR2j8HeA39
# N2oquyciousf7NDXHdcEtZ3SCWkdgncPAE/Gzmc8uHnICbxX6bBwUnD999RWCYGd
# xo0NflwwyfkHCI4y7u5Q2063z7mtmrLqB7g2jecs0mHnl8WfetqbBNbEqdJDoC8s
# lTdXx7Dg1Bunv/QLA8gG3L0MPUUNL7CPbAqMiz/fqq2L/SH9+2RqhyfrO6j/H6wb
# ZuOhrggGLNhGZir5ZN1XxF3Rr3nk75nf0DiOLnC1rXqctOKncNxAqgE9vdpr3z5w
# wrfU8/VFFlCbLlYc6bmSF52rpSO7pjznvXwl8pXTWk8840o16RD5opgGcPNshjzK
# 4j74NP3fTvxXQ1AafcOZgux8QCrF+u5f0cwa0JcmXhim3FUI2KWl
# SIG # End signature block
