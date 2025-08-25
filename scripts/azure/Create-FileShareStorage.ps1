﻿#Requires -Version 2.0

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
    09.08.2021 Konrad Brunner       Initial Version
	16.08.2021 Konrad Brunner		Added provider registration

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,
    [Parameter(Mandatory=$true)]
    [ValidateSet("Archive","StdCool","StdHot", "StdTransOpt","Premium")]
    [string]$StorageType,
    [Parameter(Mandatory=$true)]
    [string]$StorageAccountName,
    [string]$ShareName = "testshare",
    [Parameter(Mandatory=$true)]
    [string]$NetworkResourceGroupName,
    [Parameter(Mandatory=$true)]
    [string]$VirtualNetworkName,
    [Parameter(Mandatory=$true)]
    [string]$SubnetName,
    [bool]$WithPrivateEndpoint = $false,
    [bool]$WithADIntegration = $false,
    [bool]$WithAADIntegration = $false
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\Create-FileShareStorage-$($AlyaTimeString).log" -IncludeInvocationHeader -Force | Out-Null

# Constants
$suffix = ""
<#
switch($StorageType)
{
    "Archive" {
        $suffix = "ar"
    }
    "StdCool" {
        $suffix = "sc"
    }
    "StdHot" {
        $suffix = "sh"
    }
    "StdTransOpt" {
        $suffix = "st"
    }
    "Premium" {
        $suffix = "pp"
    }
    "PremCool" {
        $suffix = "pc"
    }
    "PremHot" {
        $suffix = "ph"
    }
    default {
        throw "StorageType $StorageType not yet implemented"
    }
}
max 15 chars for name if ad integrated!
#>
$StorageAccountNameFiles = $StorageAccountName + $suffix

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Network"
Install-ModuleIfNotInstalled "Az.Storage"
Install-ModuleIfNotInstalled "Az.PrivateDns"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "FileShare | Create-FileShareStorage | AZURE" -ForegroundColor $CommandInfo
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
    throw "Ressource Group not found. Pleas ecreate the Ressource Group $ResourceGroupName"
}

# =============================================================
# Checking Subscription
# =============================================================

# Checking resource provider registration
Write-Host "Checking resource provider registration" -ForegroundColor $CommandInfo
$resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Storage" -Location $AlyaLocation
if (-Not $resProv -or $resProv.Count -eq 0 -or $resProv[0].RegistrationState -ne "Registered")
{
    Write-Warning "Resource provider Microsoft.Storage not registered. Registering now resource provider Microsoft.Storage"
    Register-AzResourceProvider -ProviderNamespace "Microsoft.Storage" | Out-Null
    do
    {
        Start-Sleep -Seconds 5
        $resProv = Get-AzResourceProvider -ProviderNamespace "Microsoft.Storage" -Location $AlyaLocation
    } while ($resProv[0].RegistrationState -ne "Registered")
}

# Checking provider feature registration
Write-Host "Checking provider feature registration" -ForegroundColor $CommandInfo
$provFeatr = Get-AzProviderFeature -FeatureName AllowSMBMultichannel -ProviderNamespace Microsoft.Storage
if (-Not $provFeatr -or $provFeatr.RegistrationState -ne "Registered")
{
    Write-Warning "Provider feature AllowSMBMultichannel not registered. Registering now provider feature AllowSMBMultichannel"
    Register-AzProviderFeature -FeatureName AllowSMBMultichannel -ProviderNamespace Microsoft.Storage | Out-Null
    do
    {
        Start-Sleep -Seconds 5
        $provFeatr = Get-AzProviderFeature -FeatureName AllowSMBMultichannel -ProviderNamespace Microsoft.Storage
    } while ($provFeatr.RegistrationState -ne "Registered")
}

# =============================================================
# Checking Network
# =============================================================

# Checking virtual network
Write-Host "Checking virtual network" -ForegroundColor $CommandInfo
$VNet = Get-AzVirtualNetwork -ResourceGroupName $NetworkResourceGroupName -Name $VirtualNetworkName -ErrorAction SilentlyContinue
if (-Not $VNet)
{
    throw "Virtual network not found. Please create virtual network $VirtualNetworkName"
}

# Checking subnet
Write-Host "Checking subnet" -ForegroundColor $CommandInfo
$Subnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $VNet -Name $SubnetName -ErrorAction SilentlyContinue
if (-Not $Subnet)
{
    throw "Subnet not found. Please create the subnet $SubnetName"
}

if ($WithPrivateEndpoint)
{
    # Checking private endpoint network policies
    Write-Host "Checking private endpoint network policies" -ForegroundColor $CommandInfo
    if ($Subnet.PrivateEndpointNetworkPolicies -ne "Disabled")
    {
        Write-Warning "Private endpoint network policies not disabled, disabling it now"
        $Subnet.PrivateEndpointNetworkPolicies = "Disabled"
        $VNet = $VNet | Set-AzVirtualNetwork
    }
}

# =============================================================
# Checking Shares
# =============================================================

# Checking files storage account
Write-Host "Checking files storage account" -ForegroundColor $CommandInfo
$StrgAccountFiles = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountNameFiles -ErrorAction SilentlyContinue
if (-Not $StrgAccountFiles)
{
    Write-Warning "Files storage account not found. Creating the files storage account $StorageAccountNameFiles"
    $tags = @{DisplayName="$StorageType Azure File Storage";Services="Files"}
    switch($StorageType)
    {
        "Archive" {
            $StrgAccountFiles = New-AzStorageAccount -Name $StorageAccountNameFiles -ResourceGroupName $ResourceGroupName -Location $AlyaLocation -SkuName "Standard_LRS" -Kind StorageV2 -AccessTier Cool -EnableHttpsTrafficOnly $true -MinimumTlsVersion "TLS1_2" -Tag $tags
        }
        "StdCool" {
            $StrgAccountFiles = New-AzStorageAccount -Name $StorageAccountNameFiles -ResourceGroupName $ResourceGroupName -Location $AlyaLocation -SkuName "Standard_LRS" -Kind StorageV2 -AccessTier Cool -EnableHttpsTrafficOnly $true -MinimumTlsVersion "TLS1_2" -Tag $tags
        }
        "StdHot" {
            $StrgAccountFiles = New-AzStorageAccount -Name $StorageAccountNameFiles -ResourceGroupName $ResourceGroupName -Location $AlyaLocation -SkuName "Standard_LRS" -Kind StorageV2  -AccessTier Hot -EnableHttpsTrafficOnly $true -MinimumTlsVersion "TLS1_2" -Tag $tags
        }
        "StdTransOpt" {
            $StrgAccountFiles = New-AzStorageAccount -Name $StorageAccountNameFiles -ResourceGroupName $ResourceGroupName -Location $AlyaLocation -SkuName "Standard_LRS" -Kind StorageV2  -AccessTier Hot -EnableHttpsTrafficOnly $true -MinimumTlsVersion "TLS1_2" -Tag $tags
        }
        "Premium" {
            $StrgAccountFiles = New-AzStorageAccount -Name $StorageAccountNameFiles -ResourceGroupName $ResourceGroupName -Location $AlyaLocation -SkuName "Premium_LRS" -Kind FileStorage  -EnableHttpsTrafficOnly $true -MinimumTlsVersion "TLS1_2" -Tag $tags
        }
        "PremCool" {
            $StrgAccountFiles = New-AzStorageAccount -Name $StorageAccountNameFiles -ResourceGroupName $ResourceGroupName -Location $AlyaLocation -SkuName "Premium_LRS" -Kind FileStorage -AccessTier Cool -EnableHttpsTrafficOnly $true -MinimumTlsVersion "TLS1_2" -Tag $tags
        }
        "PremHot" {
            $StrgAccountFiles = New-AzStorageAccount -Name $StorageAccountNameFiles -ResourceGroupName $ResourceGroupName -Location $AlyaLocation -SkuName "Premium_LRS" -Kind FileStorage  -AccessTier Hot -EnableHttpsTrafficOnly $true -MinimumTlsVersion "TLS1_2" -Tag $tags
        }
        default {
            throw "StorageType $StorageType not yet implemented"
        }
    }
    if (-Not $StrgAccountFiles)
    {
        throw "Files storage account $StorageAccountNameFiles creation failed. Please fix and start over again"
    }
}

# Checking file share
Write-Host "Checking file share" -ForegroundColor $CommandInfo
$FileShare = Get-AzRmStorageShare -StorageAccount $StrgAccountFiles -Name $ShareName -ErrorAction SilentlyContinue
if (-Not $FileShare)
{
    Write-Warning "File share not found. Creating the file share $ShareName"
    $AccessTier = ""
    switch($StorageType)
    {
        "Archive" {
            $AccessTier = "Cool"
        }
        "StdCool" {
            $AccessTier = "Cool"
        }
        "StdHot" {
            $AccessTier = "Hot"
        }
        "StdTransOpt" {
            $AccessTier = "TransactionOptimized"
        }
        "Premium" {
            $AccessTier = "Premium"
        }
        "PremCool" {
            $AccessTier = "Premium"
        }
        "PremHot" {
            $AccessTier = "Premium"
        }
        default {
            throw "StorageType $StorageType not yet implemented"
        }
    }
    $tags = @{DisplayName="$AccessTier file share for testing and performance measurement";Services="Files"}
    $FileShare = New-AzRmStorageShare -StorageAccount $StrgAccountFiles -Name $ShareName -AccessTier $AccessTier -Metadata $tags
    if (-Not $FileShare)
    {
        throw "File share $ShareName creation failed. Please fix and start over again"
    }
}

# Checking storage account multichannel support
Write-Host "Checking storage account multichannel support" -ForegroundColor $CommandInfo
if ($StorageType -eq "Premium" -or $StorageType -eq "PremHot" -or $StorageType -eq "PremCool")
{
    $StrgAccountFilesProps = Get-AzStorageFileServiceProperty -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountNameFiles
    if (-Not $StrgAccountFilesProps -or (-Not $StrgAccountFilesProps.EnableSmbMultichannel))
    {
        Write-Warning "Storage account multichannel support not enabled. Enabling storage account multichannel support"
        Update-AzStorageFileServiceProperty -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountNameFiles -EnableSmbMultichannel $true | Out-Null
    }
}

# =============================================================
# Checking Private Endpoint and DNS
# =============================================================

if ($WithPrivateEndpoint)
{

    Write-Host "Checking private endpoint" -ForegroundColor $CommandInfo
    $privateEndpointName = "$($StorageAccountNameFiles)pe"
    $privateEndpoint = Get-AzPrivateEndpoint -ResourceGroupName $ResourceGroupName -Name $privateEndpointName -ErrorAction SilentlyContinue
    if (-Not $privateEndpoint)
    {
        Write-Warning "Private endpoint not found. Creating now endpoint $privateEndpointName"
        $privateEndpointConnection = New-AzPrivateLinkServiceConnection `
            -Name "$($StorageAccountNameFiles)con" `
            -PrivateLinkServiceId $StrgAccountFiles.Id `
            -GroupId "file"
        $privateEndpoint = New-AzPrivateEndpoint `
            -ResourceGroupName $ResourceGroupName `
            -Name $privateEndpointName `
            -Location $VNet.Location `
            -Subnet $Subnet `
            -PrivateLinkServiceConnection $privateEndpointConnection
    }

    Write-Host "Checking private DNS zone" -ForegroundColor $CommandInfo
    $storageAccountSuffix = $Context | `
        Select-Object -ExpandProperty Environment | `
        Select-Object -ExpandProperty StorageEndpointSuffix
    $dnsZoneName = "privatelink.file.$storageAccountSuffix"
    $dnsZone = Get-AzPrivateDnsZone | `
        Where-Object { $_.Name -eq $dnsZoneName } | `
        Where-Object {
            $privateDnsLink = Get-AzPrivateDnsVirtualNetworkLink `
                    -ResourceGroupName $_.ResourceGroupName `
                    -ZoneName $_.Name `
                    -ErrorAction SilentlyContinue
            $privateDnsLink.VirtualNetworkId -eq $VNet.Id
        }
    if (-Not $dnsZone)
    {
        Write-Warning "Private DNS zone not found. Creating now private DNS zone $privateZoneName with link"
        $dnsZone = New-AzPrivateDnsZone `
                -ResourceGroupName $NetworkResourceGroupName `
                -Name $dnsZoneName
        $privateDnsLink = New-AzPrivateDnsVirtualNetworkLink `
                -ResourceGroupName $NetworkResourceGroupName `
                -ZoneName $dnsZoneName `
                -Name "$VirtualNetworkName-link-$dnsZoneName" `
                -VirtualNetworkId $VNet.Id
    }

    Write-Host "Checking private DNS record set" -ForegroundColor $CommandInfo
    $privateEndpointIP = $privateEndpoint | `
        Select-Object -ExpandProperty NetworkInterfaces | `
        Select-Object @{ 
            Name = "NetworkInterfaces"; 
            Expression = { Get-AzNetworkInterface -ResourceId $_.Id } 
        } | `
        Select-Object -ExpandProperty NetworkInterfaces | `
        Select-Object -ExpandProperty IpConfigurations | `
        Select-Object -ExpandProperty PrivateIpAddress
    $privateDnsRecordConfig = New-AzPrivateDnsRecordConfig `
        -IPv4Address $privateEndpointIP
    $privateDnsRecordSet = Get-AzPrivateDnsRecordSet `
        -ResourceGroupName $NetworkResourceGroupName `
        -Name $StorageAccountNameFiles `
        -RecordType A `
        -ZoneName $dnsZoneName -ErrorAction SilentlyContinue
    if (-Not $privateDnsRecordSet)
    {
        Write-Warning "Private DNS record set not found. Creating now private DNS record set"
        New-AzPrivateDnsRecordSet `
            -ResourceGroupName $NetworkResourceGroupName `
            -Name $StorageAccountNameFiles `
            -RecordType A `
            -ZoneName $dnsZoneName `
            -Ttl 600 `
            -PrivateDnsRecords $privateDnsRecordConfig | Out-Null
    }

    Write-Host "Disabling public storage access" -ForegroundColor $CommandInfo
    $StrgAccountFiles | Update-AzStorageAccountNetworkRuleSet `
        -DefaultAction Deny `
        -Bypass AzureServices `
        -WarningAction SilentlyContinue | Out-Null
}

# =============================================================
# Enabling AAD Integration
# =============================================================

if ($WithAADIntegration)
{
    
}

# =============================================================
# Enabling AD Integration
# =============================================================

if ($WithADIntegration)
{

    if (-Not $StrgAccountFiles.AzureFilesIdentityBasedAuth)
    {
        Write-Warning "AD integration not yet enabled. Enabling now AD integration"
        $toolDir = "$AlyaTools\AzFilesHybrid"
        if (-Not (Test-Path $toolDir))
        {
            New-Item -Path $toolDir -ItemType Directory -Force | Out-Null
            $req = Invoke-WebRequestIndep -Uri "https://github.com/Azure-Samples/azure-files-samples/releases" -UseBasicParsing -Method Get
            [regex]$regex = "[^`"]*/release[^`"]*windows/[^`"]*"
            [regex]$regex = "[^`"]*/AzFilesHybrid.zip[^`"]*"
            $getUrl = "https://github.com"+([regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value)
            $outFile = "$toolDir\AzFilesHybrid.zip"
            $req = Invoke-WebRequestIndep -Uri $getUrl -OutFile $outFile
            $cmdTst = Get-Command -Name "Expand-Archive" -ParameterName "DestinationPath" -ErrorAction SilentlyContinue
            if ($cmdTst)
            {
                Expand-Archive -Path $outFile -DestinationPath $toolDir -Force #AlyaAutofixed
            }
            else
            {
                Expand-Archive -Path $outFile -OutputPath $toolDir -Force #AlyaAutofixed
            }
            Remove-Item -Path $outFile -Force | Out-Null
            Push-Location $toolDir
            .\CopyToPSPath.ps1
            Pop-Location 
        }

        # Integrate
        Import-Module -Name AzFilesHybrid
        $DomainAccountType = "ComputerAccount"
        $OuDistinguishedName = $null
        $EncryptionType = "AES256"
        Join-AzStorageAccountForAuth `
            -ResourceGroupName $ResourceGroupName `
            -StorageAccountName $StorageAccountNameFiles `
            -DomainAccountType $DomainAccountType `
            -OrganizationalUnitDistinguishedName $OuDistinguishedName `
            -EncryptionType $EncryptionType
        Update-AzStorageAccountAuthForAES256 -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountNameFiles
        Debug-AzStorageAccountAuth -StorageAccountName $StorageAccountNameFiles -ResourceGroupName $ResourceGroupName -Verbose

        # Check
        $StrgAccountFiles = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountNameFiles -ErrorAction SilentlyContinue
        if (-Not $StrgAccountFiles.AzureFilesIdentityBasedAuth)
        {
            Write-Error "Was not able to enable the AD integration"
        }
        else
        {
            $StrgAccountFiles.AzureFilesIdentityBasedAuth | Format-List
            $StrgAccountFiles.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties
        }
        #Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountNameFiles -ListKerbKey
    }
}

# =============================================================
# Configuring permissions
# =============================================================

# To set Default permission for storage account
if ($WithADIntegration)
{
    $defaultPermission = "None" #None|StorageFileDataSmbShareContributor|StorageFileDataSmbShareReader|StorageFileDataSmbShareElevatedContributor
    $StrgAccountFiles = Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -AccountName $StorageAccountNameFiles -DefaultSharePermission $defaultPermission
}

# Setting Share Access
# ATTENTION: Permissions can require very long time until they are reflected on the client!
$FileShareReaderRole = Get-AzRoleDefinition "Storage File Data SMB Share Reader"
$FileShareContributorRole = Get-AzRoleDefinition "Storage File Data SMB Share Contributor"
$FileShareElevatedRole = Get-AzRoleDefinition "Storage File Data SMB Share Elevated Contributor"
$scope = "/subscriptions/$($Context.Subscription.Id)/resourceGroups/$ResourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountNameFiles/fileServices/default/fileshares/$ShareName"

$admGrpName = "$($AlyaCompanyNameShortM365)SG-STG-$($StorageAccountNameFiles)-$($ShareName)-Admin"
$cntGrpName = "$($AlyaCompanyNameShortM365)SG-STG-$($StorageAccountNameFiles)-$($ShareName)-Contributor"
$rdrGrpName = "$($AlyaCompanyNameShortM365)SG-STG-$($StorageAccountNameFiles)-$($ShareName)-Reader"

$admGrp = Get-AzAdGroup -DisplayName $admGrpName -ErrorAction SilentlyContinue
if (-Not $admGrp -And -not $WithADIntegration)
{
    Write-Warning "Admin Security group  not found. Creating it now"
    $admGrp = New-AzAdGroup -DisplayName $admGrpName -MailNickname $admGrpName -Description "Group to assign admin access to share '$ShareName' on storage '$StorageAccountNameFiles'"
}
$admGrpMemb = Get-AzADGroupMember -GroupObjectId $admGrp.Id | Where-Object { $_.UserPrincipalName -eq $context.Account.Id }
if (-Not $admGrpMemb)
{
    Add-AzADGroupMember -TargetGroupObjectId $admGrp.Id -MemberUserPrincipalName $context.Account.Id
}

$cntGrp = Get-AzAdGroup -DisplayName $cntGrpName -ErrorAction SilentlyContinue
if (-Not $cntGrp -And -not $WithADIntegration)
{
    Write-Warning "Contributor Security group  not found. Creating it now"
    $cntGrp = New-AzAdGroup -DisplayName $cntGrpName -MailNickname $cntGrpName -Description "Group to assign contributor access to share '$ShareName' on storage '$StorageAccountNameFiles'"
}
$rdrGrp = Get-AzAdGroup -DisplayName $rdrGrpName -ErrorAction SilentlyContinue
if (-Not $rdrGrp -And -not $WithADIntegration)
{
    Write-Warning "Reader Security group  not found. Creating it now"
    $rdrGrp = New-AzAdGroup -DisplayName $rdrGrpName -MailNickname $rdrGrpName -Description "Group to assign reader access to share '$ShareName' on storage '$StorageAccountNameFiles'"
}

$ass = Get-AzRoleAssignment -ObjectId $admGrp.Id -RoleDefinitionName $FileShareElevatedRole.Name -Scope $scope -ErrorAction SilentlyContinue
if (-Not $ass)
{
    New-AzRoleAssignment -ObjectId $admGrp.Id -RoleDefinitionName $FileShareElevatedRole.Name -Scope $scope
}
$ass = Get-AzRoleAssignment -ObjectId $cntGrp.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $scope -ErrorAction SilentlyContinue
if (-Not $ass)
{
    New-AzRoleAssignment -ObjectId $cntGrp.Id -RoleDefinitionName $FileShareContributorRole.Name -Scope $scope
}
$ass = Get-AzRoleAssignment -ObjectId $rdrGrp.Id -RoleDefinitionName $FileShareReaderRole.Name -Scope $scope -ErrorAction SilentlyContinue
if (-Not $ass)
{
    New-AzRoleAssignment -ObjectId $rdrGrp.Id -RoleDefinitionName $FileShareReaderRole.Name -Scope $scope
}
#New-AzRoleAssignment -SignInName $context.Account.Id -RoleDefinitionName $FileShareElevatedRole.Name -Scope $scope

Get-AzRoleAssignment -Scope $scope -RoleDefinitionName $FileShareReaderRole.Name
Get-AzRoleAssignment -Scope $scope -RoleDefinitionName $FileShareContributorRole.Name
Get-AzRoleAssignment -Scope $scope -RoleDefinitionName $FileShareElevatedRole.Name

#Remove-AzRoleAssignment -RoleDefinitionName $FileShareReaderRole.Name -Scope $scope -SignInName "k.brunner@alyaconsulting.ch"
#Remove-AzRoleAssignment -RoleDefinitionName $FileShareContributorRole.Name -Scope $scope -SignInName "k.brunner@alyaconsulting.ch"
#Remove-AzRoleAssignment -RoleDefinitionName $FileShareElevatedRole.Name -Scope $scope -SignInName "k.brunner@alyaconsulting.ch"

if ($WithADIntegration)
{
    $keys = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountNameFiles
    $pwdSec = ConvertTo-SecureString -String $keys[0].Value -AsPlainText -Force
    $shareCred = New-Object PSCredential "Azure\$StorageAccountNameFiles", $pwdSec
    New-PSDrive -Name Z -PSProvider FileSystem -Root "\\$StorageAccountNameFiles.file.core.windows.net\$ShareName" -Credential $shareCred
    Get-PSDrive

    $InheritanceFlagContainerAndObject = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $PropagationFlagNone = [System.Security.AccessControl.PropagationFlags]::None
    $AccessTypeAllow = [System.Security.AccessControl.AccessControlType]::Allow 
    $AccessFullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
    $AccessReadExecute = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
    $AccessModify = [System.Security.AccessControl.FileSystemRights]::CreateDirectories -bor [System.Security.AccessControl.FileSystemRights]::CreateFiles -bor [System.Security.AccessControl.FileSystemRights]::AppendData -bor [System.Security.AccessControl.FileSystemRights]::WriteData
    $acl = Get-ACL -Path Z:
    foreach($acc in $acl.Access)
    {
        $acc
        if ($acc.IdentityReference -like "$AlyaLocalDomainName\*")
        {
            $null = $acl.RemoveAccessRule($acc)
        }
    }
    Set-Acl Z:\ $acl
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($admGrpName, $AccessFullControl, $InheritanceFlagContainerAndObject, $PropagationFlagNone, $AccessTypeAllow)
    $acl.SetAccessRule($accessRule)
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($cntGrpName, $AccessModify, $InheritanceFlagContainerAndObject, $PropagationFlagNone, $AccessTypeAllow)
    $acl.SetAccessRule($accessRule)
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($rdrGrpName, $AccessReadExecute, $InheritanceFlagContainerAndObject, $PropagationFlagNone, $AccessTypeAllow)
    $acl.SetAccessRule($accessRule)
    #$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($context.Account.Id, $AccessFullControl, $InheritanceFlagContainerAndObject, $PropagationFlagNone, $AccessTypeAllow)
    #$acl.SetAccessRule($accessRule)
    Set-Acl Z:\ $acl

    Remove-PSDrive -Name Z -Force
}

<#
# Update the password of the AD DS account registered for the storage account
# You may use either kerb1 or kerb2
Update-AzStorageAccountADObjectPassword `
        -RotateToKerbKey kerb2 `
        -ResourceGroupName "<your-resource-group-name-here>" `
        -StorageAccountName "<your-storage-account-name-here>"
#>

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAAXGo61qKrFqMY
# b3e1QrXtbYGop4XCXhiXD5A+VpZH+aCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDCjuDGjuxOV7dX3H
# 9DANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjEzMTYxODAwWhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAqrm7S5R5kmdYT3Q2wIa1m1BQW5EfmzvCg+WYiBY94XQTAxEACqVq
# 4+3K/ahp+8c7stNOJDZzQyLLcZvtLpLmkj4ZqwgwtoBrKBk3ofkEMD/f46P2Iuky
# tvmyUxdM4730Vs6mRvQP+Y6CfsUrWQDgJkiGTldCSH25D3d2eO6PeSdYTA3E3kMH
# BiFI3zxgCq3ZgbdcIn1bUz7wnzxjuAqI7aJ/dIBKDmaNR0+iIhrCFvhDo6nZ2Iwj
# 1vAQsSHlHc6SwEvWfNX+Adad3cSiWfj0Bo0GPUKHRayf2pkbOW922shL1yf/30OV
# yct8rPkMrIKzQhog2R9qJrKJ2xUWwEwiSblWX4DRpdxOROS5PcQB45AHhviDcudo
# 30gx8pjwTeCVKkG2XgdqEZoxdAa4ospWn3va+Dn6OumYkUQZ1EkVhDfdsbCXAJvY
# NCbOyx5tPzeZEFP19N5edi6MON9MC/5tZjpcLzsQUgIbHqFfZiQTposx/j+7m9WS
# aK0cDBfYKFOVQJF576yeWaAjMul4gEkXBn6meYNiV/iL8pVcRe+U5cidmgdUVveo
# BPexERaIMz/dIZIqVdLBCgBXcHHoQsPgBq975k8fOLwTQP9NeLVKtPgftnoAWlVn
# 8dIRGdCcOY4eQm7G4b+lSili6HbU+sir3M8pnQa782KRZsf6UruQpqsCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBT5XqSepeGcYSU4OKwKELHy/3vCoTANBgkq
# hkiG9w0BAQsFAAOCAgEAlSgt2/t+Z6P9OglTt1+sobomrQT0Mb97lGDQZpE364hO
# TSYkbcqxlRXZ+aINgt2WEe7GPFu+6YoZimCPV4sOfk5NZ6I3ZU+uoTsoVYpQr3Io
# zYLLNMWEK2WswPHcxx34Il6F59V/wP1RdB73g+4ZprkzsYNqQpXMv3yoDsPU9IHP
# /w3jQRx6Maqlrjn4OCaE3f6XVxDRHv/iFnipQfXUqY2dV9gkoiYL3/dQX6ibUXqj
# Xk6trvZBQr20M+fhhFPYkxfLqu1WdK5UGbkg1MHeWyVBP56cnN6IobNpHbGY6Eg0
# RevcNGiYFZsE9csZPp855t8PVX1YPewvDq2v20wcyxmPcqStJYLzeirMJk0b9UF2
# hHmIMQRuG/pjn2U5xYNp0Ue0DmCI66irK7LXvziQjFUSa1wdi8RYIXnAmrVkGZj2
# a6/Th1Z4RYEIn1Pc/F4yV9OJAPYN1Mu1LuRiaHDdE77MdhhNW2dniOmj3+nmvWbZ
# fNAI17VybYom4MNB1Cy2gm2615iuO4G6S6kdg8fTaABRh78i8DIgT6LL/yMvbDOH
# hREfFUfowgkx9clsBF1dlAG357pYgAsbS/hqTS0K2jzv38VbhMVuWgtHdwO39ACa
# udnXvAKG9w50/N0DgI54YH/HKWxVyYIltzixRLXN1l+O5MCoXhofW4QhtrofETAx
# ghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBraGWIWdHLNnfmk
# 9EdSfa+Ny3hzxSn5UnDPzU+2qe9wMA0GCSqGSIb3DQEBAQUABIICADshAokwnwU5
# cbvPuankjIeMqEssoOPQUpR/0q6agdzOqT/+3N3TkzuzSaQFJ6kl0zFR/hRkm30X
# 4AEsyVjBIwbwY+UBW8CgoL+3pzWIyuRc/+k4yoPsPvjfbwB3B/kMrOofEGxo7FCJ
# FvlqD+lTfpw71AdMhy26dcOwQOsB0L7TH+xdXT2x5NaQZp3xV+LkwczftxwTW73I
# Ugz2Tk5w/nRa+foQ/VXTPP7EvBTVrJXAK7FfFjYsFW6lAVqVvNaHQPDffxmt105m
# KdL5g4nDwPA/d5KsUcclN0CdpMIvHGb/SD3XD5cNQxCEcZW9tqA8xDNJvVDREWjY
# LiiOGD2PEkjLolddPtZqBAGMf7BzzPR/uyq8Tp8ralXqx1H9RJ49npsIZRPEBEsi
# TNaftx9mibQZVVCZybp3p5NEvMS2tB65w4Fe2uux1lJJrkirMhBy4on2XqRCZ8ms
# EX6yqHV4/KeWFT0pcQikAsp+XHHKObxAoaheCoubZQJjtNM0jBElwgfrBftSE9wV
# F0pAi2wJjuV/EY4cKULZ3FHIPAqJEKi6i+9dfs+e0jnNs2i+sRj2K4WMcDeLS+mz
# Sfotn2A6g3qFKm5jCVbAIukY3DUhqf0o4BaJu/M5gnDgKY20TK4bkbMnpbHQj9ku
# uxAQpIzoCknjVYAA6p72e/1ceCc4ul8roYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCALZrgPwKHoIzhFjuFgHRo0t05o46xuRiNL7U0GLxqL9AIUIOSXit3G35ib
# BOg15zIcl5TCRlwYDzIwMjUwODI1MTUzMDUyWjADAgEBoFikVjBUMQswCQYDVQQG
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
# IKX7WX2Rw5qsxhtjkqDEQaHPDjUI6NtT7vW8k22MiOl8MIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAS23LGUTwpqyV
# wpBhtrv6NdIWJUJGkQe1x22mzSmfjWWhZK41M3vlk3Bj0tXt5J1E+Ig0bNfUZpvU
# tsXOw8bYeYmQq8iaHLZvrwPaNaqS50AOqZR8s/wf+omkSBvlp6Svr1RrZp2/ji2A
# 3qjYS29asSLg2nt/t7Sitoie+pyf5NuvT4WB0yAYLmuWEAbz3AGlMIW7UHKrEzV6
# ArPqykC31jPapCbGoO94bzqVQBxihZccDfJJhEAibVKzo9BFdXwyLlqHgkLHy3On
# mERNsem9qaO/0TdM1hZB6C4w5ySy9WYdd0smeHjEdJpQcICXnRdBgDzkf19oWsqE
# cKp0hStrwQQTStmX6ow1oK9sc0DSo5TqDYELYPKwUQVBhZEgxJ3R9TXOjMBa4uQL
# JmBKWbG4y3F71CGBl5cQ+akrdNqTqAc1zJZ/QA6z0pWGD3cu1n6P9E3ojUHL4Fqp
# Q7vq3N6vlbXUGnAir78NgE8vTcRhnaqrYTvJTl9icpMznWmlVptw
# SIG # End signature block
