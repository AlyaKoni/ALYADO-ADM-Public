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
