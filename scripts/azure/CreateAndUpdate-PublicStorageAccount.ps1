#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

    This file is part of the Alya Base Configuration.
    The Alya Base Configuration is free software: you can redistribute it
	and/or modify it under the terms of the GNU General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
	Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
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
    27.02.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\CreateAndUpdate-PublicStorageAccount-$($AlyaTimeString).log" | Out-Null

# Constants
$RessourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
$StorageAccountName = "$($AlyaNamingPrefix)strg$($AlyaResIdPublicStorage)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Azure | CreateAndUpdate-PublicStorageAccount | AZURE" -ForegroundColor $CommandInfo
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
$ResGrp = Get-AzResourceGroup -Name $RessourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    Write-Warning "Ressource Group not found. Creating the Ressource Group $RessourceGroupName"
    $ResGrp = New-AzResourceGroup -Name $RessourceGroupName -Location $AlyaLocation -Tag @{displayName="Main Infrastructure Services";ownerEmail=$Context.Account.Id}
}

# Checking storage account
Write-Host "Checking storage account" -ForegroundColor $CommandInfo
$StrgAccount = Get-AzStorageAccount -ResourceGroupName $RessourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
if (-Not $StrgAccount)
{
    Write-Warning "Storage account not found. Creating the storage account $StorageAccountName"
    $StrgAccount = New-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $RessourceGroupName -Location $AlyaLocation -SkuName "Standard_LRS" -Kind BlobStorage -AccessTier Hot -Tag @{displayName="Public Storage"}
    if (-Not $StrgAccount)
    {
        Write-Error "Storage account $StorageAccountName creation failed. Please fix and start over again" -ErrorAction Continue
        Exit 1
    }
}
$StrgContext = New-AzStorageContext -StorageAccountName $StorageAccountName

# Checking CORS rules
Write-Host "Checking CORS rules" -ForegroundColor $CommandInfo
$StrgCorsRules = Get-AzStorageCORSRule -Context $StrgContext -ServiceType Blob
if (-Not $StrgCorsRules)
{
    Write-Warning "No CORS rules found. Creating the CORS rules."
    $CorsRules = (@{
        AllowedHeaders=@("x-ms-blob-content-type","x-ms-blob-content-disposition");
        AllowedOrigins=@("$($AlyaSharePointUrl)", "$($AlyaWebPage)");
        MaxAgeInSeconds=30;
        AllowedMethods=@("Get","Connect")})
    $StrgCorsRules = Set-AzStorageCORSRule -Context $StrgContext -ServiceType Blob -CorsRules $CorsRules
    $StrgCorsRules = Get-AzStorageCORSRule -Context $StrgContext -ServiceType Blob
    if (-Not $StrgCorsRules)
    {
        Write-Error "CORS rules creation failed. Please fix and start over again" -ErrorAction Continue
        Exit 1
    }
}
else
{
    $ruleFound = $false
    foreach($CorsRule in $CorsRules)
    {
        if ($CorsRule.AllowedOrigins -contains "$($AlyaSharePointUrl)")
        {
            $ruleFound = $true
        }
    }
    if (-Not $ruleFound)
    {
        $CorsRules = (@{
            AllowedHeaders=@("x-ms-blob-content-type","x-ms-blob-content-disposition");
            AllowedOrigins=@("$($AlyaSharePointUrl)", "$($AlyaWebPage)");
            MaxAgeInSeconds=30;
            AllowedMethods=@("Get","Connect")})
        $StrgCorsRules = Set-AzStorageCORSRule -Context $StrgContext -ServiceType Blob -CorsRules $CorsRules
        $StrgCorsRules = Get-AzStorageCORSRule -Context $StrgContext -ServiceType Blob
        if (-Not $StrgCorsRules)
        {
            Write-Error "CORS rules creation failed. Please fix and start over again" -ErrorAction Continue
            Exit 1
        }
    }
}

$BlobPublicRoot = "$AlyaData\azure\publicStorage"
$containers = Get-ChildItem -Path $BlobPublicRoot | where { $_.PSIsContainer }
foreach($container in $containers)
{
    $StorageContainerName = $container.Name
    $BlobContainerRoot = $container.FullName

    # Checking container
    Write-Host "Checking container $StorageContainerName" -ForegroundColor $CommandInfo
    $StrgKeys = Get-AzStorageAccountKey -ResourceGroupName $RessourceGroupName -Name $StorageAccountName
    $StrgKey = $StrgKeys.GetValue(0).Value
    $StrgContext = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StrgKey
    $PublicContainer = Get-AzStorageContainer -Context $StrgContext -Name $StorageContainerName -ErrorAction SilentlyContinue
    if (-Not $PublicContainer)
    {
        Write-Warning "Container not found. Creating the storage account container '$StorageContainerName'"
        $StrgContainer = New-AzStorageContainer -Context $StrgContext -Name $StorageContainerName -Permission Blob
        if (-Not $StrgContainer)
        {
            Write-Error "Storage account container '$StorageContainerName' creation failed. Please fix and start over again" -ErrorAction Continue
            Exit 1
        }
    }

    # Updating blobs
    Write-Host "Updating blobs" -ForegroundColor $CommandInfo
    Write-Host "  from $BlobContainerRoot"
    $UploadItems = Get-ChildItem -Path $BlobContainerRoot -Recurse -Force -File
    $md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
    Add-Type -AssemblyName "System.Web"
    foreach($SourceFile in $UploadItems)
    {
        #$SourceFile = $UploadItems[0]
        $relPath = $SourceFile.FullName.Replace($BlobContainerRoot, "")
        Write-Host "  - $relPath"
        $mime = [System.Web.MimeMapping]::GetMimeMapping($SourceFile.FullName)
        if (-Not $mime)
        {
            $mime = "application/octet-stream"
        }
        $BlobName = $relPath.Substring(1)
        $DestinationBlob = Get-AzStorageBlob -Context $StrgContext -Container $StorageContainerName -Blob $BlobName -ErrorAction SilentlyContinue
        if ($DestinationBlob)
        {
            if ($SourceFile.Length -gt (2*1024*1024*1024))
            {
                #TODO hash only works for up to 2GB, switch to change date if bigger
                Write-Error "File is too big for md5 hash. Please update this script!" -ErrorAction Continue
                continue
            }
            $hash = [System.Convert]::ToBase64String($md5.ComputeHash([System.IO.File]::ReadAllBytes($SourceFile.FullName)))
            $DestinationBlob.ICloudBlob.FetchAttributes()
            if ($DestinationBlob.ICloudBlob.Properties.ContentMD5 -ne $hash)
            {
			    Write-Host "    + Creating Snapshot"
			    $Tmp = $DestinationBlob.ICloudBlob.CreateSnapshot()
		        Write-Host "    + Copying blob"
                $DestinationBlob = Set-AzStorageBlobContent -File $SourceFile.FullName -Context $StrgContext -Container $StorageContainerName -Blob $BlobName -Force
            }
            $DestinationBlob.ICloudBlob.FetchAttributes()
            if ($DestinationBlob.ICloudBlob.Properties.ContentType -ne $mime)
            {
			    Write-Host "    + Changing mime to $($mime)"
                $DestinationBlob.ICloudBlob.Properties.ContentType = $mime
			    $DestinationBlob.ICloudBlob.SetProperties()
            }
        }
        else
        {
		    Write-Host "    + Copying blob"
            $DestinationBlob = Set-AzStorageBlobContent -File $SourceFile.FullName -Context $StrgContext -Container $StorageContainerName -Blob $BlobName -Force
            if ($DestinationBlob.ICloudBlob.Properties.ContentType -ne $mime)
            {
			    Write-Host "    + Changing mime to $($mime)"
                $DestinationBlob.ICloudBlob.Properties.ContentType = $mime
			    $DestinationBlob.ICloudBlob.SetProperties()
            }
        }

    }
}

#Stopping Transscript
Stop-Transcript