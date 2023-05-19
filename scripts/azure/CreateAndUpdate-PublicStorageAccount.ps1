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
    27.02.2020 Konrad Brunner       Initial Version
	16.08.2021 Konrad Brunner		Added provider registration
	20.04.2023 Konrad Brunner		Changed Mime Mapping function for PS7

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\CreateAndUpdate-PublicStorageAccount-$($AlyaTimeString).log" | Out-Null

# Constants
$ResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
$StorageAccountName = "$($AlyaNamingPrefix)strg$($AlyaResIdPublicStorage)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Storage"

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

# Checking resource provider registration
Write-Host "Checking resource provider registration Microsoft.Storage" -ForegroundColor $CommandInfo
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

# Checking ressource group
Write-Host "Checking ressource group" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    Write-Warning "Ressource Group not found. Creating the Ressource Group $ResourceGroupName"
    $ResGrp = New-AzResourceGroup -Name $ResourceGroupName -Location $AlyaLocation -Tag @{displayName="Main Infrastructure Services";ownerEmail=$Context.Account.Id}
}

# Checking storage account
Write-Host "Checking storage account" -ForegroundColor $CommandInfo
$StrgAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
if (-Not $StrgAccount)
{
    Write-Warning "Storage account not found. Creating the storage account $StorageAccountName"
    $StrgAccount = New-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName -Location $AlyaLocation -SkuName "Standard_LRS" -Kind StorageV2 -AccessTier Hot -Tag @{displayName="Public Storage"}
    if (-Not $StrgAccount)
    {
        Write-Error "Storage account $StorageAccountName creation failed. Please fix and start over again" -ErrorAction Continue
        Exit 1
    }
}
$StrgKeys = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
$StrgContext = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StrgKeys[0].Value

# Checking CORS rules
Write-Host "Checking CORS rules" -ForegroundColor $CommandInfo
$StrgCorsRules = Get-AzStorageCORSRule -Context $StrgContext -ServiceType Blob -ErrorAction SilentlyContinue
if (-Not $StrgCorsRules)
{
    Write-Warning "No CORS rules found. Creating the CORS rules."
    $retries = 20
    do
    {
        Start-Sleep -Seconds 10
        $CorsRules = (@{
            AllowedHeaders=@("x-ms-blob-content-type","x-ms-blob-content-disposition");
            AllowedOrigins=@("$($AlyaSharePointUrl)", "$($AlyaWebPage)");
            MaxAgeInSeconds=30;
            AllowedMethods=@("Get","Connect")})
        try
        {
            $StrgCorsRules = Set-AzStorageCORSRule -Context $StrgContext -ServiceType Blob -CorsRules $CorsRules
        } catch {}
        $StrgCorsRules = Get-AzStorageCORSRule -Context $StrgContext -ServiceType Blob
        $retries--
        if ($retries -lt 0)
        {
            throw "CORS rules creation failed. Please fix and start over again"
        }
    }
    while (-Not $StrgCorsRules)
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
        $retries = 20
        do
        {
            Start-Sleep -Seconds 10
            $CorsRules = (@{
                AllowedHeaders=@("x-ms-blob-content-type","x-ms-blob-content-disposition");
                AllowedOrigins=@("$($AlyaSharePointUrl)", "$($AlyaWebPage)");
                MaxAgeInSeconds=30;
                AllowedMethods=@("Get","Connect")})
            try
            {
                $StrgCorsRules = Set-AzStorageCORSRule -Context $StrgContext -ServiceType Blob -CorsRules $CorsRules
            } catch {}
            $StrgCorsRules = Get-AzStorageCORSRule -Context $StrgContext -ServiceType Blob
            $retries--
            if ($retries -lt 0)
            {
                throw "CORS rules creation failed. Please fix and start over again"
            }
        }
        while (-Not $StrgCorsRules)
        if (-Not $StrgCorsRules)
        {
            Write-Error "CORS rules creation failed. Please fix and start over again" -ErrorAction Continue
            Exit 1
        }
    }
}

$BlobPublicRoot = "$AlyaData\azure\publicStorage"
$containers = Get-ChildItem -Path $BlobPublicRoot | Where-Object { $_.PSIsContainer }
foreach($container in $containers)
{
    $StorageContainerName = $container.Name
    $BlobContainerRoot = $container.FullName

    # Checking container
    Write-Host "Checking container $StorageContainerName" -ForegroundColor $CommandInfo
    $StrgKeys = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
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
    foreach($SourceFile in $UploadItems)
    {
        #$SourceFile = $UploadItems[0]
        $relPath = $SourceFile.FullName.Replace($BlobContainerRoot, "")
        Write-Host "  - $relPath"
        $mime = Get-MimeType -Extension (Get-Item $SourceFile.FullName).Extension -ErrorAction SilentlyContinue
        if ($null -eq $mime) { $mime = "application/octet-stream" }
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
