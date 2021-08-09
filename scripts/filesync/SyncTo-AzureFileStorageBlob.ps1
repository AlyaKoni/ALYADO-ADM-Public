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
    08.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    #$FromLocalDir = "X:\data\azure\publicStorage\corporate",
    $FromLocalDir = "C:\Users\KonradBrunner\OneDrive - Alya Consulting Inh. Konrad Brunner\Desktop\Source\ALYADO-ADM-CloudConfiguration\data\azure\publicStorage\corporate",
    $ToStorageBlobContainer = "corporate",
    $StorageResourceGroupName = $null, # Main infra by default
    $StorageAccountName = $null # Public Storage by default
)

#Checking parameters
if (-Not (Test-Path $FromLocalDir))
{
    Write-Error "FromLocalDir '$($FromLocalDir)' does not exist" -ErrorAction Continue
    exit
}

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\filesync\SyncTo-AzureFileStorageBlob-$($AlyaTimeString).log" | Out-Null

# Constants
if (-Not $StorageResourceGroupName)
{
    $StorageResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdMainInfra)"
}
if (-Not $StorageAccountName)
{
    $StorageAccountName = "$($AlyaNamingPrefix)strg$($AlyaResIdPublicStorage)"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "FileSync | SyncTo-AzureFileStorageBlob | AZURE" -ForegroundColor $CommandInfo
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
$ResGrp = Get-AzResourceGroup -Name $StorageResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    throw "Ressource Group not found. Please create the Ressource Group $StorageResourceGroupName"
}

# Checking storage account
Write-Host "Checking storage account" -ForegroundColor $CommandInfo
$StrgAccount = Get-AzStorageAccount -ResourceGroupName $StorageResourceGroupName -Name $StorageAccountName -ErrorAction SilentlyContinue
if (-Not $StrgAccount)
{
    throw "Storage account not found. Please create the storage account $StorageAccountName"
}
$StrgContext = New-AzStorageContext -StorageAccountName $StorageAccountName

# Checking alyaconsulting Blob
Write-Host "Checking blob container" -ForegroundColor $CommandInfo
$DestinationContainer = Get-AzStorageContainer -Context $StrgContext -Name $ToStorageBlobContainer -ErrorAction SilentlyContinue
if (-Not $DestinationContainer)
{
    Write-Warning "Container not found. Creating the container '$ToStorageBlobContainer'"
    $DestinationContainer = New-AzStorageContainer -Context $StrgContext -Name $ToStorageBlobContainer -Permission Blob
    if (-Not $DestinationContainer)
    {
        Write-Error "Storage account container '$ToStorageBlobContainer' creation failed. Please fix and start over again" -ErrorAction Continue
        Exit 1
    }
}

# Main
Write-Host "Updating blobs" -ForegroundColor $CommandInfo
Write-Host "  from $FromLocalDir"
$UploadItems = Get-ChildItem -Path $FromLocalDir -Recurse -File -Force
$md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
Add-Type -AssemblyName "System.Web"
foreach($SourceFile in $UploadItems)
{
    #$SourceFile = $UploadItems[0]
    $relPath = $SourceFile.FullName.Replace($FromLocalDir, "")
    Write-Host "  - $relPath"
    $mime = [System.Web.MimeMapping]::GetMimeMapping($SourceFile.FullName)
    if ($SourceFile.FullName.EndsWith(".json")) { $mime = "application/json" }
    if ($SourceFile.FullName.EndsWith(".svg")) { $mime = "image/svg+xml" }
    $BlobName = $relPath.Substring(1)
    $DestinationBlob = Get-AzStorageBlob -Context $StrgContext -Container $ToStorageBlobContainer -Blob $BlobName -ErrorAction SilentlyContinue | where { -Not $_.SnapshotTime }
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
            $DestinationBlob = Set-AzStorageBlobContent -File $SourceFile.FullName -Context $StrgContext -Container $ToStorageBlobContainer -Blob $BlobName -Force
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
        $DestinationBlob = Set-AzStorageBlobContent -File $SourceFile.FullName -Context $StrgContext -Container $ToStorageBlobContainer -Blob $BlobName -Force
        if ($DestinationBlob.ICloudBlob.Properties.ContentType -ne $mime)
        {
			Write-Host "    + Changing mime to $($mime)"
            $DestinationBlob.ICloudBlob.Properties.ContentType = $mime
			$DestinationBlob.ICloudBlob.SetProperties()
        }
    }

}

#TODO Clean part

#Stopping Transscript
Stop-Transcript