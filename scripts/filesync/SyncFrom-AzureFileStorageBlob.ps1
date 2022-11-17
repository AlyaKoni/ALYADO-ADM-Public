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
    $ToLocalDir = "C:\Users\KonradBrunner\OneDrive - Alya Consulting Inh. Konrad Brunner\Desktop\Source\ALYADO-ADM-CloudConfiguration\data\azure\publicStorage\corporate",
    $FromStorageBlobContainer = "corporate",
    $StorageResourceGroupName = $null, # Main infra by default
    $StorageAccountName = $null # Public Storage by default
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\filesync\SyncFrom-AzureFileStorageBlob-$($AlyaTimeString).log" | Out-Null

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
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Storage"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "FileSync | SyncFrom-AzureFileStorageBlob | AZURE" -ForegroundColor $CommandInfo
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
$StrgKeys = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName
$StrgContext = New-AzStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StrgKeys[0].Value

# Checking alyaconsulting Blob
Write-Host "Checking blob container" -ForegroundColor $CommandInfo
$SourceContainer = Get-AzStorageContainer -Context $StrgContext -Name $FromStorageBlobContainer -ErrorAction SilentlyContinue
if (-Not $SourceContainer)
{
    Write-Warning "Container not found. Creating the container '$FromStorageBlobContainer'"
    $SourceContainer = New-AzStorageContainer -Context $StrgContext -Name $FromStorageBlobContainer -Permission Blob
    if (-Not $SourceContainer)
    {
        Write-Error "Storage account container '$FromStorageBlobContainer' creation failed. Please fix and start over again" -ErrorAction Continue
        Exit 1
    }
}

# Main
$OwnerRole = Get-AzRoleAssignment -Scope $StrgAccount.Id -SignInName (Get-AzContext).Account.Id | where { $_.RoleDefinitionName -eq "Storage Blob Data Owner" }
if (-Not $ReaderRole)
{
    $OwnerRole = New-AzRoleAssignment -Scope $StrgAccount.Id -SignInName (Get-AzContext).Account.Id -RoleDefinitionName "Storage Blob Data Owner"
    do
    {
        $OwnerRole = Get-AzRoleAssignment -Scope $StrgAccount.Id -SignInName (Get-AzContext).Account.Id | where { $_.RoleDefinitionName -eq "Storage Blob Data Owner" }
        Start-Sleep -Seconds 5
    } while (-Not $OwnerRole)
}
$SourceBlobs = Get-AzStorageBlob -Context $StrgContext -Container $FromStorageBlobContainer
$md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
foreach($SourceBlob in $SourceBlobs)
{
    if (-Not $SourceBlob.IsDeleted)
    {
        #$SourceBlob = $SourceBlobs[0
        $relPath = $SourceBlob.Name.Replace("/", "\")
        if ($SourceBlob.SnapshotTime)
        {
            continue
        }
        else
        {
            Write-Host "  - $relPath"
        }
        $SourceBlob = Get-AzStorageBlob -Context $StrgContext -Container $ToStorageBlobContainer -Blob $SourceBlob.Name
        $absPath = [IO.Path]::Combine($ToLocalDir, $relPath)
        $DestFile = get-Item -Path $absPath
        $copyFile = $false
        if (-Not $DestFile.Exists)
        {
            $copyFile = $true
        }
        else
        {
            $hash = [System.Convert]::ToBase64String($md5.ComputeHash([System.IO.File]::ReadAllBytes($DestFile.FullName)))
            $SourceBlob.ICloudBlob.FetchAttributes()
            if ($SourceBlob.ICloudBlob.Properties.ContentMD5 -ne $hash)
            {
                $copyFile = $true
            }
        }
        if ($copyFile)
        {
		    Write-Host "    + Copying file"
            Get-AzStorageBlobContent -CloudBlob $SourceBlob.ICloudBlob -Destination $absPath -Force
        }
    }
}

#TODO Clean part

#Stopping Transscript
Stop-Transcript
