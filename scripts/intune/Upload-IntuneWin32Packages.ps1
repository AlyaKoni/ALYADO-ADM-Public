﻿#Requires -Version 2.0

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
    30.09.2020 Konrad Brunner       Initial Version
    23.10.2021 Konrad Brunner       Added apps path
    24.04.2023 Konrad Brunner       Switched to Graph
    21.09.2023 Konrad Brunner       Version check
    12.12.2023 Konrad Brunner       Removed $filter odata query, was throwing bad request

#>

[CmdletBinding()]
Param(
    [string]$UploadOnlyAppWithName = $null,
    [string]$ContinueAtAppWithName = $null,
    [string]$AppsPath = "Win32Apps",
    [bool]$AskForSameVersionPackages = $true,
    [bool]$ShowProgressBar = $false
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Upload-IntuneWin32Packages-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
$AppPrefix = "WIN "
if (-Not [string]::IsNullOrEmpty($AlyaAppPrefix)) {
    $AppPrefix = "$AlyaAppPrefix "
}
$DataRoot = Join-Path (Join-Path $AlyaData "intune") $AppsPath
if (-Not (Test-Path $DataRoot))
{
    $null = New-Item -Path $DataRoot -ItemType Directory -Force
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"

# Logins
LoginTo-MgGraph -Scopes @(
    "Directory.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementServiceConfig.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementApps.ReadWrite.All"
)

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Upload-IntuneWin32Packages | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Functions
function UploadPackage($packageInfo, $app, $appConfig, $bytes)
{
    write-host "  Memory used: $([System.GC]::GetTotalMemory($true))"
    $detectVersion = $null

    # Checking existing failed upload
    Write-Host "  Checking existing failed upload"
	$appId = $app.id
    Write-Host "    appId: $($app.id)"
    $comittedVersion = $app.committedContentVersion
    if ($comittedVersion -gt 0)
    {
        $uri = "/beta/deviceAppManagement/mobileApps/$appId/Microsoft.Graph.win32LobApp/contentVersions"
        $existVersions = Get-MsGraphCollection -Uri $uri
        $maxVersion = ($existVersions.Id | Measure-Object -Maximum).Maximum
        $uri = "/beta/deviceAppManagement/mobileApps/$appId/Microsoft.Graph.win32LobApp/contentVersions/$maxVersion/files"
        $file = Get-MsGraphCollection -Uri $uri
        if ($file -and -Not $file.isCommitted)
        {
            Write-Warning "Existing failed upload found! So far, we don't know how to fix such stuff. Please wait and try later!"
            pause
            return
        }
    }

    # Checking Version
    Write-Host "  Checking Version '$($app.displayName)'"
    if ($comittedVersion -gt 0 -and $null -eq $detectVersion -and $null -ne $app.detectionRules -and $null -ne $app.detectionRules[0] -and $null -ne $app.detectionRules[0].detectionValue)
    {
        $detectVersion = [Version]$app.detectionRules[0].detectionValue
    }
    else
    {
        if (-Not [string]::IsNullOrEmpty($app.displayVersion))
        {
            $detectVersion = [Version]$app.displayVersion
        }
    }
    $doUpload = $true
    if ($comittedVersion -gt 0 -and $detectVersion -ge [Version]$version)
    {
        Write-Host "    Looks like this version has already been uploaded!" -ForegroundColor $CommandWarning
        Write-Host "      Existing version: $($detectVersion)" -ForegroundColor $CommandWarning
        Write-Host "      Version to upload: $($version)" -ForegroundColor $CommandWarning
        if ($AskForSameVersionPackages -eq $false)
        {
            $doUpload = $false
        }
        else
        {
            $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes","Upload anyway."
            $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No","Don't upload."
            $options = [System.Management.Automation.Host.ChoiceDescription[]]($no, $yes)
            $resp = $host.UI.PromptForChoice("Question", "Uploading anyway?", $options, 0)
            if ($resp -eq 0) { $doUpload = $false }
        }
    }

    if ($doUpload)
    {
        $attr = Get-Member -InputObject $appConfig -MemberType NoteProperty -Name "committedContentVersion" -ErrorAction SilentlyContinue
        if ($attr) { $appConfig.PSObject.Properties.Remove("committedContentVersion") }

        # Creating Content Version
        Write-Host "  Creating Content Version '$($app.displayName)'"
        $uri = "/beta/deviceAppManagement/mobileApps/$appId/Microsoft.Graph.win32LobApp/contentVersions"
        $contentVersion = Post-MsGraph -Uri $uri -Body "{}"
        Write-Host "    contentVersion: $($contentVersion.id)"

        # Creating Content Version file
        Write-Host "  Creating Content Version file"
        $fileBody = @{ "@odata.type" = "#Microsoft.Graph.mobileAppContentFile" }
        $fileBody.name = $package.Name
        $fileBody.size = [long]$packageInfo.ApplicationInfo.UnencryptedContentSize
        $fileBody.sizeInBytes = [long]$packageInfo.ApplicationInfo.UnencryptedContentSize
        $fileBody.sizeEncrypted = [long]$bytes.Length
        $fileBody.sizeEncryptedInBytes = [long]$bytes.Length
        $fileBody.manifest = $null
        $fileBody.isDependency = $false
        $uri = "/beta/deviceAppManagement/mobileApps/$appId/Microsoft.Graph.win32LobApp/contentVersions/$($contentVersion.id)/files"
        $file = Post-MsGraph -Uri $uri -Body ($fileBody | ConvertTo-Json -Depth 50)

        # Waiting for file uri
        Write-Host "  Waiting for file uri '$($app.displayName)'"
        $uri = "/beta/deviceAppManagement/mobileApps/$appId/Microsoft.Graph.win32LobApp/contentVersions/$($contentVersion.id)/files/$($file.id)"
        $stage = "AzureStorageUriRequest"
        $successState = "$($stage)Success"
        $pendingState = "$($stage)Pending"
        $failedState = "$($stage)Failed"
        $timedOutState = "$($stage)TimedOut"
        $Global:attempts = 100
        while ($Global:attempts -gt 0)
        {
            Start-Sleep -Seconds 3
            $file = Get-MsGraphObject -Uri $uri
            if ($file.uploadState -eq $successState)
            {
                break
            }
            elseif ($file.uploadState -ne $pendingState)
            {
                throw "Get file uri state has not succeeded: $($file.uploadState)"
            }
            $Global:attempts--
        }
        if ($file -eq $null -or $file.uploadState -ne $successState)
        {
            throw "File request did not complete within $Global:attempts attempts"
        }

        # Uploading intunewin content
        Write-Host "  Uploading intunewin content '$($app.displayName)'"
        if ($ShowProgressBar)
        {
            $OldProgressPreference = $ProgressPreference
            $ProgressPreference = "Continue"
        }
        Start-Sleep -Seconds 10 # first chunk has often 403
        $chunkSizeInBytes = 1024 * 1024 * 6
        $sasRenewalTimer = [System.Diagnostics.Stopwatch]::StartNew()
        $chunks = [Math]::Ceiling($bytes.Length / $chunkSizeInBytes)
        $enc = [System.Text.Encoding]::GetEncoding("iso-8859-1")
        $ids = @()
        for ($chunk = 0; $chunk -lt $chunks; $chunk++)
        {
            [system.gc]::Collect()
            $id = [System.Convert]::ToBase64String($enc.GetBytes($chunk.ToString("0000")))
            $ids += $id
            $start = $chunk * $chunkSizeInBytes
            $end = [Math]::Min($start + $chunkSizeInBytes - 1, $bytes.Length - 1)
            $encodedBody = $enc.GetString($bytes[$start..$end])
            $headers = @{
                "x-ms-blob-type" = "BlockBlob"
                "x-ms-blob-content-encoding" = "iso-8859-1"
                "Content-Type" = "text/plain; charset=iso-8859-1"
            }
            $currentChunk = $chunk + 1
            Write-Host "    Uploading chunk $currentChunk of $chunks ($([int]$sasRenewalTimer.Elapsed.TotalSeconds)sec)"
            if ($ShowProgressBar)
            {
                Write-Progress -Activity "    Uploading intunewin from $($package.Name)" -status "      Uploading chunk $currentChunk of $chunks" -percentComplete ($currentChunk / $chunks*100)
            }
            $curi = "$($file.azureStorageUri)&comp=block&blockid=$id"
            $Global:attempts = 10
            while ($Global:attempts -ge 0)
            {
                try {
                    do {
                        try {
                            $response = Invoke-WebRequestIndep -Uri $curi -Method Put -Headers $headers -Body $encodedBody
                            $StatusCode = $response.StatusCode
                        } catch {
                            $StatusCode = $_.Exception.Response.StatusCode.value__
                            if ($StatusCode -eq 429 -or $StatusCode -eq 503) {
                                Write-Warning "Got throttled by Microsoft. Sleeping for 45 seconds..."
                                Start-Sleep -Seconds 45
                            }
                            else {
                                try { Write-Host ($_.Exception | ConvertTo-Json -Depth 2) -ForegroundColor $CommandError } catch {}
                                throw
                            }
                        }
                    } while ($StatusCode -eq 429 -or $StatusCode -eq 503)
                    $Global:attempts = -1
                } catch {
                    Write-Host "Catched exception $($_.Exception.Message)" -ForegroundColor $CommandError
                    Write-Host "Retrying $Global:attempts times" -ForegroundColor $CommandError
                    $Global:attempts--
                    if ($Global:attempts -lt 0) { throw }
                    Start-Sleep -Seconds 10
                }
            }
            if ($currentChunk -lt $chunks -and $sasRenewalTimer.ElapsedMilliseconds -ge 450000)
            {
                Write-Host "    Upload renewal"
                $renewalUri = "$uri/renewUpload"
                $rewnewUriResult = Post-MsGraph -Uri $renewalUri
                # $stage = "AzureStorageUriRenewal"
                # $successState = "$($stage)Success"
                # $pendingState = "$($stage)Pending"
                # $Global:attempts = 10
                # while ($Global:attempts -gt 0)
                # {
                #     Start-Sleep -Seconds 3
                #     $file = Get-MsGraphObject -Uri $uri
                #     if ($file.uploadState -eq $successState)
                #     {
                #         break
                #     }
                #     elseif ($file.uploadState -ne $pendingState)
                #     {
                #         throw "Upload renewal state has not succeeded: $($file.uploadState)"
                #     }
                #     $Global:attempts--
                # }
                # if ($file -eq $null -or $file.uploadState -ne $successState)
                # {
                #     throw "File request renewel did not complete within $Global:attempts attempts"
                # }
                $sasRenewalTimer.Restart()
            }
            $encodedBody = $null
        }
        if ($ShowProgressBar)
        {
            Write-Progress -Completed -Activity "    Uploading intunewin"
            $ProgressPreference = $OldProgressPreference
        }

        # Finalize the upload.
        Write-Host "  Finalizing the upload '$($app.displayName)'"
        $curi = "$($file.azureStorageUri)&comp=blocklist"
        $xml = '<?xml version="1.0" encoding="utf-8"?><BlockList>'
        foreach ($id in $ids)
        {
            $xml += "<Latest>$id</Latest>"
        }
        $xml += '</BlockList>'
        do {
            try {
                $response = Invoke-WebRequestIndep -Uri $curi -Method Put -Body $xml -ContentType "application/xml"
                $StatusCode = $response.StatusCode
            } catch {
                $StatusCode = $_.Exception.Response.StatusCode.value__
                if ($StatusCode -eq 429 -or $StatusCode -eq 503) {
                    Write-Warning "Got throttled by Microsoft. Sleeping for 45 seconds..."
                    Start-Sleep -Seconds 45
                }
                else {
                    try { Write-Host ($_.Exception | ConvertTo-Json -Depth 2) -ForegroundColor $CommandError } catch {}
                    throw
                }
            }
        } while ($StatusCode -eq 429 -or $StatusCode -eq 503)

        # Committing the file
        Write-Host "  Committing the file '$($app.displayName)'"
        $fileEncryptionInfo = @{}
        $fileEncryptionInfo.fileEncryptionInfo = @{
            encryptionKey        = $packageInfo.ApplicationInfo.EncryptionInfo.EncryptionKey
            macKey               = $packageInfo.ApplicationInfo.EncryptionInfo.MacKey
            initializationVector = $packageInfo.ApplicationInfo.EncryptionInfo.InitializationVector
            mac                  = $packageInfo.ApplicationInfo.EncryptionInfo.Mac
            profileIdentifier    = $packageInfo.ApplicationInfo.EncryptionInfo.ProfileIdentifier
            fileDigest           = $packageInfo.ApplicationInfo.EncryptionInfo.FileDigest
            fileDigestAlgorithm  = $packageInfo.ApplicationInfo.EncryptionInfo.FileDigestAlgorithm
        }
        $curi = "/beta/deviceAppManagement/mobileApps/$appId/Microsoft.Graph.win32LobApp/contentVersions/$($contentVersion.id)/files/$($file.id)/commit"
        $file = Post-MsGraph -Uri $curi -Body ($fileEncryptionInfo | ConvertTo-Json -Depth 50)

        # Waiting for file commit
        Write-Host "  Waiting for file commit '$($app.displayName)'"
        $stage = "CommitFile"
        $successState = "$($stage)Success"
        $pendingState = "$($stage)Pending"
        $failedState = "$($stage)Failed"
        $timedOutState = "$($stage)TimedOut"
        $Global:attempts = 100
        while ($Global:attempts -gt 0)
        {
            Start-Sleep -Seconds 3
            $file = Get-MsGraphObject -Uri $uri
            if ($file.uploadState -eq $successState)
            {
                break
            }
            elseif ($file.uploadState -ne $pendingState)
            {
                throw "File upload state has not succeeded: $($file.uploadState)"
            }
            $Global:attempts--
        }
        if ($file -eq $null -or $file.uploadState -ne $successState)
        {
            throw "File request commit did not complete within $Global:attempts attempts"
        }
        Add-Member -InputObject $appConfig -MemberType NoteProperty -Name "committedContentVersion" -Value $contentVersion.id
    }

    # Committing the app
    Write-Host "  Committing the app '$($app.displayName)'"
    $uri = "/beta/deviceAppManagement/mobileApps/$appId"
    $appP = Patch-MsGraph -Uri $uri -Body ($appConfig | ConvertTo-Json -Depth 50)
}

# Main
$packages = Get-ChildItem -Path $DataRoot -Directory
$continue = $true
foreach($packageDir in $packages)
{
    if ($ContinueAtAppWithName -and $packageDir.Name -eq $ContinueAtAppWithName) { $continue = $false }
    if ($ContinueAtAppWithName -and $continue) { continue }
    if ($UploadOnlyAppWithName -and $packageDir.Name -ne $UploadOnlyAppWithName) { continue }
    if ($packageDir.Name -like "*unused*" -or $packageDir.Name -like "*donotuse*") { continue }

    [system.gc]::Collect()
    Write-Host "Uploading package $($packageDir.Name)" -ForegroundColor $CommandInfo

    $packagePath = Join-Path $packageDir.FullName "Package"
    $configPath = Join-Path $packageDir.FullName "config.json"
    $contentPath = Join-Path $packageDir.FullName "Content"
    $requirementDetectionPath = Join-Path $packageDir.FullName "RequirementDetection.ps1"

    # Checking intunewin package
    Write-Host "  Checking intunewin package"
    $package = Get-ChildItem -Path $packagePath -Filter "*.intunewin"
    if (-Not $package)
    {
        Write-Error "Can't find Intune package!" -ErrorAction Continue
        continue
    }
    if ($package.Count -gt 1)
    {
        Write-Error "Found more than 1 Intune packages!" -ErrorAction Continue
        Write-Error "Please delete older once and rerun" -ErrorAction Continue
        pause
        continue
    }

    # Extracting package information
    Write-Host "  Extracting package information"
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($package.FullName)
    $entry = $zip.Entries | Where-Object { $_.Name -eq "Detection.xml" }
    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, "$($package.FullName).Detection.xml", $true)
    $zip.Dispose()
    $packageInfo = [xml](Get-Content -Path "$($package.FullName).Detection.xml" -Raw -Encoding $AlyaUtf8Encoding)
    Remove-Item -Path "$($package.FullName).Detection.xml" -Force

    # Reading and preparing app configuration
    Write-Host "  Reading and preparing app configuration"
    $appConfig = Get-Content -Path $configPath -Raw -Encoding $AlyaUtf8Encoding
    $appConfig = $appConfig | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty isAssigned,dependentAppCount,supersedingAppCount,supersededAppCount,committedContentVersion,size,id,createdDateTime,lastModifiedDateTime,version,'@odata.context',uploadState,packageId,appIdentifier,publishingState,usedLicenseCount,totalLicenseCount,productKey,licenseType,packageIdentityName

    $appConfig.displayName = "$AppPrefix" + $packageDir.Name
    Write-Host "    displayName: $($appConfig.displayName)"
    if ($packageInfo.ApplicationInfo.Name -ne "Install.ps1" -and $packageInfo.ApplicationInfo.Name -ne "Install.cmd")
    {
        $appConfig.description = "Installs " + $packageInfo.ApplicationInfo.Name
    }
    if ($packageInfo.ApplicationInfo.MsiInfo.MsiPublisher)
    {
        $appConfig.developer = $packageInfo.ApplicationInfo.MsiInfo.MsiPublisher
    }
    $appConfig.setupFilePath = $packageInfo.ApplicationInfo.SetupFile
    $appConfig.fileName = $package.Name

    $version = $null
    $regPath = $null
    $regValue = $null
    $versionFile = Get-Item -Path (Join-Path $packageDir.FullName "version.json") -ErrorAction SilentlyContinue
    if ($versionFile)
    {
        $versionObj = Get-Content -Path $versionFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if (-Not $versionObj.regPath)
        {
            $version = [Version]$versionObj.version
        }
        else
        {
            $regPath = $versionObj.regPath
            $regValue = $versionObj.regValue
            $version = $versionObj.version
        }
    }
    else
    {
        if ($packageInfo.ApplicationInfo.MsiInfo)
        {
            $version = $packageInfo.ApplicationInfo.MsiInfo.MsiProductVersion
            Write-Host "    got version from msi product version: $version"
            $msiPackageType = "DualPurpose";
            $msiExecutionContext = $packageInfo.ApplicationInfo.MsiInfo.MsiExecutionContext
            if($msiExecutionContext -eq "System") { $msiPackageType = "PerMachine" }
            elseif($msiExecutionContext -eq "User") { $msiPackageType = "PerUser" }
            $appConfig.msiInformation = @{
                "packageType" = $msiPackageType
                "productName" = $packageInfo.ApplicationInfo.Name
                "productCode" = $packageInfo.ApplicationInfo.MsiInfo.MsiProductCode
                "productVersion" = $packageInfo.ApplicationInfo.MsiInfo.MsiProductVersion
                "publisher" = $packageInfo.ApplicationInfo.MsiInfo.MsiPublisher
                "requiresReboot" = $packageInfo.ApplicationInfo.MsiInfo.MsiRequiresReboot
                "upgradeCode" = $packageInfo.ApplicationInfo.MsiInfo.MsiUpgradeCode
            }
        }
        else
        {
            $firstTry = "msi"
            $secondTry = "exe"
            $packagePreference = Get-Item -Path (Join-Path $packageDir.FullName "PackagePreference.txt") -ErrorAction SilentlyContinue
            if ($packagePreference)
            {
                $packagePreference = $packagePreference | Get-Content
                if ($packagePreference -eq "exe")
                {
                    $firstTry = "exe"
                    $secondTry = "msi"
                }
            }

            $toInstall = Get-ChildItem -Path $contentPath -Filter "*.$firstTry" | Sort-Object -Property Name
            if (-Not $toInstall)
            {
                $toInstall = Get-ChildItem -Path $contentPath -Filter "*.$secondTry" | Sort-Object -Property Name
            }
            if ($toInstall)
            {
                if ($toInstall.Count -gt 1)
                {
                    $toInstall = $toInstall[0]
                }
                if ($toInstall.VersionInfo.FileVersion -And -Not [string]::IsNullOrEmpty($toInstall.VersionInfo.FileVersion.Trim()))
                {
                    $version = $toInstall.VersionInfo.FileVersion
                    Write-Host "    got version from file version: $version"
                }
                elseif ($toInstall.VersionInfo.ProductVersion)
                {
                    $version = $toInstall.VersionInfo.ProductVersion
                    Write-Host "    got version from product version: $version"
                }
                else
                {
                    [regex]$regex = "(\d+\.){3}(\*|\d+)"
                    $versionStr = [regex]::Match($toInstall.Name, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
                    if ([string]::IsNullOrEmpty($versionStr))
                    {
                        [regex]$regex = "(\d+\.){2}(\*|\d+)"
                        $versionStr = [regex]::Match($toInstall.Name, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
                        if ([string]::IsNullOrEmpty($versionStr))
                        {
                            [regex]$regex = "(\d+\.)?(\d+\.)?(\d+\.)?(\*|\d+)"
                            $versionStr = [regex]::Match($toInstall.Name, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
                        }
                    }
                    Write-Host "    got version from file name: $versionStr"
                    if (-Not [string]::IsNullOrEmpty($versionStr))
                    {
                        $version = [Version]$versionStr
                    }
                }
            }
            else
            {
                Write-Warning "No version found. Please make sure the config.json has appropriate rules!"
            }
        }
    }

    if ($version)
    {
        Write-Host "    version: $($version)"
        if ($regPath)
        {
            foreach($ruleWVersion in $appConfig.detectionRules)
            {
                if ($ruleWVersion.detectionType -eq "version") {
                    $ruleWVersion.detectionValue = $version
                    $ruleWVersion.keyPath = $regPath
                    $ruleWVersion.valueName = $regValue
                }
            }
            foreach($ruleWVersion in $appConfig.rules)
            {
                if ($ruleWVersion.operationType -eq "version") {
                    $ruleWVersion.comparisonValue = $version
                    $ruleWVersion.keyPath = $regPath
                    $ruleWVersion.valueName = $regValue
                }
            }
        }
        else
        {
            foreach($ruleWVersion in $appConfig.detectionRules)
            {
                if ($ruleWVersion.detectionType -eq "version") {
                    $ruleWVersion.detectionValue = ([Version]$version).ToString()
                }
            }
            foreach($ruleWVersion in $appConfig.rules)
            {
                if ($ruleWVersion.operationType -eq "version") {
                    $ruleWVersion.comparisonValue = ([Version]$version).ToString()
                }
            }
        }
    }

    $logo = Get-ChildItem -Path $packageDir.FullName -Filter "Logo.*"
    if ($logo)
    {
        $iconResponse = [System.IO.File]::ReadAllBytes("$($logo.FullName)")
        $base64icon = [System.Convert]::ToBase64String($iconResponse)
        $iconExt = ([System.IO.Path]::GetExtension($logo.FullName)).replace(".","")
        $iconType = "image/$iconExt"
        $appConfig.largeIcon = @{ "@odata.type" = "#Microsoft.Graph.mimeContent" }
        $appConfig.largeIcon.type = "$iconType"
        $appConfig.largeIcon.value = "$base64icon"
    }

    if (-Not (Get-Member -InputObject $appConfig -MemberType NoteProperty -Name "displayVersion" -ErrorAction SilentlyContinue)) {
        Add-Member  -InputObject $appConfig -MemberType NoteProperty -Name "displayVersion" -Value $null
    }
    $appConfig.displayVersion = ([Version]$version).ToString()
    $appConfigJson = $appConfig | ConvertTo-Json
    $appConfigJson | Set-Content -Path $configPath -Encoding UTF8

    # Checking if app exists
    Write-Host "  Checking if app exists"
    if ([string]::IsNullOrEmpty($appConfig.displayName))
    {
        throw "No displayName configured in appConfig!"
    }

    $searchValue = [System.Web.HttpUtility]::UrlEncode($appConfig.displayName)
    $uri = "/beta/deviceAppManagement/mobileApps?`$filter=displayName eq '$searchValue'"
    $allApps = Get-MsGraphCollection -Uri $uri
    $app = $allApps | Where-Object { $_.displayName -eq $appConfig.displayName -and $_."@odata.type" -eq "#microsoft.graph.win32LobApp" }
    if (-Not $app.id)
    {
        # Creating app
        Write-Host "  Creating app"
        $uri = "/beta/deviceAppManagement/mobileApps"
        $app = Post-MsGraph -Uri $uri -Body $appConfigJson
        $searchValue = [System.Web.HttpUtility]::UrlEncode($appConfig.displayName)
        $uri = "/beta/deviceAppManagement/mobileApps?`$filter=displayName eq '$searchValue'"
        do
        {
            Start-Sleep -Seconds 5
            $allApps = Get-MsGraphCollection -Uri $uri
            $app = $allApps | Where-Object { $_.displayName -eq $appConfig.displayName -and $_."@odata.type" -eq "#microsoft.graph.win32LobApp" }
        } while (-Not $app.id)
    }

    # Extracting intunewin file
    Write-Host "  Extracting intunewin file"
    $extFile = "$($package.FullName).Extracted"
    if (Test-Path $extFile) { Remove-Item -Path $extFile -Force }
    $zip = [System.IO.Compression.ZipFile]::OpenRead($package.FullName)
    $entry = $zip.Entries | Where-Object { $_.Name -eq "IntunePackage.intunewin" }
    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $extFile, $true)
    $entry = $null
    $zip.Dispose()
    $bytes = [System.IO.File]::ReadAllBytes($extFile)
    Remove-Item -Path $extFile -Force

    # Uploading base app package
    Write-Host "  Uploading base app package"
    Clear-Variable -Name "allApps" -Force -ErrorAction SilentlyContinue
    [system.gc]::Collect()
    UploadPackage -packageInfo $packageInfo -app $app -appConfig $appConfig -bytes $bytes

    # Checking update package if required
    Write-Host "  Checking update package if required"
    if (Test-Path $requirementDetectionPath)
    {

        # Checking if update app exists
        Write-Host "  Checking if update app exists"
        $appConfig.displayName = $appConfig.displayName+" UPD"

        $uri = "/beta/deviceAppManagement/mobileApps"
        $allApps = Get-MsGraphCollection -Uri $uri
        $app = $allApps | where { $_.displayName -eq $appConfig.displayName }

        if (-Not (Get-Member -InputObject $appConfig -MemberType NoteProperty -Name "displayVersion" -ErrorAction SilentlyContinue)) {
            Add-Member  -InputObject $appConfig -MemberType NoteProperty -Name "displayVersion" -Value $null
        }
        $appConfig.displayVersion = ([Version]$version).ToString()
    
        $detectContent = Get-Content -Path $requirementDetectionPath -Encoding $AlyaUtf8Encoding -Raw
        #$detectVersion = [Version]$appConfig.detectionRules[0].detectionValue
        if ($appConfig.detectionRules -and $appConfig.detectionRules[0]."@odata.type" -eq "#microsoft.graph.win32LobAppFileSystemDetection")
        {
            $detectContent = $detectContent.Replace("##FILEPATH##", $appConfig.detectionRules[0].path)
            $detectContent = $detectContent.Replace("##FILENAME##", $appConfig.detectionRules[0].fileOrFolderName)
            $detectContent = $detectContent.Replace("##FILEVERSION##", $appConfig.detectionRules[0].detectionValue)
            $detectContent = [Regex]::Replace($detectContent, "%programfiles%", "`$(`$env:ProgramFiles)", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            $detectContent = [Regex]::Replace($detectContent, "%programfiles\(x86\)%", "`$(`${env:ProgramFiles(x86)})", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        }
        if ($appConfig.detectionRules -and $appConfig.detectionRules[0]."@odata.type" -eq "#microsoft.graph.win32LobAppRegistryDetection")
        {
            $detectContent = $detectContent.Replace("##KEYPATH##", $appConfig.detectionRules[0].keyPath)
            $detectContent = $detectContent.Replace("##KEYNAME##", $appConfig.detectionRules[0].valueName)
            $detectContent = $detectContent.Replace("##KEYVERSION##", $appConfig.detectionRules[0].detectionValue)
        }
        $scriptContent = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($detectContent))

        $appConfig.requirementRules = @(
            @{
                "detectionValue" = "Required"
                "scriptContent" = $scriptContent
                "detectionType" = "string"
                "runAs32Bit" = $false
                "runAsAccount" = "system"
                "@odata.type" = "#microsoft.graph.win32LobAppPowerShellScriptRequirement"
                "enforceSignatureCheck" = $false
                "displayName" = "RequirementDetection.ps1"
                "operator" = "equal"
            }
        )
        $appConfig.rules += @{
            "comparisonValue" = "Required"
            "operationType" = "string"
            "scriptContent" = $scriptContent
            "operator" = "equal"
            "ruleType" = "requirement"
            "runAs32Bit" = $false
            "runAsAccount" = "system"
            "@odata.type" = "#microsoft.graph.win32LobAppPowerShellScriptRule"
            "displayName" = "RequirementDetection.ps1"
            "enforceSignatureCheck" = $false
        }
        $appConfigJson = $appConfig | ConvertTo-Json

        if (-Not $app.id)
        {
            # Creating app
            Write-Host "  Creating app"
            $uri = "/beta/deviceAppManagement/mobileApps"
            $app = Post-MsGraph -Uri $uri -Body $appConfigJson
            do
            {
                Start-Sleep -Seconds 5
                $allApps = Get-MsGraphCollection -Uri $uri
                $app = $allApps | where { $_.displayName -eq $appConfig.displayName }
            } while (-Not $app.id)
        }

        # Uploading update app package
        Write-Host "  Uploading update app package"
        Clear-Variable -Name "allApps" -Force -ErrorAction SilentlyContinue
        [system.gc]::Collect()
        UploadPackage -packageInfo $packageInfo -app $app -appConfig $appConfig -bytes $bytes
    }
    $bytes = $null
    [system.gc]::Collect()

}

#Stopping Transscript
Stop-Transcript
