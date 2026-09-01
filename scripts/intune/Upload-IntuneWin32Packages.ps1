#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2026

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
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
    06.02.2026 Konrad Brunner       Added powershell documentation

#>

<#
.SYNOPSIS
Uploads Win32 application packages to Microsoft Intune using Microsoft Graph API.

.DESCRIPTION
The Upload-IntuneWin32Packages.ps1 script automates the process of uploading and managing Win32 application packages within Microsoft Intune. It reads local application package folders, extracts and analyzes their configurations, creates or updates corresponding applications in Intune, uploads package content in chunks via Azure storage, and finalizes the upload using Microsoft Graph endpoints. The script supports resuming at a specific application, selective uploads, version management, and the creation of update applications with requirement detection scripts.

.PARAMETER UploadOnlyAppWithName
Specifies a single application to upload, identified by its package folder name.

.PARAMETER ContinueAtAppWithName
Specifies the application name in the sequence from which the script should resume execution.

.PARAMETER AppsPath
Defines the relative path to the directory containing Win32 application packages. Default is "Win32Apps".

.PARAMETER AskForSameVersionPackages
Determines whether the script should prompt for re-upload when the same version exists. Default is $true.

.PARAMETER OverwriteSameVersionPackages
Indicates whether to automatically overwrite packages of the same version without prompting. Default is $false.

.PARAMETER ShowProgressBar
Displays a progress bar during large file uploads when set to $true. Default is $false.

.INPUTS
None. This script does not accept pipeline input.

.OUTPUTS
None. The script writes progress and status messages to the host and log file.

.EXAMPLE
PS> .\Upload-IntuneWin32Packages.ps1 -AppsPath "Win32Apps" -ShowProgressBar $true

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [string]$UploadOnlyAppWithName = $null,
    [string]$ContinueAtAppWithName = $null,
    [string]$AppsPath = "Win32Apps",
    [bool]$AskForSameVersionPackages = $true,
    [bool]$OverwriteSameVersionPackages = $false,
    [bool]$ShowProgressBar = $false
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transcript
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
    "DeviceManagementApps.ReadWrite.All",
    "DeviceManagementApps.Read.All"
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
        if ($OverwriteSameVersionPackages -eq $true)
        {
            $doUpload = $true
        }
        else
        {
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
                                try { Write-Host ($_.Exception | ConvertTo-Json -Depth 1) -ForegroundColor $CommandError } catch {}
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
                    try { Write-Host ($_.Exception | ConvertTo-Json -Depth 1) -ForegroundColor $CommandError } catch {}
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
                $file | Format-List
                throw "File upload state has not succeeded: $($file.uploadState)"
            }
            $Global:attempts--
        }
        if ($file -eq $null -or $file.uploadState -ne $successState)
        {
            throw "File request commit did not complete within $Global:attempts attempts"
        }
        Add-Member -InputObject $appConfig -MemberType NoteProperty -Name "committedContentVersion" -Value $contentVersion.id

        # Committing the app
        Write-Host "  Committing the app '$($app.displayName)'"
        $attr = Get-Member -InputObject $appConfig -MemberType NoteProperty -Name "applicableArchitectures" -ErrorAction SilentlyContinue
        if ($attr) { $appConfig.PSObject.Properties.Remove("applicableArchitectures") }
        $uri = "/beta/deviceAppManagement/mobileApps/$appId"
        $appP = Patch-MsGraph -Uri $uri -Body ($appConfig | ConvertTo-Json -Depth 50)
    }
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
    $requirementDetectionPath = Join-Path $packageDir.FullName "RequirementDetectionUser.ps1"
    if (-Not (Test-Path $requirementDetectionPath))
    {
        $requirementDetectionPath = Join-Path $packageDir.FullName "RequirementDetection.ps1"
    }

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

                $version = $null
                if ($toInstall.VersionInfo.FileVersionRaw)
                {
                    $version = $toInstall.VersionInfo.FileVersionRaw
                    Write-Host "    got version from file versionRaw: $version"
                }elseif ($null -eq $version -and $toInstall.VersionInfo.FileVersion -And -Not [string]::IsNullOrEmpty($toInstall.VersionInfo.FileVersion.Trim()))
                {
                    $version = $toInstall.VersionInfo.FileVersion
                    if ($version -like "*AppVersion*")
                    {
                        $version = $toInstall.VersionInfo.ProductVersion
                        Write-Host "    got version from product version: $version"
                    }
                    else
                    {
                        Write-Host "    got version from file version: $version"
                    }
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
        $detectionVersion = $version
        $detectionVersionPath = Join-Path $packageDir.FullName "ComparisonVersionCustomizer.ps1"
        if (Test-Path $detectionVersionPath)
        {
            $detectionVersion = & $detectionVersionPath -Version $version
            Write-Host "Customized detection version: OLD:$($version) NEW:$($detectionVersion)"
        }

        Write-Host "    version: $($version)"
        if ($regPath)
        {
            foreach($ruleWVersion in $appConfig.detectionRules)
            {
                if ($ruleWVersion.detectionType -eq "version") {
                    $ruleWVersion.detectionValue = $detectionVersion
                    $ruleWVersion.keyPath = $regPath
                    $ruleWVersion.valueName = $regValue
                }
            }
            foreach($ruleWVersion in $appConfig.rules)
            {
                if ($ruleWVersion.operationType -eq "version") {
                    $ruleWVersion.comparisonValue = $detectionVersion
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
                    $ruleWVersion.detectionValue = ([Version]$detectionVersion).ToString()
                }
            }
            foreach($ruleWVersion in $appConfig.rules)
            {
                if ($ruleWVersion.operationType -eq "version") {
                    $ruleWVersion.comparisonValue = ([Version]$detectionVersion).ToString()
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
    
        # Building detection script
        $detectContent = Get-Content -Path $requirementDetectionPath -Encoding $AlyaUtf8Encoding -Raw
        $sigBlockLoc = $detectContent.IndexOf("# SIG #")
        if ($sigBlockLoc -gt 0)
        {
            # There is a signature block, better removing it because it will invalidate
            $detectContent = $detectContent.Substring(0, $sigBlockLoc)
        }
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
        if ($requirementDetectionPath -like "*User*")
        {
            ($appConfig.requirementRules | Where-Object { $_.displayName -eq "RequirementDetection.ps1" }).runAsAccount = "user"
            ($appConfig.rules | Where-Object { $_.displayName -eq "RequirementDetection.ps1" }).runAsAccount = "user"
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

# Stopping Transcript
Stop-Transcript

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCL/FrX4SRpcWvP
# /DpPAd9M2EZjckOxMoqwE+HZBpofMKCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
# Qc9vAbjutKlUMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24g
# Um9vdCBDQSAtIFIzMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9i
# YWxTaWduMB4XDTIwMDcyODAwMDAwMFoXDTI5MDMxODAwMDAwMFowUzELMAkGA1UE
# BhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2Jh
# bFNpZ24gQ29kZSBTaWduaW5nIFJvb3QgUjQ1MIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAti3FMN166KuQPQNysDpLmRZhsuX/pWcdNxzlfuyTg6qE9aND
# m5hFirhjV12bAIgEJen4aJJLgthLyUoD86h/ao+KYSe9oUTQ/fU/IsKjT5GNswWy
# KIKRXftZiAULlwbCmPgspzMk7lA6QczwoLB7HU3SqFg4lunf+RuRu4sQLNLHQx2i
# CXShgK975jMKDFlrjrz0q1qXe3+uVfuE8ID+hEzX4rq9xHWhb71hEHREspgH4nSr
# /2jcbCY+6R/l4ASHrTDTDI0DfFW4FnBcJHggJetnZ4iruk40mGtwEd44ytS+ocCc
# 4d8eAgHYO+FnQ4S2z/x0ty+Eo7+6CTc9Z2yxRVwZYatBg/WsHet3DUZHc86/vZWV
# 7Z0riBD++ljop1fhs8+oWukHJZsSxJ6Acj2T3IyU3ztE5iaA/NLDA/CMDNJF1i7n
# j5ie5gTuQm5nfkIWcWLnBPlgxmShtpyBIU4rxm1olIbGmXRzZzF6kfLUjHlufKa7
# fkZvTcWFEivPmiJECKiFN84HYVcGFxIkwMQxc6GYNVdHfhA6RdktpFGQmKmgBzfE
# ZRqqHGsWd/enl+w/GTCZbzH76kCy59LE+snQ8FB2dFn6jW0XMr746X4D9OeHdZrU
# SpEshQMTAitCgPKJajbPyEygzp74y42tFqfT3tWbGKfGkjrxgmPxLg4kZN8CAwEA
# AaOCAXcwggFzMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzAP
# BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQfAL9GgAr8eDm3pbRD2VZQu86WOzAf
# BgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpjmove4t0bvDB6BggrBgEFBQcBAQRuMGww
# LQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL3Jvb3RyMzA7
# BggrBgEFBQcwAoYvaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# cm9vdC1yMy5jcnQwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxz
# aWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggrBgEF
# BQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJ
# KoZIhvcNAQEMBQADggEBAKz3zBWLMHmoHQsoiBkJ1xx//oa9e1ozbg1nDnti2eEY
# XLC9E10dI645UHY3qkT9XwEjWYZWTMytvGQTFDCkIKjgP+icctx+89gMI7qoLao8
# 9uyfhzEHZfU5p1GCdeHyL5f20eFlloNk/qEdUfu1JJv10ndpvIUsXPpYd9Gup7EL
# 4tZ3u6m0NEqpbz308w2VXeb5ekWwJRcxLtv3D2jmgx+p9+XUnZiM02FLL8Mofnre
# kw60faAKbZLEtGY/fadY7qz37MMIAas4/AocqcWXsojICQIZ9lyaGvFNbDDUswar
# AGBIDXirzxetkpNiIHd1bL3IMrTcTevZ38GQlim9wX8wggboMIIE0KADAgECAhB3
# vQ4Ft1kLth1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENv
# ZGUgU2lnbmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAw
# MDBaMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIw
# MAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAy
# MDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj
# /SBerjgSi8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlM
# g7BKRFAEeIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRV
# X5YLEeWatSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV
# 0xHK5s2zBZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEz
# IHXMsdXtHQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMk
# oog28vmfvpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq
# 7rfYrWGlr3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult
# 5a/dm2tjIF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNu
# twFsDeCXpxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYy
# AjIwfLWTyCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofn
# GrhO7izB36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
# FgQUJZ3Q/FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0
# Q9lWULvOljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8v
# b2NzcC5nbG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUH
# MAKGOmh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWdu
# aW5ncm9vdHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJ
# KwYBBAGgMgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24u
# Y29tL3JlcG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJ
# yTm6t6E5iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbV
# YQLFY4/UovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQt
# pFg6bBNJ+KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSX
# hndGKj0jfShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6
# bs+XYXvfcXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nO
# ZNm9/Lws80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOH
# X5OKSBoRHeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dq
# cYC/lt5yA9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0i
# xxnJpsoOqHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7
# qWPLd0jV+mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g6
# 04YfM/tV5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD
# 4ED6gVYDU/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S
# /gJXhZrh0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp
# 8nKmrVa46Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqt
# f2phU7+yR2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJ
# QWTEE/bP0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKX
# vYkPbEdx+QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4
# yMYgcMKb9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmY
# F8T4xO2k6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2
# mMIVpqWCZ1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7
# spNY6rQb3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd
# 2jANBgkqhkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy
# /fAHsVv1RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW
# 2H3Bh6zNXULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0
# MP6pBPKOL6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/
# pFL9zlcctWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcex
# U0bcV0hLQ4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf
# 6AMOGaM56A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzEC
# p9LnR+34c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9m
# UF5qE6YwQqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+Ku
# aJRsz+cnZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/Jl
# N6m6GM1jEhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutof
# dgNBzMUxgiEGMIIhAgIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIOS6Ygu2
# 0ohH45VOQOr51zM44I14XjbI5X/mQXHh3pFXMA0GCSqGSIb3DQEBAQUABIICAAvY
# 1b3DvEhynU8H0kyFiDrL7HvlArZTbb+/oF+kQ6hTRs4bBWEF7O8O/9bME+9xkyK+
# BG+J6DzksIPdBkFeJAebyBPS7dOB/g0IQqR+VE8MoCV83pj7dxIxMz2+YijAdNzE
# r62LnmxRVSnnM0OBC1lK5wW268cIWu1fSky22yKfCnVLexC8XRk9LQYpkgNpIIy/
# n6ownU50lvbr4XuPncyEdPryyuqec6eLRudcEo8+TeimulEKm+q8eePwa5y5EgXL
# y9HW+ct4/h/kLA63ekLLpibfI6s/CwIjY3C5bhrumv9c8L9pZAzu2fXCv2H/HcBh
# Vy9Ij5omAe97y8Qbrt+V65kKM6y4nuknOCM0T1yejgO7r1z3A2d8j835N8hom/NU
# pqWAwZ3loxoSC2BBo57sB+dIVQTMHwFastjtmVovBY9khaWaQd1DtCzUMzU4+OFJ
# LVULpJaRgL05ASbzkujLSuGi6e2a3EE5W4RLFUkNokN4ADtXypMQicAZYCNZgHvj
# zYxDMvDqm/gXz6ZAR56ukJ1Ty8C3Qo5tyNh0vs55DSFY7+Tfu++wdEjK1FbRNv3M
# v6o96NGlRWrNiE30JEIJuIbjJHA6JYeVUt8d3FmlcqOKXmVTsufaFxUDlXKsJjW+
# n68gSMttePTnrczomtIp1dI6yrCSBn7crDkFQn4ooYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCBJmJRk0s7n4BPITzDFqbvOzFSu9V0RaqhtAw9mVdct4gIUAKBj
# n3uocY785nCRgJUbsclSuL4YDzIwMjYwODI5MTUyNTQ4WjADAgEBoF2kWzBZMQsw
# CQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMm
# R2xvYmFsc2lnbiBSNDUgVFNBIGZvciBDb2RlU2lnbiAyMDI1MTCgghlgMIIGijCC
# BHKgAwIBAgIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcNAQEMBQAwXjELMAkG
# A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0ds
# b2JhbFNpZ24gT2ZmbGluZSBSNDUgVGltZXN0YW1waW5nIENBIDIwMjUwHhcNMjUx
# MDE1MDcyNTA0WhcNMzcwMTEwMDAwMDAwWjBZMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFsc2lnbiBSNDUgVFNB
# IGZvciBDb2RlU2lnbiAyMDI1MTAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQDRSo2hjYZASCijCQSc2RMQPPKojE/xf4Uija2JnsJ7Snl2gDoxKjQ9HcU6
# rVD8pgy1sBKdVxtLLFhY3gzY/PA2iwIs6ZzCnxshtjShsN1RyzRrzc4Fq+0xQx6q
# ADUMn96mqHE/0ok53DPbmpBkkUDytGM79nQfw9WVymYgA+TkbA0/QOmPNNJIZ6Cj
# X0t3wJfhL0caiXthBBMEWKxT5v2U7ZRbCq/DVDXA9oX1iFVBVaBpx57MLL00nyHu
# x0InYS7Rr54M3tNhm7+0maxpyTFa51uY1PHtTJMup/l3RGooQ5YweCH2hDoUNwKO
# C7QkFbklhPdq27EXkueg8qLOnRDmVO1r+B1yMAbl6QuV0L+OPB1SKBAPpmIFklmJ
# 0SoibbUqxsTzejjdI+ywQLUcXilogwKWsJ46h6wjlU5AVqT7FEBYzWCTt6hf7SLQ
# bPGs02Ba8oaaNfo0SL+aApN94luEB/wuE1lgptrckLzbQlCp56OgkAJYpqYuui+T
# fueCIU0CAwEAAaOCAcYwggHCMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAK
# BggrBgEFBQcDCDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQy+tPhB2gnkGsI0j8d
# PIxlNigGGTAfBgNVHSMEGDAWgBR3AjsBMQ8edHfDSMjDB2NViKU7ojCBpQYIKwYB
# BQUHAQEEgZgwgZUwQgYIKwYBBQUHMAGGNmh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24u
# Y29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNTBPBggrBgEFBQcwAoZDaHR0
# cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NvZmZsaW5lcjQ1dGlt
# ZXN0YW1wY2EyMDI1LmNydDBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLmds
# b2JhbHNpZ24uY29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNS5jcmwwVgYD
# VR0gBE8wTTAIBgZngQwBBAIwQQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0
# dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEB
# DAUAA4ICAQCOrnCmj0eGkYpuniz6/WFm91s6KjnhkMKYlbcftgpMBtlhysVniEOf
# BvhcvoFQw4AOHG9NRVvZpkBnag5Dt1HM3Jg21gRVCBwFyP1ET8IDxoflYx5OD4SC
# NLHs6vCg6rFkNT81v9Zy8u0xXy3WboN5iK/SbTmLGqCrAGJihLLrfIhvddwVrdBy
# iHteLxgjugT6JQogCSoBF2JqmH0ZBCl515btbTuWZLrQUs5vvl2o98Mdju9yyJRW
# LzPVcUkRk9d8xBBi638FBOAuo3fcyThGcne7wUOa+TghhwIHbZ3pxTYpgo5cCxEZ
# sH8EXwiTUTwHf0qesssg/2XdcGH7s0AR4TyOJ2QnAayYOAM/XOBxNzURQg4mhMdP
# L/F8VCMKj3koJaVcx2akh0B82le/aBU8q2Oa++OwOwiHF5e+f9m+yhyYbwGSogWI
# V3hgRl+VyKrch8gv35FHr/cVz8n0/CPGRXGiYJZ7P1wOOgYdkMD2iDKVYQby5Ix/
# xCB0/lSKLnqEoFezfmnCJbGgACVswMsxhJEUjtxEcQc9afalne+IOts0v/yCRikJ
# snmVbS0x50Dk2OH+VCiU9s/XyzgfC7WzrtQ5diIdc2Ksi3JMTJm4a0LiEIZWitD5
# +6PokOkQ8+35TsHOwUhs87I/yyJjlIZpAV4Of1/JN8bWVB3Edm4WzjCCBqAwggSI
# oAMCAQICEQCD2oY3t58MhAyUe4QKUngfMA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNV
# BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9i
# YWxTaWduIFRpbWVzdGFtcGluZyBSb290IFI0NTAeFw0yNTA3MTYwMzA1MDRaFw00
# MTA3MTYwMDAwMDBaMF4xCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTQwMgYDVQQDEytHbG9iYWxTaWduIE9mZmxpbmUgUjQ1IFRpbWVzdGFt
# cGluZyBDQSAyMDI1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApHcW
# +O19i+LdAoZFYzS+5X+WYvnWoFqXAfir1hynhUTdH4RW1Db+yOmrQ275jlsQ6bzo
# Z3nN0CMncZX4E0Qhpp6Qvx27+flpfzeMQacD7VciWUiF3TLiu7wT2bBCSENUn3hf
# GMG4PJvYFvO5o4DA1iNvHhG4oSzctodoJfb4c8EjVahCw/NLizB3ra+NWe2gZBSa
# ZKraMxFt676yqx7RcQnjbF4R0OLGovsZt23vU69A5BdoPxdA9zu9rM+qTBsPDVUJ
# exYwEVU0GY7BJ5mUWWniyAPHW0Wv4Azk5t7I0XUIjA3+2OGkr0dVBXVBDyEeGBVr
# YXEdhfVLwuh6HBGJFdIrEY5KoGlpoT+4BBQe4XCH5sv15Uo+M72VKWjPA5Ex3nfF
# JC4P5FW1SR6olCSaIrtnZzc+zgmpSyiD+GcE2udQRQHbDi74enXgazk0+ktpHZ1Z
# 8oTvSaSIREovXSLbH3KC8uFIkXucl7XPH7ZGIrmF9eF4zuoo5FIUnsvV60kLqFDz
# Pk+UbLmgZDUCPlFFBBehaaNvixEymx9ON2KXev+MfK6OZChqGbrOC2wvvAFHyKlT
# ZbVHdqNiu0u5a2T1C9dSTRny1/hxLwcxL9BWPzQLwhsiyXqUzM7uD0lD9+PYMaxU
# YgoVSxqb4xvPCiVqLNabI+WtjEzYfQ0P+6tBTFsCAwEAAaOCAWIwggFeMA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDASBgNVHRMBAf8ECDAGAQH/
# AgEAMB0GA1UdDgQWBBR3AjsBMQ8edHfDSMjDB2NViKU7ojAfBgNVHSMEGDAWgBRG
# shx34XsV8KU5oXDe0cQu6m2y3jCBjgYIKwYBBQUHAQEEgYEwfzA3BggrBgEFBQcw
# AYYraHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vdGltZXN0YW1wcm9vdHI0NTBE
# BggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# dGltZXN0YW1wcm9vdHI0NS5jcnQwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2Ny
# bC5nbG9iYWxzaWduLmNvbS90aW1lc3RhbXByb290cjQ1LmNybDARBgNVHSAECjAI
# MAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggIBADKj7n7RbuRmMZZYXqlMPRJoR6X1
# n//quXGLVfOpFoR9Ya05L94w0ywBjelyGGf+nAB+CZFQ7gUOd2a2bpfpW8Xw5ArM
# +YjPEf8AtC4E6Yr105U1YNjlTSERoWJKc1hkSN5m4dpsYteFykzFQVwX50hYKH3y
# Z6Vcu6Ha0EA5ofzLpi2jK2jbRDCXbFNLi5mO1xKRdB2AzAF0f5C00b4H3d5sCOB8
# njTvAwaTMGEMeTkLWM4Z9Y+3UOtOpo1QuxXbDpXVkLXraG25iL1VtvjxEAy4534n
# UINB9whORicJJSTLba6fOK2f/1QGWEdewWLHAzE+N5oH0QoNRALpJ5JjIfeInvO+
# sQdBidnPuLKJ95HTj7XyMvJhFZjtbHJGlEWx4UgKcuNKLDLXWALfwQDN2Dey3kTf
# d4yw4nQdk1PctLLK3F4L2nnLv94BMkpY+Rfl53oOEN4yTvtwCYP+VDuZrktc7Nac
# oTVxZnKGkv8a1akckdOwQZC+i8Ay1VyzMAX/Tb4+r3c65B7cpAtq3OoUijXUJgvZ
# xci6TX78smL2TYy2tWn+8G4krnXvy2ELR2XYnKEOS4MVmrSCsjM5nxSrghE10VDX
# QbEfa93lhikfFoIuINKzWDLqvu8ZucmxEufxpHjNnnRVXX/Zv5KQq8pu/MQoOz6D
# C74n5+O5bSwvT5sgMIIGozCCBIugAwIBAgIQeEqqgXNmnJAJVOQhyUfrwDANBgkq
# hkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjET
# MBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMDEy
# MDkwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIFRpbWVzdGFt
# cGluZyBSb290IFI0NTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALp0
# M+wn3BI4IRvF02Eo1lq8T9+LzJGEQyRXvGQhvDscHz1PjK0Ht/PF1wLpERSCmqq0
# lHI7cQ0a72hrhXmOr2bqWJgNusF8edL/zbNvMUXQBXQEAHJqJ364Nz86iO2Xg/Wr
# NU0Pn1k79S/fWcV8pTJ2YJbI7e74BH4ZUXKov0RBerx7HjsAm7y64Ja/kP6Nm8Ny
# iwAS+CA6YDj3wcyFivuHeS6hKyDmy6CFkSO2xCgHVCje7BAxT4ryzRQfHt1VHOoo
# MUz5IWqozfOWZ/oBQZvNDwtof7ve8UPqF+Ww3HAis2k2WXRrxuWJKnzlC4Fdqz+P
# uNF2cvN8oqnil0G/zIxF/mHJ9mwHCwAE6BUjT4IqLfbvw/oRNkih0f16OTo0XaMs
# Dpt3UCA0QN2xAzGtX+lih3OWA2H3lLDZXGxP5xTF4fF7DSOczXCMHWreSi2LKrvb
# QhQFB6r7FNwx0/YfbMu+aGZEcE1tF/lx6wVzjpGSdetoXB72RGEYKWLdF2aI7Ci6
# SW/bPnf+uTEfdRwYoqZHvdjuSIU7/bPiDz8qmMaa+oJvsaWlhh1aOvqkbHQPd1Jh
# an+HKd45m4vus0VgMCSXFRIqhTCTJqyWpi3ocG0LqTKtLJsoCnZC8lVhUZiU3u32
# xRdvPBUQsA6tsN7FFvRl0cwvWlYIz5nE8FWRwix5AgMBAAGjggF4MIIBdDAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDwYDVR0TAQH/BAUwAwEB
# /zAdBgNVHQ4EFgQURrIcd+F7FfClOaFw3tHELuptst4wHwYDVR0jBBgwFoAUrmwF
# o5MT4qLn4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEEbzBtMC4GCCsGAQUFBzABhiJo
# dHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsGAQUFBzAChi9o
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAi0i6Nlc8csXadfnvMvWGvdwSKOOILk82XyaZ7A8BIRCWkjjGcGtt867UDr0l
# 74Z/4omNlaV+KUQDTaqYqPG33OopYyHc7c2ICssQaWF5KUIMI7zpxe9SHi8zN9VP
# ZnpmqUdUM7HdFvLYZHGjMZTlb/ZNS+KEbNDJJWdPyEvQzksF1j37fUH6irHAIeB+
# CLDZZCv56vLHCvTPLgw0YO5su5LwP/F7UhJod1mB9RwupDqMOQMN7eXMr2ZIeWPV
# Sbj/S9IlT0hOkzuTd7CaSGy2oB2zdJ5fvSIEO3w3DYW1w5q73ZxaA420DZ9MdjTV
# ha1Fe7Wfuy6Ju6zIv5JjSMY/yheqDbwAEV+L6ONDhIpDNM39O8Cie9sfuGfIjBXe
# P6Z/xyjvoW9vskHPAiLrAfhLyNJ2byXfXtpoaD17RATCQW5JO6eYVgTt0SYrBJTb
# 5O1mjj2AnaSkVXlQXuP4Gh/AFm+QFTyKpkihDHu6KuCxqYcFRpvtJVU9N2mY7UaZ
# mIVHCh5i2/2c5cFDQo69z2/2jJH9guSf7K3jlVUF80kvbTT3/2fumUC705qAQkDa
# I4lgH4NxkrXp5soK+d3HbLJYQZxmjZsqbx9vVwRDXINdO2mc3jn6hE0183sbbYvx
# bwPBKVLilL97VIvfQHoLcAJ3Py+IBwIAddKvxtYiMhmjO+gwggWDMIIDa6ADAgEC
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
# AtcKZ4MFWsmkEDGCA2EwggNdAgEBMHMwXjELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNpZ24gT2ZmbGluZSBS
# NDUgVGltZXN0YW1waW5nIENBIDIwMjUCEQCEcj/BlcwW8dsrovZg3yvkMAsGCWCG
# SAFlAwQCAqCCAUEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMCsGCSqGSIb3
# DQEJNDEeMBwwCwYJYIZIAWUDBAICoQ0GCSqGSIb3DQEBDAUAMD8GCSqGSIb3DQEJ
# BDEyBDDiZoZbWpqr0ZnxuMDPCycwvTuffp4RJzv2jDI5j0Dl4vm8aGxHcvRktfj4
# IzOhctAwgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGAuthTZIPdX2Oc7i3Ftmo21E5B6cq8OeElptkj747Dmurj
# tRrwe05uFmgVQaGoei8HDnQQcHG8s+YWK3bHfDX126su9015rda4BFNXwspsJ4+V
# mbF+fOEe3aZcQ4uZ5C1hPsa2cqaEc2jEGZVIr0OzploIE+1OEjEvZuWN8Px5wfiF
# S5hmEJxm9B3y0vDQhfjJS+6OrpXWYAqOETsxleg8tK7LsVu0MtzjlNZTixP1wYFl
# yoxoGfjCxg1KN1JIhyS2Q9sM84OsyBkpZF5nuBH/a7+7Sope6gLbJfb/6ISRgvpf
# EfakU1PGztMyt69fstD7SGtoBiAM9XYoih+5VhK6oFgcJ5DsvDRXE3pfz+iUELuq
# L/a9fjR4n+agDclEmLwiBdzoT1OSx4NQlKmKex/zxv+PTIn8oweUeLpv8dOdQgk8
# G/VG2fjiRdKVAzQoMGXm1UjTiewyqlLgO3APpVtLDxPE6HEijBJIWJYEHzt4jQKH
# gStk47k9p7EMwLNtPlxW
# SIG # End signature block
