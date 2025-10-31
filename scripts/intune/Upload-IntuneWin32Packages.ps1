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
    [bool]$OverwriteSameVersionPackages = $false,
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

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAEmJNKqdC9Rwyu
# U0E1cBEYDllP2qmMA6IVWKAS6CmZO6CCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIMFJu1j1b7n1OW+d
# uK/po0+W/H/DEHm2i6RedBbgkIdqMA0GCSqGSIb3DQEBAQUABIICABWsXsoKy8nV
# fziRCG3ijTttfSc/K1AVLweDRRgvTCteVQ3w1IFN6YThXd8qFKevUMuZQlkIMRVi
# nwF8XrMW7QUm8KPQg4tNqwMmQCz65UVW/ZAESpAU8RPqPkTOXaM90eNE1FioFgJU
# AjeXbd0KTPDTbgOxfZ6HjFwLsJepUYuLk4Hbh3OXR7FUlRAVf0ELyOO9rd9+Nsof
# NNGY2xz7NEXOdUYQj1Edl//GU/JEU2PtHLiZFs3HLk7bcX0lruoGxyspcpQJGAk4
# mlhIJ0/1tCuudRB6dwZe2nQljJjaKAlOSt60TqjPCDw5ZtmiGpCj1T7hvvfkdi4H
# 9nld0mqeq+uMbjlt5OHROItrDgBmd6rGoYqE7r3lDU/ptqVKLBSeOhObDSmg6sK5
# /7gb+AA6qvy5CnI18iugSS6WKsmOVrnkYkJUX5DUXlXNO909F8vHrOLgbqR0h6mB
# xZUr13oCP/TPydyJAHbIn1ikxKrxzG+seBz289oYzVNxlu/sF9QTFS4kX4IziTJs
# i8Pan/yRR8SH8hC4WHNDrNfckSc6ynzfSvxAaVWNPCpLZyOMoWU34tOFrAh7bFih
# FrcFef/F1jFGhgiMsuotowOHMHZ9gJJ4LqS3bt4qb4oXmrzYuDNLzwvHbgD5F2KV
# k0YGSCLhNjBLJYOSde9my74keDz2H15noYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCBdst5eDBhQipVAMk34XuI7YlCuknwubRDACWF8dapUCQIUS3EuwXA7iZ/g
# fFCMCoPDc/lWXh4YDzIwMjUxMDEzMTAyNDMyWjADAgEBoFikVjBUMQswCQYDVQQG
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
# IPN+D1Ah3FuKuIWoY3saxChkJBTfXXvEBf4Q3sRnztfVMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAm/4JpxNiEzNX
# oDId3kqZZgQNl1QxVXcGfk/fatNyJfJHr64NkHdmqlH3m+9hlvxLSgFbZzSOl/uk
# YK4J6WDk+Qv+zl2NteguI+zlL7U6dn5pn2cPcKGQY0qsESYtF24wT814CISwBQW3
# DZccr9u3NZ64nJ3R3p69UWSAKtXThW/D3XsKs3O8YhOMFPF1W1lPHbrbIj9aPib4
# +ggEviFjApSPg4Ir5O0MMcmZDpqJ6Mbgnoy3s/74YTDZgpjW4JUegU5oT9D6LKMO
# aX5thBlydQ6cIyzpwn8KgqHF3xD9gqbU1P0OjDdkUO7ow4BqlUEWRjcuunZjgqTX
# SaeazxHj0Tr/exKZ+xFi3aqpHtU0+ewHwWW0l/XofaFFYtYacd5jpAiUlPHYLmMq
# uNkt64uu9kdQIbM1YScCE8njUxG1GEetTQ9Nq0YdizkIrv7Y+OhE9cy7XmzyzPlk
# O4mWc76dlfZNKwjdJMmtDPjyAa1ptf340baMKNPxqZ4yBP2d+PuQ
# SIG # End signature block
