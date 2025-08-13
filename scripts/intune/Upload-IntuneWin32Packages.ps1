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
                if ($toInstall.VersionInfo.FileVersion -And -Not [string]::IsNullOrEmpty($toInstall.VersionInfo.FileVersion.Trim()))
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
# MIIvCQYJKoZIhvcNAQcCoIIu+jCCLvYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCYT1PMKRAdS8RY
# viwk+ngoxNDswa52K7xbkzMMFZ0TQqCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# dgNBzMUxghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHuN5T3U
# /Zqjv0coJ6WqFJTuSOYzxtL3o/mRCsz2ZLu5MA0GCSqGSIb3DQEBAQUABIICAIgt
# I5J6o+kkBIbPNpnY5CftzpTyfint7j9dB+Zc1V/ojDD8ul0QYBQ+mOofLptJJq2Y
# 6N8RnTogJIr2j8yfqNiJp1CLvZuzdEiUwCh8NZK2qcAXyfcjmUo+JedxAf+he05C
# CLmHKluXnCV2WvISJlpgWL6dwkaI7Uh1kCJ49uwEWbalXBRqgLHpaazXBTRDj+Tn
# bmmGm25OrOZg0IK2Ni41xBXuks83j9tz7hfW1o0/YFqTpYvapygRQCJ3vw9lr51f
# FDyB0nRmNLqanljcvPsushDo2glCVCL2US8E76gYuZelBQR0n30sgjy2M85hDQa/
# e7xcECJcZ07jRzko6AQWCAnEKlCjGXa/YRAcvM/Vphu8jpd7cMvOsPawibPtobO2
# rWhmVn5v7/0Kok86tmw3ZcKpzEQz+qTIZw3mISafN51kkamEmELRlAZPSW3gKbN/
# AUWSTDINr5xsZuBLhOVoQSWUhTg+aMHD66yrVRYjSxoSTcYRpy3e2GWqiy3Ab8Gb
# Omxb4Fs53uXEK2+Y0nj7hj3AlmgqEK9wxa4SfUb0kzzAWNtE1+p99bfyO2937go7
# L9soX6VgirsQYX1tO+cblfB0C0sShyWyL0pMiBENj2t3/S0NeG6PYDUcUSgBhVDh
# cUl19qU8IfC15v0QOLS2v/UspXFS8aFpCxlUpjE2oYIWuzCCFrcGCisGAQQBgjcD
# AwExghanMIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEw
# gd8GCyqGSIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCBwHjbMdM2IM/i/U3yIQ0YyAeB4ZsB4pyQ1e2seS75L1wIUYi+8
# TFbFiN5mcW+1i/xizt40t0UYDzIwMjUwNjA1MjExNzM0WjADAgEBoFikVjBUMQsw
# CQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwh
# R2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMC
# AQICEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMC
# QkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNp
# Z24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5
# WhcNMzQxMjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFs
# U2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWdu
# MSAtIFI2MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4
# PuCF6+aqCj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb
# 5gk0Xydy3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJSc
# RV1W6/6efi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy
# 5RJY+o1NWhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY
# 0Lie04DuKbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2Z
# wbI6yiFHaS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYh
# KUlrMH9+2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5s
# WtX1qvCzk6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGo
# MIIBpDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYD
# VR0OBBYEFIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQC
# MEEGCSsGAQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxz
# aWduLmNvbS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSB
# gzCBgDA5BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2Ev
# Z3N0c2FjYXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2Jh
# bHNpZ24uY29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaA
# FOoWxmnn48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9j
# cmwuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG
# 9w0BAQwFAAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26
# IFq7fQMIrN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76Tkv
# L+v2f4mHolGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftP
# ttS+G/MhNUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIl
# S3Ki74CU15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt
# 8DT4RQj9LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5
# lgJkgXEc1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD
# 9hQchjiGkyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71
# yzGKWnbAWQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGL
# ZtJFJzGJD7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVA
# GXCqHsh62QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZ
# MIIEQaADAgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNV
# BAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWdu
# MRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAw
# MDAwMFowWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOv
# dYNfqUdSx2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt
# 0ShKwSy7uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHP
# vIo7bmrEiPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFU
# UweLmW64VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16
# ZevRVqkuvftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS
# 2SU07Zbv+GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm1
# 9m1W/oodCT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIG
# bxsY1TbqZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMD
# Ad6ZJflxbumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/Miy
# Tdtk8EWfusE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9
# GbCX6oxQkW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGG
# MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDD
# vWWWMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEB
# BDIwMDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jv
# b3RyNjA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29t
# L3Jvb3QtcjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZo
# dHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0B
# AQwFAAOCAgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYW
# axlASSUIHuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCy
# z+zCVmUdvX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQ
# cXZw0g+W8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0
# Wn1yhjWzAlcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59e
# odaZzul9S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8
# oMWsr1EG8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1
# If5iEO0dMPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbcl
# IA4bUaDUY6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2M
# tnHtUiH+PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB
# +SXiLBB+gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIID
# a6ADAgECAg5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQL
# ExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjET
# MBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAw
# MDBaMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQK
# EwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4
# QZIzFKRvf+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTe
# c5RO86eJf094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWy
# ZtWQmrcxBsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7tt
# U+JIfIwQBzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrK
# otudCd5dRC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKF
# t3OiuDWqRfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTfl
# puwhCHX85mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2Fm
# CWqxBjplllnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5
# paHYgw/R/98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4O
# hxlcVLFltr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwo
# TK8CAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYD
# VR0OBBYEFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki
# 5+LXHNbH8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnm
# XNCE3tytok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJE
# lrSVXsB7jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMp
# mY4w06wh4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6
# JV2NoTFR3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG
# 7cKTBYn6fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/
# gsge/lgbKCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324G
# abbeCglIWYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5
# MCMHTI8Qv4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO7
# 7oHl2l98i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4st
# Q1LrRgyU4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjx
# guhFPmzWAtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJ
# YIZIAWUDBAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZI
# hvcNAQk0MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcN
# AQkEMSIEIPfv8cD4oUh9B/JLa6KX0oVhmrtY1kQdLaVZ1X8ahQjBMIGwBgsqhkiG
# 9w0BCRACLzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1or
# d69gXP0wczBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24g
# bnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hB
# Mzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAgwCb
# pzLkTek7Qeydhv6I47hE7mbRI8rYlwb+hcCrZxP8gcondN52Q46dqRFbnAmb64FI
# ul50pu7NmjXUse4M+ZvCz/kVRyKTXqwOEd9aIHg5mZ7/nXBXVwfRTmK75zLPYIzJ
# 2A6OZLfH3NK6Cq4uRtdjBD6gxS0r9Hv5tiOAwfZEF9SBikRIr7RJs2yR65OnGaMu
# swUncK7eHU4qgCSnqMQR42jUr0yziAuh/rBGYjIMPidjpRHV1/dUq4mHFQlgBGdW
# xAe8NXrclJSa4z9ovwqOl9iUXcXnV9StKd8UI/X3jDcLRBqN/s0RKArBfyDZf/Rw
# 2hUxvqZf6NLo2z4WYTV1mln7Nl3+gJTlF0RLzbY9sg2r27S0/eYBbzpGF/4at6dj
# n8fzpvTuWLQGGKraATBeTrn7QTnSso0Y6y7Y1+SO/IJ11d0xdhN7P99FiiRlvTJI
# l74x6r7Yiss5+1YNFjkJEtPv+PXxBh9wR7N3HU6UncslAJO0mt2B10ZijYno
# SIG # End signature block
