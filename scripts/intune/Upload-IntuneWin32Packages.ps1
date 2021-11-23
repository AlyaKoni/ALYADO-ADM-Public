#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2021

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
    30.09.2020 Konrad Brunner       Initial Version
    23.10.2021 Konrad Brunner       Added apps path

#>

[CmdletBinding()]
Param(
    [string]$UploadOnlyAppWithName = $null,
    [string]$ContinueAtAppWithName = $null,
    [string]$AppsPath = "Win32Apps"
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Upload-IntuneWin32Packages-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# Constants
$AppPrefix = "Win10 "
$DataRoot = Join-Path (Join-Path $AlyaData "intune") $AppsPath
if (-Not (Test-Path $DataRoot))
{
    $tmp = New-Item -Path $DataRoot -ItemType Directory -Force
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "AzureAdPreview"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Upload-IntuneWin32Packages | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context and token
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}
$token = Get-AdalAccessToken

# Main
$packages = Get-ChildItem -Path $DataRoot -Directory
$continue = $true
foreach($packageDir in $packages)
{
    if ($ContinueAtAppWithName -and $packageDir.Name -eq $ContinueAtAppWithName) { $continue = $false }
    if ($ContinueAtAppWithName -and $continue) { continue }
    if ($UploadOnlyAppWithName -and $packageDir.Name -ne $UploadOnlyAppWithName) { continue }
    if ($packageDir.Name -like "*unused*" -or $packageDir.Name -like "*donotuse*") { continue }

    Write-Host "Uploading package $($packageDir.Name)" -ForegroundColor $CommandInfo

    $packagePath = Join-Path $packageDir.FullName "Package"
    $configPath = Join-Path $packageDir.FullName "config.json"
    $contentPath = Join-Path $packageDir.FullName "Content"

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
        Write-Error "Please delete older once" -ErrorAction Continue
        continue
    }

    # Extracting package information
    Write-Host "  Extracting package information"
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($package.FullName)
    $entry = $zip.Entries | Where-Object { $_.Name -eq "Detection.xml" }
    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, "$($package.FullName).Detection.xml", $true)
    $zip.Dispose()
    $packageInfo = [xml](Get-Content -Path "$($package.FullName).Detection.xml" -Raw -Encoding UTF8)
    Remove-Item -Path "$($package.FullName).Detection.xml" -Force

    # Reading and preparing app configuration
    Write-Host "  Reading and preparing app configuration"
    $appConfig = Get-Content -Path $configPath -Raw -Encoding UTF8
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
            $toInstall = Get-ChildItem -Path $contentPath -Filter "*.msi" | Sort-Object -Property Name
            if (-Not $toInstall)
            {
                $toInstall = Get-ChildItem -Path $contentPath -Filter "*.exe" | Sort-Object -Property Name
            }
            if ($toInstall)
            {
                if ($toInstall.Count -gt 1)
                {
                    $toInstall = $toInstall[0]
                }
                if ($toInstall.VersionInfo.FileVersion)
                {
                    $version = $toInstall.VersionInfo.FileVersion
                }
                elseif ($toInstall.VersionInfo.ProductVersion)
                {
                    $version = $toInstall.VersionInfo.ProductVersion
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
                $ruleWVersion.detectionValue = $version
                $ruleWVersion.keyPath = $regPath
                $ruleWVersion.valueName = $regValue
            }
            foreach($ruleWVersion in $appConfig.rules)
            {
                $ruleWVersion.comparisonValue = $version
                $ruleWVersion.keyPath = $regPath
                $ruleWVersion.valueName = $regValue
            }
        }
        else
        {
            foreach($ruleWVersion in $appConfig.detectionRules)
            {
                $ruleWVersion.detectionValue = ([Version]$version).ToString()
            }
            foreach($ruleWVersion in $appConfig.rules)
            {
                $ruleWVersion.comparisonValue = ([Version]$version).ToString()
            }
        }
    }

    $logo = Get-ChildItem -Path $packageDir.FullName -Filter "Logo.*"
    if ($logo)
    {
        $iconResponse = Invoke-WebRequest "$($logo.FullName)"
        $base64icon = [System.Convert]::ToBase64String($iconResponse.Content)
        $iconExt = ([System.IO.Path]::GetExtension($logo.FullName)).replace(".","")
        $iconType = "image/$iconExt"
        $appConfig.largeIcon = @{ "@odata.type" = "#microsoft.graph.mimeContent" }
        $appConfig.largeIcon.type = "$iconType"
        $appConfig.largeIcon.value = "$base64icon"
    }

    $appConfigJson = $appConfig | ConvertTo-Json
    $appConfigJson | Set-Content -Path $configPath -Encoding UTF8

    # Checking if app exists
    Write-Host "  Checking if app exists"
    $searchValue = [System.Web.HttpUtility]::UrlEncode($appConfig.displayName)
    $uri = "https://graph.microsoft.com/Beta/deviceAppManagement/mobileApps?`$filter=displayName eq '$searchValue'"
    $app = (Get-MsGraphObject -AccessToken $token -Uri $uri).value
    if (-Not $app.id)
    {
        # Creating app
        Write-Host "  Creating app"
        $uri = "https://graph.microsoft.com/Beta/deviceAppManagement/mobileApps"
        $app = Post-MsGraph -AccessToken $token -Uri $uri -Body $appConfigJson
    }

    # Extracting intunewin file
    Write-Host "  Extracting intunewin file"
    $zip = [System.IO.Compression.ZipFile]::OpenRead($package.FullName)
    $entry = $zip.Entries | Where-Object { $_.Name -eq "IntunePackage.intunewin" }
    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, "$($package.FullName).Extracted", $true)
    $zip.Dispose()
    $bytes = [System.IO.File]::ReadAllBytes("$($package.FullName).Extracted")
    Remove-Item -Path "$($package.FullName).Extracted" -Force

    # Creating Content Version
    Write-Host "  Creating Content Version"
	$appId = $app.id
    Write-Host "    appId: $($app.id)"
	$uri = "https://graph.microsoft.com/Beta/deviceAppManagement/mobileApps/$appId/microsoft.graph.win32LobApp/contentVersions"
	$contentVersion = Post-MsGraph -AccessToken $token -Uri $uri -Body "{}"
    Write-Host "    contentVersion: $($contentVersion.id)"

    # Creating Content Version file
    Write-Host "  Creating Content Version file"
	$fileBody = @{ "@odata.type" = "#microsoft.graph.mobileAppContentFile" }
	$fileBody.name = $package.Name
	$fileBody.size = [long]$packageInfo.ApplicationInfo.UnencryptedContentSize
	$fileBody.sizeEncrypted = [long]$bytes.Length
	$fileBody.manifest = $null
    $fileBody.isDependency = $false
	$uri = "https://graph.microsoft.com/Beta/deviceAppManagement/mobileApps/$appId/microsoft.graph.win32LobApp/contentVersions/$($contentVersion.id)/files"
	$file = Post-MsGraph -AccessToken $token -Uri $uri -Body ($fileBody | ConvertTo-Json -Depth 50)

    # Waiting for file uri
    Write-Host "  Waiting for file uri"
    $uri = "https://graph.microsoft.com/Beta/deviceAppManagement/mobileApps/$appId/microsoft.graph.win32LobApp/contentVersions/$($contentVersion.id)/files/$($file.id)"
    $stage = "AzureStorageUriRequest"
	$successState = "$($stage)Success"
	$pendingState = "$($stage)Pending"
	$failedState = "$($stage)Failed"
	$timedOutState = "$($stage)TimedOut"
	$Global:attempts = 100
	while ($Global:attempts -gt 0)
	{
		Start-Sleep -Seconds 3
		$file = Get-MsGraphObject -AccessToken $token -Uri $uri
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
		throw "File request did not complete within $Global:attempts attempts"
	}

    # Uploading intunewin content
    Write-Host "  Uploading intunewin content"
    $OldProgressPreference = $ProgressPreference
    $ProgressPreference = "Continue"
    Start-Sleep -Seconds 10 # first chunk has often 403
    $chunkSizeInBytes = 1024 * 1024 * 6
	$sasRenewalTimer = [System.Diagnostics.Stopwatch]::StartNew()
	$chunks = [Math]::Ceiling($bytes.Length / $chunkSizeInBytes)
    $enc = [System.Text.Encoding]::GetEncoding("iso-8859-1")
	$ids = @()
	for ($chunk = 0; $chunk -lt $chunks; $chunk++)
    {
		$id = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($chunk.ToString("0000")))
		$ids += $id
        $start = $chunk * $chunkSizeInBytes
        $end = [Math]::Min($start + $chunkSizeInBytes - 1, $bytes.Length - 1)
        $body = $bytes[$start..$end]
        $encodedBody = $enc.GetString($body)
        $headers = @{
	        "x-ms-blob-type" = "BlockBlob"
        }
		$currentChunk = $chunk + 1
        Write-Progress -Activity "    Uploading intunewin from $($package.Name)" -status "      Uploading chunk $currentChunk of $chunks" -percentComplete ($currentChunk / $chunks*100)
        $curi = "$($file.azureStorageUri)&comp=block&blockid=$id"
        $Global:attempts = 10
        while ($Global:attempts -ge 0)
        {
            try {
                do {
                    try {
                        $response = Invoke-WebRequest -Uri $curi -Method Put -Headers $headers -Body $encodedBody
                        $StatusCode = $response.StatusCode
                    } catch {
                        $StatusCode = $_.Exception.Response.StatusCode.value__
                        if ($StatusCode -eq 429) {
                            Write-Warning "Got throttled by Microsoft. Sleeping for 45 seconds..."
                            Start-Sleep -Seconds 45
                        }
                        else {
                            try { Write-Host ($_.Exception | ConvertTo-Json -Depth 2) -ForegroundColor $CommandError } catch {}
                            throw
                        }
                    }
                } while ($StatusCode -eq 429)
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
	        $renewalUri = "$uri/renewUpload"
	        $rewnewUriResult = Post-MsGraph -AccessToken $token -Uri $uri -Body "{}"	
            $stage = "AzureStorageUriRenewal"
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
		        throw "File request renewel did not complete within $Global:attempts attempts"
	        }
			$sasRenewalTimer.Restart()
        }
	}
    Write-Progress -Completed -Activity "    Uploading intunewin"
	$ProgressPreference = $OldProgressPreference

	# Finalize the upload.
	$curi = "$($file.azureStorageUri)&comp=blocklist"
	$xml = '<?xml version="1.0" encoding="utf-8"?><BlockList>'
	foreach ($id in $ids)
	{
		$xml += "<Latest>$id</Latest>"
	}
	$xml += '</BlockList>'
    do {
        try {
            $response = Invoke-WebRequest -Uri $curi -Method Put -Body $xml
            $StatusCode = $response.StatusCode
        } catch {
            $StatusCode = $_.Exception.Response.StatusCode.value__
            if ($StatusCode -eq 429) {
                Write-Warning "Got throttled by Microsoft. Sleeping for 45 seconds..."
                Start-Sleep -Seconds 45
            }
            else {
                try { Write-Host ($_.Exception | ConvertTo-Json -Depth 2) -ForegroundColor $CommandError } catch {}
                throw
            }
        }
    } while ($StatusCode -eq 429)

    # Committing the file
    Write-Host "  Committing the file"
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
    $curi = "https://graph.microsoft.com/Beta/deviceAppManagement/mobileApps/$appId/microsoft.graph.win32LobApp/contentVersions/$($contentVersion.id)/files/$($file.id)/commit"
	$file = Post-MsGraph -AccessToken $token -Uri $curi -Body ($fileEncryptionInfo | ConvertTo-Json -Depth 50)

    # Waiting for file commit
    Write-Host "  Waiting for file commit"
    $stage = "CommitFile"
	$successState = "$($stage)Success"
	$pendingState = "$($stage)Pending"
	$failedState = "$($stage)Failed"
	$timedOutState = "$($stage)TimedOut"
	$Global:attempts = 100
	while ($Global:attempts -gt 0)
	{
		Start-Sleep -Seconds 3
		$file = Get-MsGraphObject -AccessToken $token -Uri $uri
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

    # Committing the app
    Write-Host "  Committing the app"
    Add-Member -InputObject $appConfig -MemberType NoteProperty -Name "committedContentVersion" -Value $contentVersion.id
    $uri = "https://graph.microsoft.com/Beta/deviceAppManagement/mobileApps/$appId"
    $appP = Patch-MsGraph -AccessToken $token -Uri $uri -Body ($appConfig | ConvertTo-Json -Depth 50)
}

#Stopping Transscript
Stop-Transcript