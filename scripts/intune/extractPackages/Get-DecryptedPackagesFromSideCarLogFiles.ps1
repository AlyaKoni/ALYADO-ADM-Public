﻿#Requires -Version 2

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


#>

<#
Version: 1.0
Author:  Oliver Kieselbach
Script:  Get-DecryptInfoFromSideCarLogFiles.ps1

Description:
run as Admin on a device where you are AADJ and Intune enrolled to successfully decrypt 
the log message containing decryption info for Intune Win32 apps (.intunewin)

Release notes:
Version 1.0: Original published version.

The script is provided "AS IS" with no warranties.
#>

function Decrypt($base64string)
{
    [System.Reflection.Assembly]::LoadWithPartialName("System.Security") | Out-Null

    $content = [Convert]::FromBase64String($base64string)
    $envelopedCms = New-Object Security.Cryptography.Pkcs.EnvelopedCms
    $certCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $envelopedCms.Decode($content)
    $envelopedCms.Decrypt($certCollection)

    $utf8content = [text.encoding]::UTF8.getstring($envelopedCms.ContentInfo.Content)

    return $utf8content
}

$agentLogPath = Join-Path $env:ProgramData "Microsoft\IntuneManagementExtension\Logs\IntuneManagementExtension.log"
$stringToSearchResp = "<![LOG[Get content info from service,ret = {"
$stringToSearchPoly = "<![LOG[Get policies = [{"

Write-Host "Getting intune apps"
$apps = @()
$policies = @()
Get-Content $agentLogPath | ForEach-Object {
    if ($nextRespLine) {
        $reply = "{$($_.ToString().TrimStart())}" | ConvertFrom-Json
        
        $responsePayload = ($reply.ResponsePayload | ConvertFrom-Json)
        $contentInfo = ($responsePayload.ContentInfo | ConvertFrom-Json)
        $decryptInfo = Decrypt(([xml]$responsePayload.DecryptInfo).EncryptedMessage.EncryptedContent) | ConvertFrom-Json

        "  ApplicationId: $($responsePayload.ApplicationId)"
        "    URL: $($contentInfo.UploadLocation)"
        "    Key: $($decryptInfo.EncryptionKey)"
        "    IV:  $($decryptInfo.IV)"

        $apps += @{ "ApplicationId"= "$($responsePayload.ApplicationId)";
                    "URL"= "$($contentInfo.UploadLocation)";
                    "Key"= "$($decryptInfo.EncryptionKey)";
                    "IV"= "$($decryptInfo.IV)"}

        $nextRespLine = $false
    }
    if ($_.ToString().StartsWith($stringToSearchResp) -eq $true) {
        $nextRespLine = $true
    }
    if ($_.ToString().StartsWith($stringToSearchPoly) -eq $true) {
        $repl = $_.ToString().TrimStart()
        $repl = $repl.Substring($stringToSearchPoly.Length, $repl.IndexOf("}]]LOG]!>")-$stringToSearchPoly.Length)
        foreach($pol in ("[{$($repl)}]" | ConvertFrom-Json))
        {
            $extPol = $policies | Where-Object { $_.Id -eq $pol.Id }
            if (-Not $extPol)
            {
                $policies += $pol
            }
            else
            {
                $policies[$policies.IndexOf($extPol)] = $pol
            }
        }
    }
}

$failedAppsPath = "C:\Program Files (x86)\Microsoft Intune Management Extension\Content\Incoming"
$extractToPath = [Environment]::GetFolderPath("Desktop")
$failedApps = Get-ChildItem -Path $failedAppsPath -Filter "*.bin"

Write-Host "Getting failed apps"
Add-Type -AssemblyName System.IO.Compression.FileSystem
$failedApps | ForEach-Object {
    Write-Host "  Found failed app: $($_.Name)"
    foreach($app in $apps)
    {
        if ($_.Name -like "$($app.ApplicationId)*")
        {
            $pol = $policies | Where-Object { $_.Id -eq $app.ApplicationId }
            Write-Host "    AppID: $($app.ApplicationId)"
            Write-Host "      Name: $($pol.Name)"
            Write-Host "      InstallCommand: $($pol.InstallCommandLine)"
            $outpath = Join-Path $extractToPath ($app.ApplicationId + "_failed")
            Write-Host "      Content: $($outpath)"
            $encFile = & "$PSScriptRoot\IntuneWinAppUtilDecoder.exe" `"$($app.URL)`" /key:$($app.Key) /iv:$($app.IV)
            $decFile = $encFile[3].Substring(6, $encFile[3].LastIndexOf("'")-6)
            $decFileZip = $decFile + ".decoded"
            if (-Not (Test-Path $outpath))
            {
                New-Item -ItemType Directory -Path $outpath | Out-Null
            }
            else
            {
                Remove-Item -Path $outpath -Recurse -Force | Out-Null
                New-Item -ItemType Directory -Path $outpath | Out-Null
            }
            [System.IO.Compression.ZipFile]::ExtractToDirectory($decFileZip, $outpath)
            break
        }
    }
}

Write-Host "Getting successfull apps"
foreach($app in $apps)
{
    $fapp = $failedApps | Where-Object { $_.Name -like "$($app.ApplicationId)*" }
    if (-Not $fapp)
    {
        Write-Host "  Found successfull app: $($app.ApplicationId)"
        $pol = $policies | Where-Object { $_.Id -eq $app.ApplicationId }
        Write-Host "    AppID: $($app.ApplicationId)"
        Write-Host "      Name: $($pol.Name)"
        Write-Host "      InstallCommand: $($pol.InstallCommandLine)"
        $outpath = Join-Path $extractToPath ($app.ApplicationId + "_success")
        Write-Host "      Content: $($outpath)"
        $encFile = & "$PSScriptRoot\IntuneWinAppUtilDecoder.exe" `"$($app.URL)`" /key:$($app.Key) /iv:$($app.IV)
        $decFile = $encFile[3].Substring(6, $encFile[3].LastIndexOf("'")-6)
        $decFileZip = $decFile + ".decoded"
        if (-Not (Test-Path $outpath))
        {
            New-Item -ItemType Directory -Path $outpath | Out-Null
        }
        else
        {
            Remove-Item -Path $outpath -Recurse -Force | Out-Null
            New-Item -ItemType Directory -Path $outpath | Out-Null
        }
        [System.IO.Compression.ZipFile]::ExtractToDirectory($decFileZip, $outpath)
    }
}
