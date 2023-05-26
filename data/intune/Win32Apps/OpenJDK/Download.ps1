#Requires -Version 2

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


#>

. "$PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1"

#
# Downloading Setup Exe
#

$pageUrl = "https://www.oracle.com/java/technologies/javase-downloads.html"
$req = Invoke-WebRequestIndep -Uri $pageUrl -UseBasicParsing -Method Get
[regex]$regex = "[^`"']*javase-(?!server)[^`"']*jre[^`"']*downloads\.html"
$newUrl = "https://www.oracle.com"+([regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value)
$req = Invoke-WebRequestIndep -Uri $newUrl -UseBasicParsing -Method Get
[regex]$regex = "[^`"']*jre[^`"']*windows-x64\.exe"
$fileUrl = ([regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value)
$fileName = $fileUrl.SubString($fileUrl.LastIndexOf("/")+1)

Write-Host "`n`n"
Write-Host "JRE download"
Write-Host "====================="

Write-Host "`n`n"
Write-Host "We browse now to:"
Write-Host "  $newUrl"
Write-Host "Please download the following file:"
Write-Host "  $fileName"
Write-Host "`n"
pause
Write-Host "`n"

$packageRoot = "$PSScriptRoot"
$contentRoot = Join-Path $packageRoot "Content"
if (-Not (Test-Path $contentRoot))
{
    $tmp = New-Item -Path $contentRoot -ItemType Directory -Force
}
$profile = [Environment]::GetFolderPath("UserProfile")
$downloads = $profile+"\downloads"
$lastfilename = $null
$file = Get-ChildItem -path $downloads | sort LastWriteTime | Select-Object -last 1
if ($file)
{
    $lastfilename = $file.Name
}
$filename = $null
$attempts = 10
while ($attempts -ge 0)
{
    Write-Host "Downloading setup file from $newUrl"
    Write-Warning "Please don't start any other download!"
    try {
        Start-Process $newUrl
        do
        {
            Start-Sleep -Seconds 10
            $file = Get-ChildItem -path $downloads | sort LastWriteTime | Select-Object -last 1
            if ($file)
            {
                $filename = $file.Name
                if ($filename.Contains("crdownload")) { $filename = $lastfilename }
                if ($filename.Contains("partial")) { $filename = $lastfilename }
            }
        } while ($lastfilename -eq $filename)
        $attempts = -1
    } catch {
        Write-Host "Catched exception $($_.Exception.Message)"
        Write-Host "Retrying $attempts times"
        $attempts--
        if ($attempts -lt 0) { throw }
        Start-Sleep -Seconds 10
    }
}
Start-Sleep -Seconds 3
if ($filename)
{
    $sourcePath = $downloads+"\"+$filename
    $patch = Get-ChildItem -Path $contentRoot -Filter "*.exe"
    if ($patch)
    {
        $patch | Remove-Item -Force
    }
    Move-Item -Path $sourcePath -Destination $contentRoot -Force
}
else
{
    throw "We were not able to download the setup file"
}
