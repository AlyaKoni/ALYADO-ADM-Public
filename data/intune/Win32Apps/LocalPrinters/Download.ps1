#Requires -Version 2

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

. "$PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1"

$hpPclDownloadUrl = "https://ftp.hp.com/pub/softlib/software13/COL40842/ds-99374-23/upd-pcl6-x64-7.0.0.24832.exe"
$hpPsDownloadUrl = "https://ftp.hp.com/pub/softlib/software13/COL40842/ds-99376-23/upd-ps-x64-7.0.0.24832.exe"
$sharpPclDownloadUrl = "http://global.sharp/restricted/products/copier/downloads/search/files/021418/SH_D09_PCL6_PS_2005a_German_64bit.exe"
$innoextractDownloadUrl = "https://constexpr.org/innoextract/files/innoextract-1.9-windows.zip"

$packageRoot = "$PSScriptRoot"
$contentRoot = Join-Path $packageRoot "ContentZip"

# HpPcl6
$instPath = Join-Path $contentRoot "HpPcl6"
if ((Test-Path $instPath))
{
    Remove-Item -Path $instPath -Recurse -Force
}
$null = New-Item -Path $instPath -ItemType Directory -Force
$unpackFile = Join-Path $contentRoot "driver.zip"
$req = Invoke-WebRequestIndep -Uri $hpPclDownloadUrl -Method Get -OutFile $unpackFile
$cmdTst = Get-Command -Name "Expand-Archive" -ParameterName "DestinationPath" -ErrorAction SilentlyContinue
if ($cmdTst)
{
    Expand-Archive -Path $unpackFile -DestinationPath $instPath -Force #AlyaAutofixed
}
else
{
    Expand-Archive -Path $unpackFile -OutputPath $instPath -Force #AlyaAutofixed
}
Remove-Item -Path $unpackFile -Force

# HpPs6
$instPath = Join-Path $contentRoot "HpPs"
if ((Test-Path $instPath))
{
    Remove-Item -Path $instPath -Recurse -Force
}
$null = New-Item -Path $instPath -ItemType Directory -Force
$unpackFile = Join-Path $contentRoot "driver.zip"
$req = Invoke-WebRequestIndep -Uri $hpPsDownloadUrl -Method Get -OutFile $unpackFile
$cmdTst = Get-Command -Name "Expand-Archive" -ParameterName "DestinationPath" -ErrorAction SilentlyContinue
if ($cmdTst)
{
    Expand-Archive -Path $unpackFile -DestinationPath $instPath -Force #AlyaAutofixed
}
else
{
    Expand-Archive -Path $unpackFile -OutputPath $instPath -Force #AlyaAutofixed
}
Remove-Item -Path $unpackFile -Force

# innoextract
$instPath = Join-Path $contentRoot "innoextract"
if ((Test-Path $instPath))
{
    Remove-Item -Path $instPath -Recurse -Force
}
$null = New-Item -Path $instPath -ItemType Directory -Force
$unpackFile = Join-Path $contentRoot "innoextract.zip"
$req = Invoke-WebRequestIndep -Uri $innoextractDownloadUrl -Method Get -OutFile $unpackFile
$cmdTst = Get-Command -Name "Expand-Archive" -ParameterName "DestinationPath" -ErrorAction SilentlyContinue
if ($cmdTst)
{
    Expand-Archive -Path $unpackFile -DestinationPath $instPath -Force #AlyaAutofixed
}
else
{
    Expand-Archive -Path $unpackFile -OutputPath $instPath -Force #AlyaAutofixed
}
Remove-Item -Path $unpackFile -Force
$innopath = $instPath
$innoextract = Join-Path $instPath "innoextract.exe"

# SharpPcl6
$instPath = Join-Path $contentRoot "SharpPcl6"
if ((Test-Path $instPath))
{
    Remove-Item -Path $instPath -Recurse -Force
}
$null = New-Item -Path $instPath -ItemType Directory -Force
$unpackFile = Join-Path $contentRoot "driver.exe"
$req = Invoke-WebRequestIndep -Uri $sharpPclDownloadUrl -Method Get -OutFile $unpackFile
Push-Location -Path $instPath
& "$innoextract" $unpackFile
Pop-Location
Remove-Item -Path $innopath -Recurse -Force
Remove-Item -Path $unpackFile -Force
