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

Write-Host "    Preparing version"
$packageRoot = "$PSScriptRoot"
$versionFile = Join-Path $packageRoot "version.json"
if ((Test-Path $versionFile))
{
    $versionObj = Get-Content -Path $versionFile -Raw -Encoding UTF8 | ConvertFrom-Json
    $version = $versionObj.version
}
else
{
    $versionObj = @{}
    $versionObj.version = "1.0"
    $version = $versionObj.version
}
Write-Host "      actual: $version"

$contentPath = Join-Path $packageRoot "Content"
$zip = Get-ChildItem -Path $contentPath -Filter "*.zip"
[regex]$regex = "-(.*?)_"
$versionStr = [regex]::Match($zip[0].Name, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Groups[1].Value

Write-Host "      new: $versionStr"
if (-Not $versionStr.Contains(".")) { $versionStr = $versionStr + ".0" }
$versionObj.version = $versionStr
$versionObj | ConvertTo-Json | Set-Content -Path $versionFile -Encoding UTF8 -Force
Copy-Item -Path $versionFile -Destination $contentPath
