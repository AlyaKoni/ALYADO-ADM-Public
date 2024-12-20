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

. "$PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1"

if (-not $AlyaIsPsUnix)
{
    throw "Please run this script on a mac"
}

$pageUrl = "https://www.sourcetreeapp.com/"
$appName = "Sourcetree"

$req = Invoke-WebRequestIndep -Uri $pageUrl -UseBasicParsing -Method Get
[regex]$regex = "[^`"]*ga/Sourcetree[^`"]*\.zip"
$newUrl = [regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
$fileName = Split-Path -Path $newUrl -Leaf
$packageRoot = "$PSScriptRoot"
$contentRoot = Join-Path $packageRoot "Content"
if (-Not (Test-Path $contentRoot))
{
    $null = New-Item -Path $contentRoot -ItemType Directory -Force
}
Invoke-WebRequestIndep -UseBasicParsing -Method Get -UserAgent "Wget" -Uri $newUrl -Outfile "$contentRoot\$fileName"

$dirName = Split-Path -Path $fileName -LeafBase
#$dmgName = $fileName.Replace(".zip", ".dmg")
$pkgName = $fileName.Replace(".zip", ".pkg")
unzip "$contentRoot/$fileName" -d "$contentRoot/$dirName"

[regex]$regex = "(\d+\.){2}\d+"
$versionStr = [regex]::Match($fileName, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value
[regex]$regex = "(\d+\.){2}\d+_(\d+)"
$bundleVersion = [regex]::Match($fileName, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Groups[2].Value

$plistCont = Get-Content -Path "$contentRoot/$dirName/$appName.app/Contents/Info.plist" -Encoding utf8 -Raw
$plistContNew = $plistCont.Replace("<string>$bundleVersion</string>", "<string>$versionStr</string>")
$plistContNew | Set-Content -Path "$contentRoot/$dirName/$appName.app/Contents/Info.plist" -Encoding utf8

productbuild --sign $AlyaMacPackageInstallCertName --component "$contentRoot/$dirName/$appName.app" "/Applications" "$contentRoot/$pkgName"
#productbuild --sign $AlyaMacPackageInstallCertName --component "/Applications/$appName.app" "$contentRoot/$pkgName"
#pkgbuild --install-location "/Applications" --component "$contentRoot/$dirName/$appName.app" "$contentRoot/$pkgName"
#hdiutil create -srcfolder "$contentRoot/$dirName"  -volname "$dirName" "$contentRoot/$dmgName"
#installer -pkg "$contentRoot/$pkgName" -target /

Remove-Item -Path "$contentRoot\$fileName" -Recurse -Force
Remove-Item -Path "$contentRoot\$dirName" -Recurse -Force
