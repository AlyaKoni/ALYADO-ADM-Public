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

$pageUrl = "https://kdiff3.sourceforge.net/"
$appName = "kdiff3"

$req = Invoke-WebRequestIndep -Uri $pageUrl -UseBasicParsing -Method Get

[regex]$regex = "[^`"]*diff3[^`"]*\.dmg/download"
$newUrl = [regex]::Match($req.Content, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value.Replace("..","")
$fileName = Split-Path -Path $newUrl.Replace("/download", "") -Leaf

$packageRoot = "$PSScriptRoot"
$contentRoot = Join-Path $packageRoot "Content"
if (-Not (Test-Path $contentRoot))
{
    $null = New-Item -Path $contentRoot -ItemType Directory -Force
}
Invoke-WebRequestIndep -UseBasicParsing -Method Get -UserAgent "Wget" -Uri $newUrl -Outfile "$contentRoot\$fileName"

[regex]$regex = "(\d+\.){2}\d+"
$versionStr = [regex]::Match($fileName, $regex, [Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant').Value

$dirName = $fileName.Replace(".dmg","")
$null = New-Item -Path "$contentRoot/$dirName" -ItemType Directory -Force

hdiutil attach -nobrowse -readonly "$contentRoot/$fileName"
$volume = "/Volumes/$appName"
rsync -av "/Volumes/$appName" "$contentRoot/$dirName" --exclude .Trashes
hdiutil detach $volume

$plistCont = Get-Content -Path "$contentRoot/$dirName/$appName/$appName.app/Contents/Info.plist" -Encoding utf8 -Raw
$idx = $plistCont.IndexOf("<key>CFBundleIdentifier</key>")
$plistContNew = $plistCont.Substring(0,$idx) + "<key>CFBundleVersion</key>`n`t<string>$versionStr</string>`n`t" + $plistCont.Substring($idx)
$plistContNew | Set-Content -Path "$contentRoot/$dirName/$appName/$appName.app/Contents/Info.plist" -Encoding utf8

$pkgName = $fileName.Replace(".dmg", ".pkg")
productbuild --sign $AlyaMacPackageInstallCertName --component "$contentRoot/$dirName/$appName/$appName.app" "/Applications" "$contentRoot/$pkgName"

Remove-Item -Path "$contentRoot/$fileName" -Force
Remove-Item -Path "$contentRoot/$dirName" -Recurse -Force
