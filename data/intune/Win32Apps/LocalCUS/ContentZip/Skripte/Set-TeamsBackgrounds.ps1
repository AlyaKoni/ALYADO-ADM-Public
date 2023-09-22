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

Write-Host "Alya Teams Backgrounds"
Write-Host "======================"
$storageRoot = "https://alyainfpstrg001.blob.core.windows.net/teams/"
$customer = "AlyaConsulting"
$teamsDir = "$env:APPDATA\Microsoft\Teams"
$uploadsDir = "$teamsDir\Backgrounds\Uploads"
if (-Not (Test-Path $teamsDir))
{
    throw "Teams directory $teamsDir not found. Is Teams installed?"
}
if (-Not (Test-Path $uploadsDir))
{
    $null = New-Item -Path $uploadsDir -ItemType Directory -Force
}
$tryFileList = @(
    "fluentSpaces3Own.png",
    "fluentSpaces4Own.png",
    "teamsBackgroundContemporaryOffice02Own.png",
    "teamsBackgroundHomeOwn.png",
    "teamsBackgroundTraditionalOffice01Own.png"
)
foreach($tryFile in $tryFileList)
{
    try
    {
        $outFile = "$uploadsDir\$customer-$tryFile"
        if (Test-Path $outFile)
        {
            $null = Remove-Item -Path $outFile -Force -ErrorAction SilentlyContinue
        }
        $req = Invoke-WebRequest -UseBasicParsing -Uri ($storageRoot+"$tryFile") -Method Get -OutFile $outFile -ErrorAction SilentlyContinue
    }
    catch {}
}
