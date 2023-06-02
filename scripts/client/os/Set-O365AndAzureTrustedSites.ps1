#Requires -Version 2.0
#Requires -RunAsAdministrator

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


    History:
    Date       Author     Description
    ---------- -------------------- ----------------------------
    13.03.2019 Konrad Brunner       Initial Version

#>

[CmdletBinding(DefaultParameterSetName='HKEY_CURRENT_USER')] 
Param
(
    [Parameter(ParameterSetName="HKEY_CURRENT_USER", Mandatory=$false)]
    [switch] $HKCU = $false,
    [Parameter(ParameterSetName="HKEY_LOCAL_MACHINE", Mandatory=$false)]
    [switch] $HKLM = $false
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\client\os\Set-O365AndAzureTrustedSites-$((Get-Date).ToString("yyyyMMddHHmmss")).log" | Out-Null

#TODO local URLs in Intranet Zone dword:00000001

Write-Host "Getting URLs from services" -ForegroundColor $CommandInfo
$urlsToSet = & "$($AlyaScripts)\network\Get-MSIPRangesAndUrls.ps1" -urlsonly -dataonly

Write-Host "Generating registry entries" -ForegroundColor $CommandInfo
$regStr = "Windows Registry Editor Version 5.00`n`n"
foreach ($url in $urlsToSet)
{
    $zone = "00000002"
    if ($url.Contains("login.microsoftonline.com") -or $url.Contains("autologon.microsoftazuread-sso.com")) { $zone = "00000001" }
    $dom = $url.Substring($url.IndexOf(".") + 1)
    $sub = $url.Substring(0, $url.IndexOf("."))
    $regStr += "[$($PsCmdlet.ParameterSetName)\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\$($dom)\$($sub)]`n"
    $regStr += "`"https`"=dword:$($zone)`n`n"
}

$regFile = "$($AlyaData)\client\os\Set-O365AndAzureTrustedSites-$((Get-Date).ToString("yyyyMMddHHmmss")).reg"
if (-Not (Test-Path "$($AlyaData)\client\os2"))
{
    $null = New-Item -Path "$($AlyaData)\client\os" -ItemType Directory -Force
}
Write-Host "Generating registry file $($regFile)" -ForegroundColor $CommandInfo
$regStr | Set-Content -Path $regFile -Force

Write-Host "Importing registry file '$($AlyaData)\client\os'" -ForegroundColor $CommandInfo
& $regFile

#Stopping Transscript
Stop-Transcript
