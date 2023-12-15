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

$deviceKeyboard = "00000807"
$packageRoot = "$PSScriptRoot"
$languagesToInstall = @()

#Getting en-US
$languagesToInstall += @{
	"Order" = 4
	"Locale" = "en-US"
	"LanguageTag" = "en-CH"
	"ProductId" = "9PDSCC711RVF"
	"SkuId" = "0016"
	"ProductTitle" = "English (United States) Local Experience Pack"
	"LicenseType" = "online"
	"PackageFamilyName" = "Microsoft.LanguageExperiencePacken-US_8wekyb3d8bbwe"
	"GeoId" = $AlyaGeoId
	"InputLanguageID" = "0409:$deviceKeyboard"
}

#Getting it-IT
$languagesToInstall += @{
	"Order" = 2
	"Locale" = "it-IT"
	"LanguageTag" = "it-CH"
	"ProductId" = "9P8PQWNS6VJX"
	"SkuId" = "0016"
	"ProductTitle" = "italiano Pacchetto di esperienze locali"
	"LicenseType" = "online"
	"PackageFamilyName" = "Microsoft.LanguageExperiencePackit-IT_8wekyb3d8bbwe"
	"GeoId" = $AlyaGeoId
	"InputLanguageID" = "0810:$deviceKeyboard"
}

#Getting fr-FR
$languagesToInstall += @{
	"Order" = 1
	"Locale" = "fr-FR"
	"LanguageTag" = "fr-CH"
	"ProductId" = "9NHMG4BJKMDG"
	"SkuId" = "0016"
	"ProductTitle" = "Module d\u0027expérience locale français (France)"
	"LicenseType" = "online"
	"PackageFamilyName" = "Microsoft.LanguageExperiencePackfr-FR_8wekyb3d8bbwe"
	"GeoId" = $AlyaGeoId
	"InputLanguageID" = "100c:$deviceKeyboard"
}

#Getting de-DE
$languagesToInstall += @{
	"Order" = 3
	"Locale" = "de-DE"
	"LanguageTag" = "de-CH"
	"ProductId" = "9P6CT0SLW589"
	"SkuId" = "0016"
	"ProductTitle" = "Deutsch Local Experience Pack"
	"LicenseType" = "online"
	"PackageFamilyName" = "Microsoft.LanguageExperiencePackde-DE_8wekyb3d8bbwe"
	"GeoId" = $AlyaGeoId
	"InputLanguageID" = "0807:$deviceKeyboard"
}

$languagesToInstall | ConvertTo-Json -Depth 50 | Set-Content -Path "$packageRoot\Scripts\localesToInstall.json" -Force -Encoding UTF8
