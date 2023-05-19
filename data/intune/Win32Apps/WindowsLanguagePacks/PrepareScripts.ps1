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

$deviceKeyboard = "00000807"
$packageRoot = "$PSScriptRoot"
if (-Not (Test-Path "$packageRoot\Scripts\localesToInstall.json"))
{
    . $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1
    Install-ModuleIfNotInstalled "MSStore"

    try
    {
        Write-Warning "Please login to your store for business"
        if (-Not $Global:StroreCreds)
        {
            $Global:StroreCreds = Get-Credential -Message "Please provide MS Store admin credentials"
        }
        Connect-MSStore -Credentials $Global:StroreCreds
        $apps = Get-MSStoreInventory -IncludeOffline -MaxResults 999
    } catch
    {
        Write-Warning "Please grant access to the store app"
        Grant-MSStoreClientAppAccess
        Connect-MSStore -Credentials $Global:StroreCreds
        $apps = Get-MSStoreInventory -IncludeOffline -MaxResults 999
    }

    $languagesToInstall = @()

    #Getting en-US
    Write-Host "Getting Local Experience Pack en-US"
    $pck = $apps | Where-Object { $_.ProductTitle.StartsWith("English (United States) Local Experience Pack") }
    if (-Not $pck) { throw "Can't find local experience pack 'English (United States) Local Experience Pack' in your store!" }
    $req = Invoke-WebRequestIndep -UseBasicParsing -Uri "https://bspmts.mp.microsoft.com/v1/public/catalog/Retail/Products/$($pck.ProductId)/applockerdata"
    $languagesToInstall += @{
        "Locale" = "en-US"
        "ProductId" = $pck.ProductId
        "SkuId" = $pck.SkuId
        "ProductTitle" = $pck.ProductTitle
        "LicenseType" = $pck.LicenseType
        "PackageFamilyName" = ($req | ConvertFrom-JSON).packageFamilyName
        "GeoId" = $AlyaGeoId
        "InputLanguageID" = "0409:$deviceKeyboard" # en-US: United States - English (0409:00000409) en-CHde: Swiss German (0807:00000807)
    }
    $ass = Get-MSStoreSeatAssignments -ProductId $pck.ProductId -SkuId $pck.SkuId
    if (-Not $ass -or $ass.Count -eq 0)
    {
        Write-Host "No assignment found. Creating one for current user"
        $tmp = Add-MSStoreSeatAssignment -ProductId $pck.ProductId -SkuId $pck.SkuId -Username $Global:StroreCreds.UserName
    }

    #Getting it-IT
    Write-Host "Getting Local Experience Pack it-IT"
    $pck = $apps | Where-Object { $_.ProductTitle.StartsWith("italiano Pacchetto di esperienze locali") }
    if (-Not $pck) { throw "Can't find local experience pack 'italiano Pacchetto di esperienze locali' in your store!" }
    $req = Invoke-WebRequestIndep -UseBasicParsing -Uri "https://bspmts.mp.microsoft.com/v1/public/catalog/Retail/Products/$($pck.ProductId)/applockerdata"
    $languagesToInstall += @{
        "Locale" = "it-IT"
        "ProductId" = $pck.ProductId
        "SkuId" = $pck.SkuId
        "ProductTitle" = $pck.ProductTitle
        "LicenseType" = $pck.LicenseType
        "PackageFamilyName" = ($req | ConvertFrom-JSON).packageFamilyName
        "GeoId" = $AlyaGeoId
        "InputLanguageID" = "0810:$deviceKeyboard" #it-IT: Italian (0410:00000410) it-CH: Swiss French (0810:0000100c) it-CH: Italian (0810:00000410)
    }
    $ass = Get-MSStoreSeatAssignments -ProductId $pck.ProductId -SkuId $pck.SkuId
    if (-Not $ass -or $ass.Count -eq 0)
    {
        Write-Host "No assignment found. Creating one for current user"
        $tmp = Add-MSStoreSeatAssignment -ProductId $pck.ProductId -SkuId $pck.SkuId -Username $Global:StroreCreds.UserName
    }

    #Getting fr-FR
    Write-Host "Getting Local Experience Pack fr-FR"
    $pck = $apps | Where-Object { $_.ProductTitle.StartsWith("Module d'expérience locale français (France)") }
    if (-Not $pck) { throw "Can't find local experience pack 'Module d'expérience locale français (France)' in your store!" }
    $req = Invoke-WebRequestIndep -UseBasicParsing -Uri "https://bspmts.mp.microsoft.com/v1/public/catalog/Retail/Products/$($pck.ProductId)/applockerdata"
    $languagesToInstall += @{
        "Locale" = "fr-FR"
        "ProductId" = $pck.ProductId
        "SkuId" = $pck.SkuId
        "ProductTitle" = $pck.ProductTitle
        "LicenseType" = $pck.LicenseType
        "PackageFamilyName" = ($req | ConvertFrom-JSON).packageFamilyName
        "GeoId" = $AlyaGeoId
        "InputLanguageID" = "100c:$deviceKeyboard" #fr-FR: French (040c:0000040c) fr-CH: Swiss French (100c:0000100c)	de-CH: Swiss German (0807:00000807)
    }
    $ass = Get-MSStoreSeatAssignments -ProductId $pck.ProductId -SkuId $pck.SkuId
    if (-Not $ass -or $ass.Count -eq 0)
    {
        Write-Host "No assignment found. Creating one for current user"
        $tmp = Add-MSStoreSeatAssignment -ProductId $pck.ProductId -SkuId $pck.SkuId -Username $Global:StroreCreds.UserName
    }

    #Getting de-DE
    Write-Host "Getting Local Experience Pack de-DE"
    $pck = $apps | Where-Object { $_.ProductTitle.StartsWith("Deutsch Local Experience Pack") }
    if (-Not $pck) { throw "Can't find local experience pack 'Deutsch Local Experience Pack' in your store!" }
    $req = Invoke-WebRequestIndep -UseBasicParsing -Uri "https://bspmts.mp.microsoft.com/v1/public/catalog/Retail/Products/$($pck.ProductId)/applockerdata"
    $languagesToInstall += @{
        "Locale" = "de-DE"
        "ProductId" = $pck.ProductId
        "SkuId" = $pck.SkuId
        "ProductTitle" = $pck.ProductTitle
        "LicenseType" = $pck.LicenseType
        "PackageFamilyName" = ($req | ConvertFrom-JSON).packageFamilyName
        "GeoId" = $AlyaGeoId
        "InputLanguageID" = "0807:$deviceKeyboard" # de-DE: German (0407:00000407) de-CH: Swiss German (0807:00000807) fr-CH: Swiss French (100C:0000100C)
    }
    $ass = Get-MSStoreSeatAssignments -ProductId $pck.ProductId -SkuId $pck.SkuId
    if (-Not $ass -or $ass.Count -eq 0)
    {
        Write-Host "No assignment found. Creating one for current user"
        $tmp = Add-MSStoreSeatAssignment -ProductId $pck.ProductId -SkuId $pck.SkuId -Username $Global:StroreCreds.UserName
    }

    $languagesToInstall | ConvertTo-Json -Depth 50 | Set-Content -Path "$packageRoot\Scripts\localesToInstall.json" -Force -Encoding UTF8
}
