$deviceKeyboard = "00000807"
$packageRoot = "$PSScriptRoot"
if (-Not (Test-Path "$packageRoot\Scripts\localesToInstall.json"))
{
    . $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1
    Install-ModuleIfNotInstalled "MSStore"

    try
    {
        $apps = Get-MSStoreInventory -IncludeOffline -MaxResults 999
    } catch
    {
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
    }

    $languagesToInstall = @()

    #Getting en-US
    $pck = $apps | Where-Object { $_.ProductTitle.StartsWith("English (United States) Local Experience Pack") }
    if (-Not $pck) { throw "Can't find local experience pack 'English (United States) Local Experience Pack' in your store!" }
    $req = Invoke-WebRequest -SkipHttpErrorCheck -UseBasicParsing -Uri "https://bspmts.mp.microsoft.com/v1/public/catalog/Retail/Products/$($pck.ProductId)/applockerdata"
    $languagesToInstall += @{
        "Order" = 4
        "Locale" = "en-US"
        "LanguageTag" = "en-CH"
        "ProductId" = $pck.ProductId
        "SkuId" = $pck.SkuId
        "ProductTitle" = $pck.ProductTitle
        "LicenseType" = $pck.LicenseType
        "PackageFamilyName" = ($req | ConvertFrom-JSON).packageFamilyName
        "GeoId" = $AlyaGeoId
        "InputLanguageID" = "0409:$deviceKeyboard" # en-US: United States - English (0409:00000409) en-CHde: Swiss German (0807:00000807)
    }

    #Getting it-IT
    $pck = $apps | Where-Object { $_.ProductTitle.StartsWith("italiano Pacchetto di esperienze locali") }
    if (-Not $pck) { throw "Can't find local experience pack 'italiano Pacchetto di esperienze locali' in your store!" }
    $req = Invoke-WebRequest -SkipHttpErrorCheck -UseBasicParsing -Uri "https://bspmts.mp.microsoft.com/v1/public/catalog/Retail/Products/$($pck.ProductId)/applockerdata"
    $languagesToInstall += @{
        "Order" = 1
        "Locale" = "it-IT"
        "LanguageTag" = "it-CH"
        "ProductId" = $pck.ProductId
        "SkuId" = $pck.SkuId
        "ProductTitle" = $pck.ProductTitle
        "LicenseType" = $pck.LicenseType
        "PackageFamilyName" = ($req | ConvertFrom-JSON).packageFamilyName
        "GeoId" = $AlyaGeoId
        "InputLanguageID" = "0810:$deviceKeyboard" #it-IT: Italian (0410:00000410) it-CH: Swiss French (0810:0000100c) it-CH: Italian (0810:00000410)
    }

    #Getting fr-FR
    $pck = $apps | Where-Object { $_.ProductTitle.StartsWith("Module d'expérience locale français (France)") }
    if (-Not $pck) { throw "Can't find local experience pack 'Module d'expérience locale français (France)' in your store!" }
    $req = Invoke-WebRequest -SkipHttpErrorCheck -UseBasicParsing -Uri "https://bspmts.mp.microsoft.com/v1/public/catalog/Retail/Products/$($pck.ProductId)/applockerdata"
    $languagesToInstall += @{
        "Order" = 2
        "Locale" = "fr-FR"
        "LanguageTag" = "fr-CH"
        "ProductId" = $pck.ProductId
        "SkuId" = $pck.SkuId
        "ProductTitle" = $pck.ProductTitle
        "LicenseType" = $pck.LicenseType
        "PackageFamilyName" = ($req | ConvertFrom-JSON).packageFamilyName
        "GeoId" = $AlyaGeoId
        "InputLanguageID" = "100c:$deviceKeyboard" #fr-FR: French (040c:0000040c) fr-CH: Swiss French (100c:0000100c)	de-CH: Swiss German (0807:00000807)
    }

    #Getting de-DE
    $pck = $apps | Where-Object { $_.ProductTitle.StartsWith("Deutsch Local Experience Pack") }
    if (-Not $pck) { throw "Can't find local experience pack 'Deutsch Local Experience Pack' in your store!" }
    $req = Invoke-WebRequest -SkipHttpErrorCheck -UseBasicParsing -Uri "https://bspmts.mp.microsoft.com/v1/public/catalog/Retail/Products/$($pck.ProductId)/applockerdata"
    $languagesToInstall += @{
        "Order" = 3
        "Locale" = "de-DE"
        "LanguageTag" = "de-CH"
        "ProductId" = $pck.ProductId
        "SkuId" = $pck.SkuId
        "ProductTitle" = $pck.ProductTitle
        "LicenseType" = $pck.LicenseType
        "PackageFamilyName" = ($req | ConvertFrom-JSON).packageFamilyName
        "GeoId" = $AlyaGeoId
        "InputLanguageID" = "0807:$deviceKeyboard" # de-DE: German (0407:00000407) de-CH: Swiss German (0807:00000807) fr-CH: Swiss French (100C:0000100C)
    }

    $languagesToInstall | ConvertTo-Json -Depth 50 | Set-Content -Path "$packageRoot\Scripts\localesToInstall.json" -Force -Encoding UTF8
}
