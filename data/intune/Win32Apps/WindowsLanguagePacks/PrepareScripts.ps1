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
    $pck = $apps | where { $_.ProductTitle.StartsWith("English (United States) Local Experience Pack") }
    if (-Not $pck) { throw "Can't find local experience pack 'English (United States) Local Experience Pack' in your store!" }
    $req = Invoke-WebRequest -UseBasicParsing -Uri "https://bspmts.mp.microsoft.com/v1/public/catalog/Retail/Products/$($pck.ProductId)/applockerdata"
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
    $pck = $apps | where { $_.ProductTitle.StartsWith("italiano Pacchetto di esperienze locali") }
    if (-Not $pck) { throw "Can't find local experience pack 'italiano Pacchetto di esperienze locali' in your store!" }
    $req = Invoke-WebRequest -UseBasicParsing -Uri "https://bspmts.mp.microsoft.com/v1/public/catalog/Retail/Products/$($pck.ProductId)/applockerdata"
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
    $pck = $apps | where { $_.ProductTitle.StartsWith("Module d'exp�rience locale fran�ais (France)") }
    if (-Not $pck) { throw "Can't find local experience pack 'Module d'exp�rience locale fran�ais (France)' in your store!" }
    $req = Invoke-WebRequest -UseBasicParsing -Uri "https://bspmts.mp.microsoft.com/v1/public/catalog/Retail/Products/$($pck.ProductId)/applockerdata"
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
    $pck = $apps | where { $_.ProductTitle.StartsWith("Deutsch Local Experience Pack") }
    if (-Not $pck) { throw "Can't find local experience pack 'Deutsch Local Experience Pack' in your store!" }
    $req = Invoke-WebRequest -UseBasicParsing -Uri "https://bspmts.mp.microsoft.com/v1/public/catalog/Retail/Products/$($pck.ProductId)/applockerdata"
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