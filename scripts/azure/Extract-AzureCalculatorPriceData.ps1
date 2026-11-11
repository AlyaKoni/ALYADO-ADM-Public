#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2026

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
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
    Date       Author               Description
    ---------- -------------------- ----------------------------
    18.03.2021 Konrad Brunner       Initial Version
    06.02.2026 Konrad Brunner       Added powershell documentation
    19.10.2026 Konrad Brunner       Platform-dependent Close-ExcelPackage (-Show on Windows only)

#>

<#
.SYNOPSIS
Extracts Azure pricing and benchmark data from the Azure Pricing Calculator and related APIs, and exports the results to Excel files for reference and analysis.

.DESCRIPTION
The Extract-AzureCalculatorPriceData.ps1 script retrieves detailed pricing data for multiple Azure services such as Virtual Machines, Disks, PostgreSQL, Azure SQL Database, and related benchmarks. It queries official Microsoft pricing APIs to collect current configuration, currency, and service pricing data, converts these into structured PowerShell objects, and exports them to an Excel workbook with multiple worksheets. Each worksheet represents a service category (e.g., PricesVMs, PricesDisks, PricesPostgreSql, PricesAzureSqlDatabase, etc.), providing a complete analytical overview of Azure cost components. The script also downloads performance benchmark tables for Windows and Linux VM sizes from Microsoft documentation pages.

.PARAMETER exportCurrencyName
Specifies the currency for which pricing data should be exported. Defaults to "chf".

.INPUTS
None. All configuration data and input values are obtained from environment scripts and online Azure APIs.

.OUTPUTS
An Excel workbook containing Azure service price and benchmark data saved at the configured data path.

.EXAMPLE
PS> .\Extract-AzureCalculatorPriceData.ps1 -exportCurrencyName "usd"

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    $exportCurrencyName = "chf"
)

# Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transcript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\Extract-AzureCalculatorData-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ImportExcel"

# Main
Write-Host "Getting actual configuration"
$resp = Invoke-WebRequestIndep -UseBasicParsing -Method GET -Uri "https://azure.microsoft.com/en-us/pricing/calculator/"
$mtch = $resp.Content -match "global.currencyData = (.*);"
$exportCurrencyData = ConvertFrom-Json -InputObject $Matches[1]
$mtch = $resp.Content -match "name=`"awa-stv`" content=`"(.*)`""
$version = $Matches[1]
$culture = "en-us"
$discount = "mosp"
$csvDelemiter = ";"
$query = "?culture=$culture&discount=$discount&v=$version"
$exportCurrency = $exportCurrencyData."$exportCurrencyName"

Write-Host "Getting data"
$support = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v2/pricing/support/calculator/$query"
$categories = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v2/pricing/categories/calculator/$query"
$regions = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v2/pricing/calculator/regions/$query"
$resources = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v2/calculator/resources/$query"
$currencies = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v2/currencies/$query"
$config = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v2/calculator/config/$query"
$manageddisks = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v2/pricing/managed-disks/calculator/$query"
$storage = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v3/pricing/storage/calculator/$query"
$bandwidth = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v2/pricing/bandwidth/calculator/$query"
$virtualmachines = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v3/pricing/virtual-machines/calculator/$query"
$postgresql = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v3/pricing/postgresql/calculator/$query"
$config = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v2/calculator/config/$query"
$azuresqldatabase = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v3/pricing/azure-sql-database/calculator/$query"
$functions = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v2/pricing/functions/calculator/$query"
$backup = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v2/pricing/backup/calculator/$query"
$monitor = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v2/pricing/monitor/calculator/$query"
$automation = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v2/pricing/automation/calculator/$query"
$keyvault = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v2/pricing/key-vault/calculator/$query"
$analysisservices = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v2/pricing/analysis-services/calculator/$query"

$computeWinBenchmarks = Invoke-WebRequestIndep -UseBasicParsing -Method GET -Uri "https://learn.microsoft.com/en-us/azure/virtual-machines/windows/compute-benchmark-scores"

############################################################################################
Write-Host "Building products table" -ForegroundColor $CommandInfo
$productsCsv = [System.Collections.ArrayList]@()
foreach ($categorySlug in $categories.slug)
{
    $category = $categories | Where-Object { $_.slug -eq $categorySlug }
    #Write-Host "Category: $($category.displayName)"
    foreach ($productSlug in $category.products.slug)
    {
        $product = $category.products | Where-Object { $_.slug -eq $productSlug }
        #Write-Host "  Product: $($product.displayName)"

        $pricingUrl = Iif ($null -eq $product.links -or [string]::IsNullOrEmpty($product.links.pricingUrl)) $null {$product.links.pricingUrl.Replace("acom:", "https://azure.microsoft.com").Replace("docs:", "https://learn.microsoft.com")}
        $documentationUrl = Iif ($null -eq $product.links -or [string]::IsNullOrEmpty($product.links.documentationUrl)) $null {$product.links.documentationUrl.Replace("acom:", "https://azure.microsoft.com").Replace("docs:", "https://learn.microsoft.com")}
        $url = Iif ($null -eq $product.links -or [string]::IsNullOrEmpty($product.links.url)) $null {$product.links.url.Replace("acom:", "https://azure.microsoft.com").Replace("docs:", "https://learn.microsoft.com")}
        $slaUrl = Iif ($null -eq $product.links -or [string]::IsNullOrEmpty($product.links.slaUrl)) $null {$product.links.slaUrl.Replace("acom:", "https://azure.microsoft.com").Replace("docs:", "https://learn.microsoft.com")}
        $roadmapUrl = Iif ($null -eq $product.links -or [string]::IsNullOrEmpty($product.links.roadmapUrl)) $null {$product.links.roadmapUrl.Replace("acom:", "https://azure.microsoft.com").Replace("docs:", "https://learn.microsoft.com")}
        if ($pricingUrl -eq "#") { $pricingUrl = "" }
        if ($documentationUrl -eq "#") { $documentationUrl = "" }
        if ($url -eq "#") { $url = "" }
        if ($slaUrl -eq "#") { $slaUrl = "" }
        if ($roadmapUrl -eq "#") { $roadmapUrl = "" }
        if ($pricingUrl -and $pricingUrl.StartsWith("/")) { $pricingUrl = "https://azure.microsoft.com"+$pricingUrl }
        if ($documentationUrl -and $documentationUrl.StartsWith("/")) { $documentationUrl = "https://azure.microsoft.com"+$documentationUrl }
        if ($url -and $url.StartsWith("/")) { $url = "https://azure.microsoft.com"+$url }
        if ($slaUrl -and $slaUrl.StartsWith("/")) { $slaUrl = "https://azure.microsoft.com"+$slaUrl }
        if ($roadmapUrl -and $roadmapUrl.StartsWith("/")) { $roadmapUrl = "https://azure.microsoft.com"+$roadmapUrl }

        $obj = [pscustomobject]@{
            category = $category.displayName
            product = $product.displayName
            description = $product.description
            keywords = $product.keywords
            pricingUrl = $pricingUrl
            documentationUrl = $documentationUrl
            url = $url
            slaUrl = $slaUrl
            roadmapUrl = $roadmapUrl
        }
        $productsCsv.Add($obj) | Out-Null
    }
}
Write-Host "Exporting Excel - Sheet PricesProducts" -ForegroundColor $CommandInfo
$excel = $productsCsv | Export-Excel -Path "$AlyaData\azure\PricesAndBenchmarks.xlsx" -WorksheetName "PricesProducts" -TableName "PricesProducts" -BoldTopRow -AutoFilter -FreezeTopRow -ClearSheet -PassThru -NoNumberConversion *
Close-ExcelPackage $excel
#Clear-Variable -Name "productsCsv" -Force -ErrorAction SilentlyContinue

############################################################################################
Write-Host "Building postgresql table" -ForegroundColor $CommandInfo
$allOffers = @{}
foreach ($offerName in (Get-Member -InputObject $postgresql.offers))
{
    if (@("Equals","GetHashCode","GetType","ToString","Copy","Invoke","IsInstance","MemberType","Name","OverloadDefinitions","TypeNameOfValue","Value") -notcontains $offerName.Name)
    {
        $offer = $postgresql.offers."$($offerName.Name)"
        $membs = Get-Member -InputObject $offer.prices
        foreach($memb in $membs)
        {
            if (@("Equals","GetHashCode","GetType","ToString","Copy","Invoke","IsInstance","MemberType","Name","OverloadDefinitions","TypeNameOfValue","Value") -notcontains $memb.Name)
            {
                $fullOfferPriceName = $offerName.Name+"--"+$memb.Name
                $allOffers.Add($fullOfferPriceName, $offer.prices."$($memb.Name)") | Out-Null
            }
        }
    }
}
$allSkus = [System.Collections.ArrayList]@()
foreach ($sku in (Get-Member -InputObject $postgresql.skus))
{
    if (@("Equals","GetHashCode","GetType","ToString","Copy","Invoke","IsInstance","MemberType","Name","OverloadDefinitions","TypeNameOfValue","Value") -notcontains $sku.Name)
    {
        $membs = Get-Member -InputObject $postgresql.skus."$($sku.Name)"
        foreach($memb in $membs)
        {
            if (@("Equals","GetHashCode","GetType","ToString","Copy","Invoke","IsInstance","MemberType","Name","OverloadDefinitions","TypeNameOfValue","Value") -notcontains $memb.Name)
            {
                $offers = $postgresql.skus."$($sku.Name)"."$($memb.Name)"
                foreach($offer in $offers)
                {
                    $priceName = $offer.Substring($offer.LastIndexOf("-") + 1, $offer.Length - $offer.LastIndexOf("-") - 1)
                    if (-Not $allSkus.Contains($priceName))
                    {
                        $allSkus.Add($priceName) | Out-Null
                    }
                }
            }
        }
    }
}

$dbTypes = @()
foreach ($atype in $postgresql.types)
{
    $dbTypes += $atype.slug
}
$dbTypes += @(
    "hyperscalecitus",
    "flexible-server",
    ""
)
$dbTypes = $dbTypes | Sort-Object { -($_.length) }

$dbTiers = @()
foreach ($atype in $postgresql.tiers)
{
    $dbTiers += $atype.slug
}
$dbTiers += @(
    "basic-generalpurpose",
    "standard-generalpurpose",
    "standard",
    "momoryoptimized",
    ""
)
$dbTiers = $dbTiers | Sort-Object { -($_.length) }

$dbPurchaseModels = @()
foreach ($atype in $postgresql.purchaseModels)
{
    $dbPurchaseModels += $atype.slug
}
$dbPurchaseModels += @(
    "compute",
    "backup",
    "storage",
    "amd-compute",
    ""
)
$dbPurchaseModels = $dbPurchaseModels | Sort-Object { -($_.length) }

$priceMembers = @()
$postgresqlCsv = [System.Collections.ArrayList]@()
foreach ($region in $postgresql.regions)
{
    #$region = $postgresql.regions | Where-Object { $_.slug -eq "switzerland-north" }
    #if ($region.slug -ne "europe-west") { continue }
    #Write-Host "Region: $($region.displayName)"
    $doneSku = @()
    foreach ($dbType in $dbTypes)
    {
        foreach ($dbTier in $dbTiers)
        {
            if (-Not [string]::IsNullOrEmpty($dbType) -and -Not [string]::IsNullOrEmpty($dbTier)) { $dbTier = "-"+$dbTier }
            foreach ($dbPurchaseModel in $dbPurchaseModels)
            {
                if (-Not [string]::IsNullOrEmpty($dbTier) -and -Not [string]::IsNullOrEmpty($dbPurchaseModel)) { $dbPurchaseModel = "-"+$dbPurchaseModel }
                $skuName = "$dbType$dbTier$dbPurchaseModel"
                #Write-Host "  skuName: $($skuName)"
                if ([string]::IsNullOrEmpty($skuName)) { continue }
                $skus = @()
                $sks = $postgresql.skus.PSObject.Properties | Where-Object { $_.Name.StartsWith($skuName) }
                foreach($sk in $sks)
                {
                    $instance = $sk.Name.Replace($sk.Name, "").Trim("-")
                    $dashCnt = $instance.Length - $instance.Replace("-", "").Count
                    #Write-Host "  sk: $($sk.Name)"
                    #Write-Host "  dashCnt: $($dashCnt)"
                    if ($dashCnt -lt 2)
                    {
                        $skus += @($sk.Name)
                    }
                }
                foreach($skun in $skus)
                {
                    if ($doneSku -notcontains $skun)
                    {
                        $instance = $skun.Replace($skuName, "").Trim("-")
                        #Write-Host "    "
                        #Write-Host "    SkuName: $($skun)"
                        #Write-Host "      Instance: $($instance)"
                        $sku = $postgresql.skus."$skun"

                        $serverType = $dbType.Trim("-")
                        if ([string]::IsNullOrEmpty($serverType)) { $serverType = "server" }
                        $obj = [pscustomobject]@{
                            dbType = $serverType
                            dbTier = $dbTier.Trim("-").Replace("momoryoptimized", "memoryoptimized")
                            dbPurchaseModel = $dbPurchaseModel.Trim("-")
                            instance = $instance.Trim("-")
                            region = $region.displayName
                        }
                        $onePriceFound = $false
                        foreach($skuPriceName in (Get-Member -InputObject $sku))
                        {
                            if (@("Equals","GetHashCode","GetType","ToString","Copy","Invoke","IsInstance","MemberType","Name","OverloadDefinitions","TypeNameOfValue","Value") -notcontains $skuPriceName.Name)
                            {
                                #Write-Host "      Price: $($skuPriceName.Name)"
                                $priceName = "price$($skuPriceName.Name)"
                                $price = 0.0
                                $offers = $sku."$($skuPriceName.Name)"
                                $priceType = $null
                                foreach($offer in $offers)
                                {
                                    #Write-Host "        Offer: $($offer)"
                                    if ($null -eq $priceType)
                                    {
                                        $priceType = $offer.Replace($skun, "").Trim("-")
                                        $priceName = "price-$priceType-$($skuPriceName.Name)"
                                    }
                                    $prices = $allOffers[$offer]
                                    $memb = Get-Member -InputObject $prices -Name $region.slug -ErrorAction SilentlyContinue
                                    if ($memb)
                                    {
                                        $price += $prices."$($region.slug)".value * $exportCurrency.modernConversion
                                        $onePriceFound = $true
                                    }
                                    $offerName = $offer.Substring(0, $offer.LastIndexOf("-") - 1)
                                }
                                if ($price -eq 0.0) { $price = $null }
                                if ($priceMembers -notcontains $priceName) { $priceMembers += $priceName }
                                Add-Member -InputObject $obj -MemberType NoteProperty -Name $priceName -Value $price
                            }
                        }
                        if ($onePriceFound) { $postgresqlCsv.Add($obj) | Out-Null }
                                
                        $doneSku += $skun
                    }
                }
            }
        }
    }
}
foreach($row in $postgresqlCsv)
{
    foreach($memberName in $priceMembers)
    {
        $memb = Get-Member -InputObject $row -Name $memberName -ErrorAction SilentlyContinue
        if (-Not $memb)
        {
            Add-Member -InputObject $row -MemberType NoteProperty -Name $memberName -Value $null
        }
    }
}
Write-Host "Exporting Excel - Sheet PricesPostgreSql" -ForegroundColor $CommandInfo
$excel = $postgresqlCsv | Export-Excel -Path "$AlyaData\azure\PricesAndBenchmarks.xlsx" -WorksheetName "PricesPostgreSql" -TableName "PricesPostgreSql" -BoldTopRow -AutoFilter -FreezeTopRow -ClearSheet -PassThru -NoNumberConversion *
Close-ExcelPackage $excel
#Clear-Variable -Name "postgresqlCsv" -Force -ErrorAction SilentlyContinue

############################################################################################
Write-Host "Building disk table" -ForegroundColor $CommandInfo

$tierSlugs =  $manageddisks.tiers.slug
$tierSlugs += "burstable"
$tierSlugs += "transactions"
$tierSlugs += "premiumssd-v2"
$tierSlugs = $tierSlugs | Sort-Object { $_ }

$sizeSlugs =  $manageddisks.sizes.slug
$sizeSlugs += "hdd"
$sizeSlugs += "ssd"
$sizeSlugs += "snapshot"
$sizeSlugs += "enablement"
$sizeSlugs += "transaction"
$sizeSlugs = $sizeSlugs | Sort-Object { $_ }

$redundancySlugs =  $manageddisks.tierRedundancies.slug
$redundancySlugs += ""
$redundancySlugs = $redundancySlugs | Sort-Object { $_ }

$addTypes = @("-disk-mount", "-one-year", "")
$addTypes = $addTypes | Sort-Object { $_ }

$diskCsv = [System.Collections.ArrayList]@()
foreach ($region in $manageddisks.regions)
{
    #$region = $manageddisks.regions | Where-Object { $_.slug -eq "switzerland-north" }
    #Write-Host "Region: $($region.displayName)"
    foreach ($tierSlug in $tierSlugs)
    {
        #$tierSlug = $tierSlugs | Where-Object { $_ -eq "premiumssd" }
        $tier = $manageddisks.tiers | Where-Object { $_.slug -eq $tierSlug }
        $tierName = $tier.displayName
        if ([string]::IsNullOrEmpty($tierName)) { $tierName = $tierSlug }
        #$tier = $manageddisks.tiers | Where-Object { $_.slug -eq "standardssd" }
        #Write-Host "  Tier: $($tierName)"
        foreach ($sizeSlug in $sizeSlugs)
        {
            $size = $manageddisks.sizes | Where-Object { $_.slug -eq $sizeSlug }
            $sizeName = $size.displayName
            if ([string]::IsNullOrEmpty($sizeName)) { $sizeName = $sizeSlug }
            #Write-Host "    Size: $($sizeName)"
            $sizeSlug = $sizeSlug -replace "ultra", ""
            foreach ($redundancySlug in $redundancySlugs)
            {
                $redundancy = $manageddisks.tierRedundancies | Where-Object { $_.slug -eq $redundancySlug }
                #$redundancy = $manageddisks.tierRedundancies | Where-Object { $_.slug -eq "lrs" }
                #Write-Host "      Redundancy: $($redundancy.displayName)"
                foreach ($addType in $addTypes)
                {
                    $offerName = "$tierSlug-$sizeSlug-$redundancySlug$addType"
                    if ([string]::IsNullOrEmpty($redundancySlug))
                    {
                        $offerName = "$tierSlug-$sizeSlug$addType"
                    }
                    $memb = Get-Member -InputObject $manageddisks.offers -Name $offerName -ErrorAction SilentlyContinue
                    if ($memb)
                    {
                        $offer = $manageddisks.offers.$offerName
                        $memb = Get-Member -InputObject $offer.prices -Name $region.slug -ErrorAction SilentlyContinue
                        if ($memb)
                        {
                            $price = $offer.prices."$($region.slug)".value * $exportCurrency.modernConversion
                            $obj = [pscustomobject]@{
                                tier = $tierName
                                sizeName = $sizeName
                                redundancy = $redundancy.displayName+$addType
                                region = $region.displayName
                                offer = $offerName
                                iops = $offer.iops
                                size = $offer.size
                                speed = $offer.speed
                                pricingTypes = $offer.pricingTypes
                                burstingIops = $offer.burstingIops
                                burstingThroughput = $offer.burstingThroughput
                                maxPaidTransaction = $offer.maxPaidTransaction
                                price = $price
                            }
                            $diskCsv.Add($obj) | Out-Null
                        }
                    }
                }
            }
        }
    }
}
Write-Host "Exporting Excel - Sheet PricesDisks" -ForegroundColor $CommandInfo
$excel = $diskCsv | Export-Excel -Path "$AlyaData\azure\PricesAndBenchmarks.xlsx" -WorksheetName "PricesDisks" -TableName "PricesDisks" -BoldTopRow -AutoFilter -FreezeTopRow -ClearSheet -PassThru -NoNumberConversion *
Close-ExcelPackage $excel
#Clear-Variable -Name "diskCsv" -Force -ErrorAction SilentlyContinue

############################################################################################
Write-Host "Building compute table" -ForegroundColor $CommandInfo
$allSkus = [System.Collections.ArrayList]@()
foreach ($sku in $virtualmachines.skus.PSObject.Properties)
{
    if (@("Equals","GetHashCode","GetType","ToString","Copy","Invoke","IsInstance","MemberType","Name","OverloadDefinitions","TypeNameOfValue","Value") -notcontains $sku.Name)
    {
        foreach($memb in $virtualmachines.skus."$($sku.Name)".PSObject.Properties)
        {
            if (@("Equals","GetHashCode","GetType","ToString","Copy","Invoke","IsInstance","MemberType","Name","OverloadDefinitions","TypeNameOfValue","Value") -notcontains $memb.Name)
            {
                if (-Not $allSkus.Contains($memb.Name))
                {
                    $allSkus.Add($memb.Name) | Out-Null
                }
            }
        }
    }
}
$allPrices = [System.Collections.ArrayList]@()
foreach ($offerName in $virtualmachines.offers.PSObject.Properties)
{
    if (@("Equals","GetHashCode","GetType","ToString","Copy","Invoke","IsInstance","MemberType","Name","OverloadDefinitions","TypeNameOfValue","Value") -notcontains $offerName.Name)
    {
        $offer = $virtualmachines.offers."$($offerName.Name)"
        foreach($memb in $offer.prices.PSObject.Properties)
        {
            if (@("Equals","GetHashCode","GetType","ToString","Copy","Invoke","IsInstance","MemberType","Name","OverloadDefinitions","TypeNameOfValue","Value") -notcontains $memb.Name)
            {
                if (-Not $allPrices.Contains($memb.Name))
                {
                    $allPrices.Add($memb.Name) | Out-Null
                }
            }
        }
    }
}
$allOffers = @{}
foreach ($offerName in $virtualmachines.offers.PSObject.Properties)
{
    if (@("Equals","GetHashCode","GetType","ToString","Copy","Invoke","IsInstance","MemberType","Name","OverloadDefinitions","TypeNameOfValue","Value") -notcontains $offerName.Name)
    {
        $offer = $virtualmachines.offers."$($offerName.Name)"
        foreach($memb in $offer.prices.PSObject.Properties)
        {
            if (@("Equals","GetHashCode","GetType","ToString","Copy","Invoke","IsInstance","MemberType","Name","OverloadDefinitions","TypeNameOfValue","Value") -notcontains $memb.Name)
            {
                $fullOfferPriceName = $offerName.Name+"--"+$memb.Name
                $allOffers.Add($fullOfferPriceName, $offer.prices."$($memb.Name)") | Out-Null
            }
        }
    }
}
$slugCount = $virtualmachines.tiers.Count * $virtualmachines.regions.Count * $virtualmachines.dropdown.slug.Count
$slugsDone = 0
$allPriceCols = [System.Collections.ArrayList]@()
$computeCsv = [System.Collections.ArrayList]@()
Write-Host "  Processing $($slugCount) items"
foreach ($operatingSystem in ($virtualmachines.operatingSystems | Sort-Object -Property "displayName" -Descending))
{
    #$operatingSystem = $virtualmachines.operatingSystems | Where-Object { $_.slug -eq "windows" }
    #Write-Host "Operating System: $($operatingSystem.displayName)"
    foreach ($tier in $virtualmachines.tiers)
    {
        #$tier = $virtualmachines.tiers | Where-Object { $_.slug -eq "standard" }
        #Write-Host "  Tier: $($tier.displayName)"
        $virtualmachines.regions += @{
            slug = "global"
            displayName = "Global"
        }
        foreach ($region in $virtualmachines.regions)
        {
            #$region = $virtualmachines.regions | Where-Object { $_.slug -eq "switzerland-north" }
            #Write-Host "    Region: $($region.displayName)"
            foreach ($groupSlug in ($virtualmachines.dropdown.slug | Sort-Object))
            {

                #not sku ends with one of the


                #$groupSlug = $virtualmachines.dropdown.slug | Where-Object { $_ -eq "memoryoptimized" }
                $slugsDone++
                if (($slugsDone % 50) -eq 0) { Write-Host "$($slugsDone)..." -NoNewLine }
                $group = $virtualmachines.dropdown | Where-Object { $_.slug -eq $groupSlug }
                $groupName = $group.displayName
                if ([string]::IsNullOrEmpty($groupName)) { $groupName = $groupSlug }
                if ([string]::IsNullOrEmpty($groupName)) { $groupName = "All" }
                #Write-Host "      Group: $($groupName)"
                $groupSeries = $group.series
                foreach ($subgroupSlug in ($groupSeries.slug | Sort-Object))
                {
                    #$subgroupSlug = ($groupSeries.slug | Sort-Object) | Where-Object { $_ -eq "esv5" }
                    $subgroup = $groupSeries | Where-Object { $_.slug -eq $subgroupSlug }
                    $subgroupName = $subgroup.displayName
                    if ([string]::IsNullOrEmpty($subgroupName)) { $subgroupName = $subgroupSlug }
                    #Write-Host "        Sub Group: $subgroupName"
                    $instances = $subgroup.instances
                    foreach ($instance in $instances)
                    {
                        #$instance = $instances | Where-Object { $_.slug -eq "e8sv5" }
                        #Write-Host "          Instance: $($operatingSystem.slug)-$slug-$($tier.slug)"
                        $slug = $instance.slug
                        $instanceName = $instance.displayName.Split(":")[0]
                        $instanceDesc = $instance.displayName.Split(":")[1]
                        $skuName = "$($operatingSystem.slug)-$slug-$($tier.slug)"
                        $features = $null
                        if (($instanceName -match '^[a-zA-Z]+(?:\d+-\d+|\d+)([a-zA-Z]*)'))
                        {
                            $features = $Matches[1]
                        }
                        $obj = [pscustomobject]@{
                            operatingSystem = $operatingSystem.displayName
                            tier = $tier.displayName
                            region = $region.displayName
                            group = $groupName
                            subgroup = $subgroupName
                            series = $null
                            instance = $skuName
                            name = $instanceName
                            desc = $instanceDesc
                            cores = $null
                            ram = $null
                            diskSize = $null
                            isVcpu = $null
                            gpu = $null
                            features = $features
                            isHidden = $null
                            pricingTypes = $null
                            offerType = $null
                        }
                        $prices = @{}
                        $memb = Get-Member -InputObject $virtualmachines.skus -Name $skuName -ErrorAction SilentlyContinue
                        if ($memb)
                        {

                            # $virtualmachines.skus."windows-e8dv4-standard"
                            # $virtualmachines.offers."windows-e8dv4-standard"
                            # $virtualmachines.offers."linux-e8dv4-standard"
                            # $virtualmachines.offers."windows-ri-8-core"

                            # $virtualmachines.offers."windows-e8dv4-standard".prices.perhour."switzerland-north" 1.1292
                            # $virtualmachines.offers."linux-e8dv4-standard".prices.perhouroneyearreserved."switzerland-north" 0.44909
                            # $virtualmachines.offers."windows-ri-8-core".prices.perhour."global" 0.368

                            # payg 1.1292
                            # one-year 0.81709

                            foreach ($priceName in $virtualmachines.skus."$skuName".PSObject.Properties.Name)
                            {
                                #"$priceName"
                                if ($priceName.StartsWith("sv-") -or $priceName.StartsWith("ahbsv-")) { continue }

                                $priceColName = "price-$priceName"
                                if ($allPriceCols -notcontains $priceColName) {
                                    $allPriceCols.Add($priceColName) | Out-Null
                                }
                                if (-Not $prices.Keys -contains $priceColName) { $prices."$priceColName" = 0 }


                                foreach ($offerNameFull in $virtualmachines.skus."$skuName"."$priceName")
                                {
                                    $offerName = $offerNameFull.Substring(0,$offerNameFull.IndexOf("--"))
                                    $offerPriceName = $offerNameFull.Substring($offerNameFull.IndexOf("--")+2)
                                    $offer = $virtualmachines.offers."$offerName"
                                    if ($offer)
                                    {
                                        #"  $offerName $offerPriceName $($region.slug)"
                                        if ($null -eq $obj.cores -and $null -ne $offer.cores) { $obj.cores = $offer.cores }
                                        if ($null -eq $obj.ram -and $null -ne $offer.ram) { $obj.ram = $offer.ram }
                                        if ($null -eq $obj.diskSize -and $null -ne $offer.diskSize) { $obj.diskSize = $offer.diskSize }
                                        if ($null -eq $obj.series -and $null -ne $offer.series) { $obj.series = $offer.series }
                                        if ($null -eq $obj.isVcpu -and $null -ne $offer.isVcpu) { $obj.isVcpu = $offer.isVcpu }
                                        if ($null -eq $obj.gpu -and $null -ne $offer.gpu) { $obj.gpu = $offer.gpu }
                                        if ($null -eq $obj.isHidden -and $null -ne $offer.isHidden) { $obj.isHidden = $offer.isHidden }
                                        if ($null -ne $offer.pricingTypes) { 
                                            if ($null -eq $obj.pricingTypes) { $obj.pricingTypes = $offer.pricingTypes }
                                            else { 
                                                if (-Not $obj.pricingTypes.Contains($offer.pricingTypes)) {
                                                    $obj.pricingTypes += ","+$offer.pricingTypes 
                                                }
                                            }
                                        }
                                        if ($null -ne $offer.offerType) { 
                                            if ($null -eq $obj.offerType) { $obj.offerType = $offer.offerType }
                                            else { 
                                                if (-Not $obj.pricingTypes.Contains($offer.offerType)) {
                                                    $obj.offerType += ","+$offer.offerType
                                                }
                                            }
                                        }
                                        $pmemb = Get-Member -InputObject $offer.prices."$offerPriceName" -Name "$($region.slug)" -ErrorAction SilentlyContinue
                                        if ($pmemb) {
                                            #"    $($offer.prices."$offerPriceName"."$($region.slug)".value)"
                                            $prices."$priceColName" += $offer.prices."$offerPriceName"."$($region.slug)".value * $exportCurrency.modernConversion
                                        }
                                        else {
                                            $pmemb = Get-Member -InputObject $offer.prices."$offerPriceName" -Name "global" -ErrorAction SilentlyContinue
                                            if ($pmemb) {
                                                #"    $($offer.prices."$offerPriceName"."global".value)"
                                                $prices."$priceColName" += $offer.prices."$offerPriceName"."global".value * $exportCurrency.modernConversion
                                            }
                                            else {
                                                #Write-Warning "    No price for region $($region.slug) in sku $skuName"
                                            }
                                        }
                                        #Add-Member -InputObject $obj -MemberType NoteProperty -Name $priceColName -Value $price
                                    }
                                    else {
                                        Write-Warning "    No offer $offerName in sku $skuName"
                                    }
                                }
                            }
                            <#
                            $virtualmachines.skus."ubuntu-pro-e96adsv5-standard"
                            payg          : {linux-e96adsv5-standard--perhour, ubuntu-pro-96-core--perhour}
                            one-year      : {linux-e96adsv5-standard--perhouroneyearreserved, ubuntu-pro-96-core--perhour}
                            three-year    : {linux-e96adsv5-standard--perhourthreeyearreserved, ubuntu-pro-96-core--perhour}
                            sv-one-year   : {linux-e96adsv5-standard--perunitoneyearsavings, ubuntu-pro-96-core--perhour}
                            sv-three-year : {linux-e96adsv5-standard--perunitthreeyearsavings, ubuntu-pro-96-core--perhour}
                            spot          : {linux-e96adsv5-standard--perhourspot, ubuntu-pro-96-core--perhour}

                            $virtualmachines.offers."ubuntu-pro-96-core".prices.PSObject.Properties.Name
                            $virtualmachines.offers."linux-e96adsv5-standard".prices.PSObject.Properties.Name
                            perhour
                            perhouroneyearreserved
                            perhourthreeyearreserved
                            perunitoneyearsavings
                            perunitthreeyearsavings
                            perhourspot

                            $virtualmachines.offers."linux-e96adsv5-standard"
                            
                            $virtualmachines.offers."linux-e96adsv5-standard".prices
                            @{australia-central=; australia-central-2=; australia-east=; australia-southeast=; brazil-south=; brazil-southeast=; canada-central=; canada-east=; central-india=; us-ce… 
                            
                            


                            $instanceName = $instance.displayName.Split(":")[0]
                            $instanceDesc = $instance.displayName.Split(":")[1]
                            $offer = $virtualmachines.offers."$skuName"
                            if ($offer)
                            {
                                $cores = $offer.cores
                                $ram = $offer.ram
                                $diskSize = $offer.diskSize
                                $series = $offer.series
                                $isVcpu = $offer.isVcpu
                                $gpu = $offer.gpu
                                $isHidden = $offer.isHidden
                                $pricingTypes = $offer.pricingTypes
                                $offerType = $offer.offerType
                                $features = ""
                                #'^([a-zA-Z]+)(?:(\d+-\d+)|(\d+))([a-zA-Z]*)\s*([a-zA-Z0-9]*)\s*(v\d+)*'
                                if (($instanceName -match '^[a-zA-Z]+(?:\d+-\d+|\d+)([a-zA-Z]*)'))
                                {
                                    $features = $Matches[1]
                                }
                                $obj = [pscustomobject]@{
                                    operatingSystem = $operatingSystem.displayName
                                    tier = $tier.displayName
                                    region = $region.displayName
                                    group = $groupName
                                    subgroup = $subgroupName
                                    series = $series
                                    instance = $skuName
                                    name = $instanceName
                                    desc = $instanceDesc
                                    cores = $cores
                                    ram = $ram
                                    diskSize = $diskSize
                                    isVcpu = $isVcpu
                                    gpu = $gpu
                                    features = $features
                                    isHidden = $isHidden
                                    pricingTypes = $pricingTypes
                                    offerType = $offerType
                                }
                                $onePriceFound = $false
                                foreach($sku in $offer.prices.PSObject.Properties.Name)
                                {
                                    if ($allSkus -notcontains $sku)
                                    {
                                        $allSkus += $sku
                                    }
                                    $prices = $offer."$sku"
                                }
                                <#
                                foreach($sku in $offer.prices.PSObject.Properties.Name)
                                {
                                    if ($allSkus -notcontains $offP)
                                    {
                                        $allSkus += $offP
                                    }
                                }
                                foreach($sku in $allSkus)
                                {
                                    $priceName = "price" + $sku
                                    $memb = Get-Member -InputObject $virtualmachines.skus."$skuName" -Name $sku -ErrorAction SilentlyContinue
                                    if ($memb)
                                    {
                                        $price = 0.0
                                        $offers = $virtualmachines.skus."$skuName"."$sku"
                                        foreach($offer in $offers)
                                        {
                                            $prices = $allOffers[$offer]
                                            $memb = Get-Member -InputObject $prices -Name $region.slug -ErrorAction SilentlyContinue
                                            if ($memb)
                                            {
                                                $price += $prices."$($region.slug)".value * $exportCurrency.modernConversion
                                                $onePriceFound = $true
                                            }
                                        }
                                        if ($price -eq 0.0) { $price = $null }
                                        Add-Member -InputObject $obj -MemberType NoteProperty -Name $priceName -Value $price
                                    }
                                    else
                                    {
                                        Add-Member -InputObject $obj -MemberType NoteProperty -Name $priceName -Value $null
                                    }
                                }
                                if ($onePriceFound) { $computeCsv.Add($obj) | Out-Null }
                            }
                            else
                            {
                                #Write-Warning "Offer not found: $($operatingSystem.slug)-$slug-$($tier.slug)"
                            }#>
                        }
                        else
                        {
                            #Write-Warning "SKU not found: $($operatingSystem.slug)-$slug-$($tier.slug) on $($instance.slug)"
                        }
                        foreach($price in $prices.Keys)
                        {
                            if ($prices."$price" -eq 0) {
                                Add-Member -InputObject $obj -MemberType NoteProperty -Name $price -Value $null
                            } else {
                                Add-Member -InputObject $obj -MemberType NoteProperty -Name $price -Value $prices."$price"
                            }
                        }
                        $computeCsv.Add($obj) | Out-Null
                    }
                }
            }
        }
    }
}
foreach($row in $computeCsv)
{
    foreach($memberName in $allPriceCols)
    {
        $memb = Get-Member -InputObject $row -Name $memberName -ErrorAction SilentlyContinue
        if (-Not $memb)
        {
            Add-Member -InputObject $row -MemberType NoteProperty -Name $memberName -Value $null
        }
    }
}
Write-Host "Exporting Excel - Sheet PricesVMs" -ForegroundColor $CommandInfo
$excel = $computeCsv | Export-Excel -Path "$AlyaData\azure\PricesAndBenchmarks.xlsx" -WorksheetName "PricesVMs" -TableName "PricesVMs" -BoldTopRow -AutoFilter -FreezeTopRow -ClearSheet -PassThru -NoNumberConversion *
Close-ExcelPackage $excel
#Clear-Variable -Name "computeCsv" -Force -ErrorAction SilentlyContinue

############################################################################################
Write-Host "Building compute benchmark table" -ForegroundColor $CommandInfo
$benchmarksCsv = [System.Collections.ArrayList]@()
$benchmarks = @(
    @{
        OS = "Windows"
        URL = "https://learn.microsoft.com/en-us/azure/virtual-machines/windows/compute-benchmark-scores"
    },
    @{
        OS = "Linux"
        URL = "https://learn.microsoft.com/en-us/azure/virtual-machines/linux/compute-benchmark-scores"
    }
)
foreach($benchmark in $benchmarks)
{
    Write-Host "  $($benchmark.OS): $($benchmark.URL)"
    $computeWinBenchmarks = Invoke-WebRequestIndep -UseBasicParsing -Method GET -Uri $benchmark.URL
    $tables = ([regex]::Matches($computeWinBenchmarks.Content, "<table>(\n|.)*?</table>", [System.Text.RegularExpressions.RegExOptions]::Multiline -bor [System.Text.RegularExpressions.RegExOptions]::IgnoreCase)).Value
    foreach($table in $tables)
    {
        $xtable = [xml]$table
        if ($xtable.table.thead.tr.th[0] -ne "VM Size") { continue }
        $cols = @()
        for ($c=0; $c -lt $xtable.table.thead.tr.th.Count; $c++)
        {
            if (-Not [string]::IsNullOrEmpty($xtable.table.thead.tr.th[$c].'#text'))
            {
                $cols += $xtable.table.thead.tr.th[$c].'#text'
            }
            else
            {
                $cols += $xtable.table.thead.tr.th[$c]
            }
        }
        foreach($row in $xtable.table.tbody.tr)
        {
            $obj = [pscustomobject]@{
                os = $benchmark.OS
            }
            for ($c=0; $c -lt $cols.Count; $c++)
            {
                if (-Not [string]::IsNullOrEmpty($row.td[$c].'#text'))
                {
                    Add-Member -InputObject $obj -MemberType NoteProperty -Name $cols[$c] -Value $row.td[$c].'#text'
                }
                else
                {
                    Add-Member -InputObject $obj -MemberType NoteProperty -Name $cols[$c] -Value $row.td[$c]
                }
            }
            $benchmarksCsv.Add($obj) | Out-Null
        }
    }
}
Write-Host "Exporting Excel - Sheet BenchmarkVMs" -ForegroundColor $CommandInfo
$excel = $benchmarksCsv | Export-Excel -Path "$AlyaData\azure\PricesAndBenchmarks.xlsx" -WorksheetName "BenchmarkVMs" -TableName "BenchmarkVMs" -BoldTopRow -AutoFilter -FreezeTopRow -ClearSheet -PassThru -NoNumberConversion *
Close-ExcelPackage $excel
#Clear-Variable -Name "benchmarksCsv" -Force -ErrorAction SilentlyContinue

############################################################################################
Write-Host "Building azuresqldatabase table" -ForegroundColor $CommandInfo
$allOffers = @{}
foreach ($offerName in (Get-Member -InputObject $azuresqldatabase.offers))
{
    if (@("Equals","GetHashCode","GetType","ToString","Copy","Invoke","IsInstance","MemberType","Name","OverloadDefinitions","TypeNameOfValue","Value") -notcontains $offerName.Name)
    {
        $offer = $azuresqldatabase.offers."$($offerName.Name)"
        $membs = Get-Member -InputObject $offer.prices
        foreach($memb in $membs)
        {
            if (@("Equals","GetHashCode","GetType","ToString","Copy","Invoke","IsInstance","MemberType","Name","OverloadDefinitions","TypeNameOfValue","Value") -notcontains $memb.Name)
            {
                $fullOfferPriceName = $offerName.Name+"--"+$memb.Name
                $allOffers.Add($fullOfferPriceName, $offer.prices."$($memb.Name)") | Out-Null
            }
        }
    }
}
$allSkus = [System.Collections.ArrayList]@()
foreach ($sku in (Get-Member -InputObject $azuresqldatabase.skus))
{
    if (@("Equals","GetHashCode","GetType","ToString","Copy","Invoke","IsInstance","MemberType","Name","OverloadDefinitions","TypeNameOfValue","Value") -notcontains $sku.Name)
    {
        $membs = Get-Member -InputObject $azuresqldatabase.skus."$($sku.Name)"
        foreach($memb in $membs)
        {
            if (@("Equals","GetHashCode","GetType","ToString","Copy","Invoke","IsInstance","MemberType","Name","OverloadDefinitions","TypeNameOfValue","Value") -notcontains $memb.Name)
            {
                $offers = $azuresqldatabase.skus."$($sku.Name)"."$($memb.Name)"
                foreach($offer in $offers)
                {
                    $priceName = $offer.Substring($offer.LastIndexOf("-") + 1, $offer.Length - $offer.LastIndexOf("-") - 1)
                    if (-Not $allSkus.Contains($priceName))
                    {
                        $allSkus.Add($priceName) | Out-Null
                    }
                }
            }
        }
    }
}

$dbTypes = @(
    "managed",
    "standard",
    "retention",
    "premium",
    "hyperscale"
)
foreach ($atype in $azuresqldatabase.types)
{
    $dbTypes += $atype.slug
}
$dbTypes = $dbTypes | Sort-Object { -($_.length) }

$dbPurchaseModels = @(
    "backup",
    "compute",
    "compute-vcore",
    "storage",
    "instance",
    "elastic-pool"
)
foreach ($atype in $azuresqldatabase.purchaseModels)
{
    $dbPurchaseModels += $atype.slug
}
$dbPurchaseModels = $dbPurchaseModels | Sort-Object { -($_.length) }

$dbTiers = @(
    "instance-pools",
    "business-critical-storage",
    "general-purpose-storage",
    "pitr-storage-hyperscale",
    "pitr-backup-storage",
    "operations",
    "backup",
    "backup-storage-point",
    "ltr-backup-storage"
)
foreach ($atype in $azuresqldatabase.dtuTiers)
{
    $dbTiers += $atype.slug
}
foreach ($atype in $azuresqldatabase.vcoreTiers)
{
    $dbTiers += $atype.slug
}
$dbTiers = $dbTiers | Sort-Object { -($_.length) }

$dbComputeTiers = @("")
foreach ($atype in $azuresqldatabase.computeTiers)
{
    $dbComputeTiers += $atype.slug
}
$dbComputeTiers = $dbComputeTiers | Sort-Object { -($_.length) }

$priceMembers = @()
$azuresqldatabaseCsv = [System.Collections.ArrayList]@()
foreach ($region in $azuresqldatabase.regions)
{
    #$region = $azuresqldatabase.regions | Where-Object { $_.slug -eq "switzerland-north" }
    #Write-Host "Region: $($region.displayName)"
    $doneSku = @()
    foreach ($dbType in $dbTypes)
    {
        foreach ($dbPurchaseModel in $dbPurchaseModels)
        {
            if (-Not [string]::IsNullOrEmpty($dbType) -and -Not [string]::IsNullOrEmpty($dbPurchaseModel)) { $dbPurchaseModel = "-"+$dbPurchaseModel }
            foreach ($dbTier in $dbTiers)
            {
                if (-Not [string]::IsNullOrEmpty($dbPurchaseModel) -and -Not [string]::IsNullOrEmpty($dbTier)) { $dbTier = "-"+$dbTier }
                foreach ($dbComputeTier in $dbComputeTiers)
                {
                    if (-Not [string]::IsNullOrEmpty($dbTier) -and -Not [string]::IsNullOrEmpty($dbComputeTier)) { $dbComputeTier = "-"+$dbComputeTier }
                    $skuName = "$dbType$dbPurchaseModel$dbTier$dbComputeTier"
                    if ([string]::IsNullOrEmpty($skuName)) { continue }
                    $skus = @()
                    $sks = $azuresqldatabase.skus.PSObject.Properties | Where-Object { $_.Name.StartsWith($skuName) }
                    foreach($sk in $sks)
                    {
                        $instance = $sk.Name.Replace($sk.Name, "").Trim("-")
                        $dashCnt = $instance.Length - $instance.Replace("-", "").Count
                        #Write-Host "  sk: $($sk.Name)"
                        #Write-Host "  dashCnt: $($dashCnt)"
                        if ($dashCnt -lt 2)
                        {
                            $skus += @($sk.Name)
                        }
                    }
                    foreach($skun in $skus)
                    {
                        if ($doneSku -notcontains $skun)
                        {
                            $instance = $skun.Replace($skuName, "").Trim("-")
                            #Write-Host "    "
                            #Write-Host "    SkuName: $($skun)"
                            #Write-Host "      Instance: $($instance)"
                            $sku = $azuresqldatabase.skus."$skun"

                            $obj = [pscustomobject]@{
                                dbType = $dbType.Trim("-")
                                dbPurchaseModel = $dbPurchaseModel.Trim("-")
                                dbTier = $dbTier.Trim("-")
                                dbComputeTier = $dbComputeTier.Trim("-")
                                instance = $instance.Trim("-")
                                region = $region.displayName
                            }
                            $onePriceFound = $false
                            foreach($skuPriceName in (Get-Member -InputObject $sku))
                            {
                                if (@("Equals","GetHashCode","GetType","ToString","Copy","Invoke","IsInstance","MemberType","Name","OverloadDefinitions","TypeNameOfValue","Value") -notcontains $skuPriceName.Name)
                                {
                                    #Write-Host "      Price: $($skuPriceName.Name)"
                                    $priceName = "price$($skuPriceName.Name)"
                                    $price = 0.0
                                    $offers = $sku."$($skuPriceName.Name)"
                                    $priceType = $null
                                    foreach($offer in $offers)
                                    {
                                        #Write-Host "        Offer: $($offer)"
                                        if ($null -eq $priceType)
                                        {
                                            $priceType = $offer.Replace($skun, "").Trim("-")
                                            $priceName = "price-$priceType-$($skuPriceName.Name)"
                                        }
                                        $prices = $allOffers[$offer]
                                        $memb = Get-Member -InputObject $prices -Name $region.slug -ErrorAction SilentlyContinue
                                        if ($memb)
                                        {
                                            $price += $prices."$($region.slug)".value * $exportCurrency.modernConversion
                                            $onePriceFound = $true
                                        }
                                        $offerName = $offer.Substring(0, $offer.LastIndexOf("-") - 1)
                                    }
                                    if ($price -eq 0.0) { $price = $null }
                                    if ($priceMembers -notcontains $priceName) { $priceMembers += $priceName }
                                    Add-Member -InputObject $obj -MemberType NoteProperty -Name $priceName -Value $price
                                }
                            }
                            if ($onePriceFound) { $azuresqldatabaseCsv.Add($obj) | Out-Null }
                                    
                            $doneSku += $skun
                        }
                    }
                }
            }
        }
    }
}
foreach($row in $azuresqldatabaseCsv)
{
    foreach($memberName in $priceMembers)
    {
        $memb = Get-Member -InputObject $row -Name $memberName -ErrorAction SilentlyContinue
        if (-Not $memb)
        {
            Add-Member -InputObject $row -MemberType NoteProperty -Name $memberName -Value $null
        }
    }
}
Write-Host "Exporting Excel - Sheet PricesAzureSqlDatabase" -ForegroundColor $CommandInfo
$excel = $azuresqldatabaseCsv | Export-Excel -Path "$AlyaData\azure\PricesAndBenchmarks.xlsx" -WorksheetName "PricesAzureSqlDatabase" -TableName "PricesAzureSqlDatabase" -BoldTopRow -AutoFilter -FreezeTopRow -ClearSheet -PassThru -NoNumberConversion *
# -Show uses Start-Process on the xlsx file: works on Windows only,
# on Linux/macOS it fails with Permission denied (file is already saved before)
if (($PSVersionTable.PSVersion.Major -lt 6) -Or $IsWindows)
{
    Close-ExcelPackage $excel -Show
}
else
{
    Close-ExcelPackage $excel
}
#Clear-Variable -Name "azuresqldatabaseCsv" -Force -ErrorAction SilentlyContinue

#TODO
#   functions
#   backup
#   monitor
#   automation
#   keyvault
#   analysisservices

############################################################################################
Write-Host "Building keyvault table" -ForegroundColor $CommandInfo

# Stopping Transcript
Stop-Transcript

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBgUinHFdc0jtvA
# Ej3cuqeZ/a5YbWhNlek6sSy+YcFEraCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
# Qc9vAbjutKlUMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24g
# Um9vdCBDQSAtIFIzMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9i
# YWxTaWduMB4XDTIwMDcyODAwMDAwMFoXDTI5MDMxODAwMDAwMFowUzELMAkGA1UE
# BhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2Jh
# bFNpZ24gQ29kZSBTaWduaW5nIFJvb3QgUjQ1MIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAti3FMN166KuQPQNysDpLmRZhsuX/pWcdNxzlfuyTg6qE9aND
# m5hFirhjV12bAIgEJen4aJJLgthLyUoD86h/ao+KYSe9oUTQ/fU/IsKjT5GNswWy
# KIKRXftZiAULlwbCmPgspzMk7lA6QczwoLB7HU3SqFg4lunf+RuRu4sQLNLHQx2i
# CXShgK975jMKDFlrjrz0q1qXe3+uVfuE8ID+hEzX4rq9xHWhb71hEHREspgH4nSr
# /2jcbCY+6R/l4ASHrTDTDI0DfFW4FnBcJHggJetnZ4iruk40mGtwEd44ytS+ocCc
# 4d8eAgHYO+FnQ4S2z/x0ty+Eo7+6CTc9Z2yxRVwZYatBg/WsHet3DUZHc86/vZWV
# 7Z0riBD++ljop1fhs8+oWukHJZsSxJ6Acj2T3IyU3ztE5iaA/NLDA/CMDNJF1i7n
# j5ie5gTuQm5nfkIWcWLnBPlgxmShtpyBIU4rxm1olIbGmXRzZzF6kfLUjHlufKa7
# fkZvTcWFEivPmiJECKiFN84HYVcGFxIkwMQxc6GYNVdHfhA6RdktpFGQmKmgBzfE
# ZRqqHGsWd/enl+w/GTCZbzH76kCy59LE+snQ8FB2dFn6jW0XMr746X4D9OeHdZrU
# SpEshQMTAitCgPKJajbPyEygzp74y42tFqfT3tWbGKfGkjrxgmPxLg4kZN8CAwEA
# AaOCAXcwggFzMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzAP
# BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQfAL9GgAr8eDm3pbRD2VZQu86WOzAf
# BgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpjmove4t0bvDB6BggrBgEFBQcBAQRuMGww
# LQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL3Jvb3RyMzA7
# BggrBgEFBQcwAoYvaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# cm9vdC1yMy5jcnQwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxz
# aWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggrBgEF
# BQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJ
# KoZIhvcNAQEMBQADggEBAKz3zBWLMHmoHQsoiBkJ1xx//oa9e1ozbg1nDnti2eEY
# XLC9E10dI645UHY3qkT9XwEjWYZWTMytvGQTFDCkIKjgP+icctx+89gMI7qoLao8
# 9uyfhzEHZfU5p1GCdeHyL5f20eFlloNk/qEdUfu1JJv10ndpvIUsXPpYd9Gup7EL
# 4tZ3u6m0NEqpbz308w2VXeb5ekWwJRcxLtv3D2jmgx+p9+XUnZiM02FLL8Mofnre
# kw60faAKbZLEtGY/fadY7qz37MMIAas4/AocqcWXsojICQIZ9lyaGvFNbDDUswar
# AGBIDXirzxetkpNiIHd1bL3IMrTcTevZ38GQlim9wX8wggboMIIE0KADAgECAhB3
# vQ4Ft1kLth1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENv
# ZGUgU2lnbmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAw
# MDBaMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIw
# MAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAy
# MDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj
# /SBerjgSi8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlM
# g7BKRFAEeIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRV
# X5YLEeWatSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV
# 0xHK5s2zBZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEz
# IHXMsdXtHQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMk
# oog28vmfvpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq
# 7rfYrWGlr3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult
# 5a/dm2tjIF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNu
# twFsDeCXpxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYy
# AjIwfLWTyCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofn
# GrhO7izB36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
# FgQUJZ3Q/FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0
# Q9lWULvOljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8v
# b2NzcC5nbG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUH
# MAKGOmh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWdu
# aW5ncm9vdHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJ
# KwYBBAGgMgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24u
# Y29tL3JlcG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJ
# yTm6t6E5iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbV
# YQLFY4/UovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQt
# pFg6bBNJ+KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSX
# hndGKj0jfShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6
# bs+XYXvfcXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nO
# ZNm9/Lws80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOH
# X5OKSBoRHeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dq
# cYC/lt5yA9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0i
# xxnJpsoOqHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7
# qWPLd0jV+mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDCjuDGju
# xOV7dX3H9DANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjEzMTYxODAwWhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAqrm7S5R5kmdYT3Q2wIa1m1BQW5EfmzvCg+WYiBY94XQT
# AxEACqVq4+3K/ahp+8c7stNOJDZzQyLLcZvtLpLmkj4ZqwgwtoBrKBk3ofkEMD/f
# 46P2IukytvmyUxdM4730Vs6mRvQP+Y6CfsUrWQDgJkiGTldCSH25D3d2eO6PeSdY
# TA3E3kMHBiFI3zxgCq3ZgbdcIn1bUz7wnzxjuAqI7aJ/dIBKDmaNR0+iIhrCFvhD
# o6nZ2Iwj1vAQsSHlHc6SwEvWfNX+Adad3cSiWfj0Bo0GPUKHRayf2pkbOW922shL
# 1yf/30OVyct8rPkMrIKzQhog2R9qJrKJ2xUWwEwiSblWX4DRpdxOROS5PcQB45AH
# hviDcudo30gx8pjwTeCVKkG2XgdqEZoxdAa4ospWn3va+Dn6OumYkUQZ1EkVhDfd
# sbCXAJvYNCbOyx5tPzeZEFP19N5edi6MON9MC/5tZjpcLzsQUgIbHqFfZiQTposx
# /j+7m9WSaK0cDBfYKFOVQJF576yeWaAjMul4gEkXBn6meYNiV/iL8pVcRe+U5cid
# mgdUVveoBPexERaIMz/dIZIqVdLBCgBXcHHoQsPgBq975k8fOLwTQP9NeLVKtPgf
# tnoAWlVn8dIRGdCcOY4eQm7G4b+lSili6HbU+sir3M8pnQa782KRZsf6UruQpqsC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBT5XqSepeGcYSU4OKwKELHy/3vC
# oTANBgkqhkiG9w0BAQsFAAOCAgEAlSgt2/t+Z6P9OglTt1+sobomrQT0Mb97lGDQ
# ZpE364hOTSYkbcqxlRXZ+aINgt2WEe7GPFu+6YoZimCPV4sOfk5NZ6I3ZU+uoTso
# VYpQr3IozYLLNMWEK2WswPHcxx34Il6F59V/wP1RdB73g+4ZprkzsYNqQpXMv3yo
# DsPU9IHP/w3jQRx6Maqlrjn4OCaE3f6XVxDRHv/iFnipQfXUqY2dV9gkoiYL3/dQ
# X6ibUXqjXk6trvZBQr20M+fhhFPYkxfLqu1WdK5UGbkg1MHeWyVBP56cnN6IobNp
# HbGY6Eg0RevcNGiYFZsE9csZPp855t8PVX1YPewvDq2v20wcyxmPcqStJYLzeirM
# Jk0b9UF2hHmIMQRuG/pjn2U5xYNp0Ue0DmCI66irK7LXvziQjFUSa1wdi8RYIXnA
# mrVkGZj2a6/Th1Z4RYEIn1Pc/F4yV9OJAPYN1Mu1LuRiaHDdE77MdhhNW2dniOmj
# 3+nmvWbZfNAI17VybYom4MNB1Cy2gm2615iuO4G6S6kdg8fTaABRh78i8DIgT6LL
# /yMvbDOHhREfFUfowgkx9clsBF1dlAG357pYgAsbS/hqTS0K2jzv38VbhMVuWgtH
# dwO39ACaudnXvAKG9w50/N0DgI54YH/HKWxVyYIltzixRLXN1l+O5MCoXhofW4Qh
# trofETAxgiEGMIIhAgIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIA9w4ctG
# z8krpyoLOyNi2mf4yuSd15MAVjMUOXUfN11KMA0GCSqGSIb3DQEBAQUABIICAI6N
# 7oRA9RXCHIAxANAda6dfjnPw0/KYXiu9sUqv0e7biJApAML5trd01cNV5/M2qaMP
# e1QtJ+6f9jyEA5RLbsdscEntdbBIKykwxuEzDVowULPM2DcCRENyi39xzENvpBK4
# goLPruk9WeabLeevPgWKmW5PtQd2qIs7atwMN4OPCLvHgvFF9XNCvUTcqW4A7sag
# ALGi0hECFhcxJ6R/oxIlB21iclKNemotjw6qQxbgFeY3SwfxcBwgap3OqOo+umsA
# bMepRY6v9sYJsO1WrX8pNaoFRE+YAy92HV/A9v2UEy+scNO07TFCdxalGYMDWnAh
# wI6zqWWQcQYidMsDenDxK2n8SXmbmL+unzDFri1678hEc6J7uMgNKpldo8xMR94o
# zWs69LerVStbgPy7tk2R+iV/MW2HTpBES3KevhOLs58pJwVWIUZqRtwuHpygI8HF
# ncsaQJdTpJixuePhomnEyn+EsZMj29p7gVM6UosfmV4JxbqFCt3ZwowrCvtaOqAs
# dGLbwRw2kY4kbZL4E+5KH79f757Vqy9f+IraPlLG+W3JrYeu3i+jhSljx/t741Ro
# 4H3NCWb5nxVduBKWFUNJLaQGvALUK+Anx0LBTq3PS63w5ztTlnfqUQ5Rxy3vtDqd
# bfK9L3QFJoN8QYPTYYDdiHDX7N5j1Y+Af9Z+DmIuoYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCCiPHNV40uRHCFZuZrZvfRcTKuil3uKrMQYmuLzQqNWhwIUPEQ7
# NN0SjCb7szsrD6bVQVBdUdQYDzIwMjYxMDIwMTMzMTUyWjADAgEBoF2kWzBZMQsw
# CQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMm
# R2xvYmFsc2lnbiBSNDUgVFNBIGZvciBDb2RlU2lnbiAyMDI1MTCgghlgMIIGijCC
# BHKgAwIBAgIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcNAQEMBQAwXjELMAkG
# A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0ds
# b2JhbFNpZ24gT2ZmbGluZSBSNDUgVGltZXN0YW1waW5nIENBIDIwMjUwHhcNMjUx
# MDE1MDcyNTA0WhcNMzcwMTEwMDAwMDAwWjBZMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFsc2lnbiBSNDUgVFNB
# IGZvciBDb2RlU2lnbiAyMDI1MTAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQDRSo2hjYZASCijCQSc2RMQPPKojE/xf4Uija2JnsJ7Snl2gDoxKjQ9HcU6
# rVD8pgy1sBKdVxtLLFhY3gzY/PA2iwIs6ZzCnxshtjShsN1RyzRrzc4Fq+0xQx6q
# ADUMn96mqHE/0ok53DPbmpBkkUDytGM79nQfw9WVymYgA+TkbA0/QOmPNNJIZ6Cj
# X0t3wJfhL0caiXthBBMEWKxT5v2U7ZRbCq/DVDXA9oX1iFVBVaBpx57MLL00nyHu
# x0InYS7Rr54M3tNhm7+0maxpyTFa51uY1PHtTJMup/l3RGooQ5YweCH2hDoUNwKO
# C7QkFbklhPdq27EXkueg8qLOnRDmVO1r+B1yMAbl6QuV0L+OPB1SKBAPpmIFklmJ
# 0SoibbUqxsTzejjdI+ywQLUcXilogwKWsJ46h6wjlU5AVqT7FEBYzWCTt6hf7SLQ
# bPGs02Ba8oaaNfo0SL+aApN94luEB/wuE1lgptrckLzbQlCp56OgkAJYpqYuui+T
# fueCIU0CAwEAAaOCAcYwggHCMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAK
# BggrBgEFBQcDCDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQy+tPhB2gnkGsI0j8d
# PIxlNigGGTAfBgNVHSMEGDAWgBR3AjsBMQ8edHfDSMjDB2NViKU7ojCBpQYIKwYB
# BQUHAQEEgZgwgZUwQgYIKwYBBQUHMAGGNmh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24u
# Y29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNTBPBggrBgEFBQcwAoZDaHR0
# cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NvZmZsaW5lcjQ1dGlt
# ZXN0YW1wY2EyMDI1LmNydDBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLmds
# b2JhbHNpZ24uY29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNS5jcmwwVgYD
# VR0gBE8wTTAIBgZngQwBBAIwQQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0
# dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEB
# DAUAA4ICAQCOrnCmj0eGkYpuniz6/WFm91s6KjnhkMKYlbcftgpMBtlhysVniEOf
# BvhcvoFQw4AOHG9NRVvZpkBnag5Dt1HM3Jg21gRVCBwFyP1ET8IDxoflYx5OD4SC
# NLHs6vCg6rFkNT81v9Zy8u0xXy3WboN5iK/SbTmLGqCrAGJihLLrfIhvddwVrdBy
# iHteLxgjugT6JQogCSoBF2JqmH0ZBCl515btbTuWZLrQUs5vvl2o98Mdju9yyJRW
# LzPVcUkRk9d8xBBi638FBOAuo3fcyThGcne7wUOa+TghhwIHbZ3pxTYpgo5cCxEZ
# sH8EXwiTUTwHf0qesssg/2XdcGH7s0AR4TyOJ2QnAayYOAM/XOBxNzURQg4mhMdP
# L/F8VCMKj3koJaVcx2akh0B82le/aBU8q2Oa++OwOwiHF5e+f9m+yhyYbwGSogWI
# V3hgRl+VyKrch8gv35FHr/cVz8n0/CPGRXGiYJZ7P1wOOgYdkMD2iDKVYQby5Ix/
# xCB0/lSKLnqEoFezfmnCJbGgACVswMsxhJEUjtxEcQc9afalne+IOts0v/yCRikJ
# snmVbS0x50Dk2OH+VCiU9s/XyzgfC7WzrtQ5diIdc2Ksi3JMTJm4a0LiEIZWitD5
# +6PokOkQ8+35TsHOwUhs87I/yyJjlIZpAV4Of1/JN8bWVB3Edm4WzjCCBqAwggSI
# oAMCAQICEQCD2oY3t58MhAyUe4QKUngfMA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNV
# BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9i
# YWxTaWduIFRpbWVzdGFtcGluZyBSb290IFI0NTAeFw0yNTA3MTYwMzA1MDRaFw00
# MTA3MTYwMDAwMDBaMF4xCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTQwMgYDVQQDEytHbG9iYWxTaWduIE9mZmxpbmUgUjQ1IFRpbWVzdGFt
# cGluZyBDQSAyMDI1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApHcW
# +O19i+LdAoZFYzS+5X+WYvnWoFqXAfir1hynhUTdH4RW1Db+yOmrQ275jlsQ6bzo
# Z3nN0CMncZX4E0Qhpp6Qvx27+flpfzeMQacD7VciWUiF3TLiu7wT2bBCSENUn3hf
# GMG4PJvYFvO5o4DA1iNvHhG4oSzctodoJfb4c8EjVahCw/NLizB3ra+NWe2gZBSa
# ZKraMxFt676yqx7RcQnjbF4R0OLGovsZt23vU69A5BdoPxdA9zu9rM+qTBsPDVUJ
# exYwEVU0GY7BJ5mUWWniyAPHW0Wv4Azk5t7I0XUIjA3+2OGkr0dVBXVBDyEeGBVr
# YXEdhfVLwuh6HBGJFdIrEY5KoGlpoT+4BBQe4XCH5sv15Uo+M72VKWjPA5Ex3nfF
# JC4P5FW1SR6olCSaIrtnZzc+zgmpSyiD+GcE2udQRQHbDi74enXgazk0+ktpHZ1Z
# 8oTvSaSIREovXSLbH3KC8uFIkXucl7XPH7ZGIrmF9eF4zuoo5FIUnsvV60kLqFDz
# Pk+UbLmgZDUCPlFFBBehaaNvixEymx9ON2KXev+MfK6OZChqGbrOC2wvvAFHyKlT
# ZbVHdqNiu0u5a2T1C9dSTRny1/hxLwcxL9BWPzQLwhsiyXqUzM7uD0lD9+PYMaxU
# YgoVSxqb4xvPCiVqLNabI+WtjEzYfQ0P+6tBTFsCAwEAAaOCAWIwggFeMA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDASBgNVHRMBAf8ECDAGAQH/
# AgEAMB0GA1UdDgQWBBR3AjsBMQ8edHfDSMjDB2NViKU7ojAfBgNVHSMEGDAWgBRG
# shx34XsV8KU5oXDe0cQu6m2y3jCBjgYIKwYBBQUHAQEEgYEwfzA3BggrBgEFBQcw
# AYYraHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vdGltZXN0YW1wcm9vdHI0NTBE
# BggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# dGltZXN0YW1wcm9vdHI0NS5jcnQwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2Ny
# bC5nbG9iYWxzaWduLmNvbS90aW1lc3RhbXByb290cjQ1LmNybDARBgNVHSAECjAI
# MAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggIBADKj7n7RbuRmMZZYXqlMPRJoR6X1
# n//quXGLVfOpFoR9Ya05L94w0ywBjelyGGf+nAB+CZFQ7gUOd2a2bpfpW8Xw5ArM
# +YjPEf8AtC4E6Yr105U1YNjlTSERoWJKc1hkSN5m4dpsYteFykzFQVwX50hYKH3y
# Z6Vcu6Ha0EA5ofzLpi2jK2jbRDCXbFNLi5mO1xKRdB2AzAF0f5C00b4H3d5sCOB8
# njTvAwaTMGEMeTkLWM4Z9Y+3UOtOpo1QuxXbDpXVkLXraG25iL1VtvjxEAy4534n
# UINB9whORicJJSTLba6fOK2f/1QGWEdewWLHAzE+N5oH0QoNRALpJ5JjIfeInvO+
# sQdBidnPuLKJ95HTj7XyMvJhFZjtbHJGlEWx4UgKcuNKLDLXWALfwQDN2Dey3kTf
# d4yw4nQdk1PctLLK3F4L2nnLv94BMkpY+Rfl53oOEN4yTvtwCYP+VDuZrktc7Nac
# oTVxZnKGkv8a1akckdOwQZC+i8Ay1VyzMAX/Tb4+r3c65B7cpAtq3OoUijXUJgvZ
# xci6TX78smL2TYy2tWn+8G4krnXvy2ELR2XYnKEOS4MVmrSCsjM5nxSrghE10VDX
# QbEfa93lhikfFoIuINKzWDLqvu8ZucmxEufxpHjNnnRVXX/Zv5KQq8pu/MQoOz6D
# C74n5+O5bSwvT5sgMIIGozCCBIugAwIBAgIQeEqqgXNmnJAJVOQhyUfrwDANBgkq
# hkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjET
# MBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMDEy
# MDkwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIFRpbWVzdGFt
# cGluZyBSb290IFI0NTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALp0
# M+wn3BI4IRvF02Eo1lq8T9+LzJGEQyRXvGQhvDscHz1PjK0Ht/PF1wLpERSCmqq0
# lHI7cQ0a72hrhXmOr2bqWJgNusF8edL/zbNvMUXQBXQEAHJqJ364Nz86iO2Xg/Wr
# NU0Pn1k79S/fWcV8pTJ2YJbI7e74BH4ZUXKov0RBerx7HjsAm7y64Ja/kP6Nm8Ny
# iwAS+CA6YDj3wcyFivuHeS6hKyDmy6CFkSO2xCgHVCje7BAxT4ryzRQfHt1VHOoo
# MUz5IWqozfOWZ/oBQZvNDwtof7ve8UPqF+Ww3HAis2k2WXRrxuWJKnzlC4Fdqz+P
# uNF2cvN8oqnil0G/zIxF/mHJ9mwHCwAE6BUjT4IqLfbvw/oRNkih0f16OTo0XaMs
# Dpt3UCA0QN2xAzGtX+lih3OWA2H3lLDZXGxP5xTF4fF7DSOczXCMHWreSi2LKrvb
# QhQFB6r7FNwx0/YfbMu+aGZEcE1tF/lx6wVzjpGSdetoXB72RGEYKWLdF2aI7Ci6
# SW/bPnf+uTEfdRwYoqZHvdjuSIU7/bPiDz8qmMaa+oJvsaWlhh1aOvqkbHQPd1Jh
# an+HKd45m4vus0VgMCSXFRIqhTCTJqyWpi3ocG0LqTKtLJsoCnZC8lVhUZiU3u32
# xRdvPBUQsA6tsN7FFvRl0cwvWlYIz5nE8FWRwix5AgMBAAGjggF4MIIBdDAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDwYDVR0TAQH/BAUwAwEB
# /zAdBgNVHQ4EFgQURrIcd+F7FfClOaFw3tHELuptst4wHwYDVR0jBBgwFoAUrmwF
# o5MT4qLn4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEEbzBtMC4GCCsGAQUFBzABhiJo
# dHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsGAQUFBzAChi9o
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAi0i6Nlc8csXadfnvMvWGvdwSKOOILk82XyaZ7A8BIRCWkjjGcGtt867UDr0l
# 74Z/4omNlaV+KUQDTaqYqPG33OopYyHc7c2ICssQaWF5KUIMI7zpxe9SHi8zN9VP
# ZnpmqUdUM7HdFvLYZHGjMZTlb/ZNS+KEbNDJJWdPyEvQzksF1j37fUH6irHAIeB+
# CLDZZCv56vLHCvTPLgw0YO5su5LwP/F7UhJod1mB9RwupDqMOQMN7eXMr2ZIeWPV
# Sbj/S9IlT0hOkzuTd7CaSGy2oB2zdJ5fvSIEO3w3DYW1w5q73ZxaA420DZ9MdjTV
# ha1Fe7Wfuy6Ju6zIv5JjSMY/yheqDbwAEV+L6ONDhIpDNM39O8Cie9sfuGfIjBXe
# P6Z/xyjvoW9vskHPAiLrAfhLyNJ2byXfXtpoaD17RATCQW5JO6eYVgTt0SYrBJTb
# 5O1mjj2AnaSkVXlQXuP4Gh/AFm+QFTyKpkihDHu6KuCxqYcFRpvtJVU9N2mY7UaZ
# mIVHCh5i2/2c5cFDQo69z2/2jJH9guSf7K3jlVUF80kvbTT3/2fumUC705qAQkDa
# I4lgH4NxkrXp5soK+d3HbLJYQZxmjZsqbx9vVwRDXINdO2mc3jn6hE0183sbbYvx
# bwPBKVLilL97VIvfQHoLcAJ3Py+IBwIAddKvxtYiMhmjO+gwggWDMIIDa6ADAgEC
# Ag5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9i
# YWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
# AxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwx
# IDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9i
# YWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRv
# f+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJ
# f094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcx
# BsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQ
# Bzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5d
# RC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWq
# RfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX8
# 5mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjpl
# llnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R
# /98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFl
# tr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEA
# AaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE
# FK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tyt
# ok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7
# jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh
# 4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR
# 3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6
# fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgb
# KCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglI
# WYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Q
# v4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98
# i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU
# 4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzW
# AtcKZ4MFWsmkEDGCA2EwggNdAgEBMHMwXjELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNpZ24gT2ZmbGluZSBS
# NDUgVGltZXN0YW1waW5nIENBIDIwMjUCEQCEcj/BlcwW8dsrovZg3yvkMAsGCWCG
# SAFlAwQCAqCCAUEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMCsGCSqGSIb3
# DQEJNDEeMBwwCwYJYIZIAWUDBAICoQ0GCSqGSIb3DQEBDAUAMD8GCSqGSIb3DQEJ
# BDEyBDAmu1bU4UfE34mnpypV2cNjijK2eZOssOPFNx5JmYXjZlp9wIAMueX3NO6m
# 8KfhUYUwgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGAroB0O6eTLlvARnf4Ag0ytdjHqGyT3AqxyksrXGnZiSpJ
# HMc9Xemo0sF22CYsL/lxT3LcJdCscFG6f/PwJ4vIPomM1vwiGRZSIGlyUhJbtufa
# NCgRA3skdLWN03OTcQZ8h/YV4JvzIqqSOk6AguTzX4mk8RdtKsCuITEG20Gtl+gv
# cLw/GGiFiN41Rz84OLlA27l9N5BmfcYanRjsA9bMfupsk0nl/7eOPNkldFORx5pt
# tZ1wibtTJnsVXWpdihgS8bSiGKZ4q5AMp773sP2eJaEiYIKf9kJSHDDPzyr1SsWG
# m8r2kIfxm5IfdYWI3Dm9x3m4CM0QU/JunaItivrQxEawNt1FGcQHCn2ACJEThcB2
# QpjFO0uuraWChNRXcBhYRwxFktNVb3aUTm8DOPwyWGVORuEiwuvO8NAhhxMqu1/M
# qPi/LOJQjBI4xieTPLDV6UlIQLtkhUJe0SMNtHSUYhWDkMutwpaitcQ+XG5Kz8nm
# TTVt2lnvsc3Va+NouFP3
# SIG # End signature block
