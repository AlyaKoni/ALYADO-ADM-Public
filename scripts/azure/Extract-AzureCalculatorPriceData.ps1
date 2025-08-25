#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2025

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
    Date       Author               Description
    ---------- -------------------- ----------------------------
    18.03.2021 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    $exportCurrencyName = "chf"
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
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
Close-ExcelPackage $excel -Show
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

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC688rlLCj2tFaH
# 6iDiBWentP/p0xLIdGLKXQgoVQoMvaCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
# th1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAwMDBaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# EylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj/SBerjgS
# i8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlMg7BKRFAE
# eIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRVX5YLEeWa
# tSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV0xHK5s2z
# BZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEzIHXMsdXt
# HQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMkoog28vmf
# vpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq7rfYrWGl
# r3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult5a/dm2tj
# IF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNutwFsDeCX
# pxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYyAjIwfLWT
# yCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofnGrhO7izB
# 36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJZ3Q
# /FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lWULvO
# ljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5ncm9v
# dHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJKwYBBAGg
# MgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3Jl
# cG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJyTm6t6E5
# iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbVYQLFY4/U
# ovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQtpFg6bBNJ
# +KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSXhndGKj0j
# fShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6bs+XYXvf
# cXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nOZNm9/Lws
# 80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOHX5OKSBoR
# HeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dqcYC/lt5y
# A9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0ixxnJpsoO
# qHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7qWPLd0jV
# +mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72f1LiSY25
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDCjuDGjuxOV7dX3H
# 9DANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjEzMTYxODAwWhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAqrm7S5R5kmdYT3Q2wIa1m1BQW5EfmzvCg+WYiBY94XQTAxEACqVq
# 4+3K/ahp+8c7stNOJDZzQyLLcZvtLpLmkj4ZqwgwtoBrKBk3ofkEMD/f46P2Iuky
# tvmyUxdM4730Vs6mRvQP+Y6CfsUrWQDgJkiGTldCSH25D3d2eO6PeSdYTA3E3kMH
# BiFI3zxgCq3ZgbdcIn1bUz7wnzxjuAqI7aJ/dIBKDmaNR0+iIhrCFvhDo6nZ2Iwj
# 1vAQsSHlHc6SwEvWfNX+Adad3cSiWfj0Bo0GPUKHRayf2pkbOW922shL1yf/30OV
# yct8rPkMrIKzQhog2R9qJrKJ2xUWwEwiSblWX4DRpdxOROS5PcQB45AHhviDcudo
# 30gx8pjwTeCVKkG2XgdqEZoxdAa4ospWn3va+Dn6OumYkUQZ1EkVhDfdsbCXAJvY
# NCbOyx5tPzeZEFP19N5edi6MON9MC/5tZjpcLzsQUgIbHqFfZiQTposx/j+7m9WS
# aK0cDBfYKFOVQJF576yeWaAjMul4gEkXBn6meYNiV/iL8pVcRe+U5cidmgdUVveo
# BPexERaIMz/dIZIqVdLBCgBXcHHoQsPgBq975k8fOLwTQP9NeLVKtPgftnoAWlVn
# 8dIRGdCcOY4eQm7G4b+lSili6HbU+sir3M8pnQa782KRZsf6UruQpqsCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBT5XqSepeGcYSU4OKwKELHy/3vCoTANBgkq
# hkiG9w0BAQsFAAOCAgEAlSgt2/t+Z6P9OglTt1+sobomrQT0Mb97lGDQZpE364hO
# TSYkbcqxlRXZ+aINgt2WEe7GPFu+6YoZimCPV4sOfk5NZ6I3ZU+uoTsoVYpQr3Io
# zYLLNMWEK2WswPHcxx34Il6F59V/wP1RdB73g+4ZprkzsYNqQpXMv3yoDsPU9IHP
# /w3jQRx6Maqlrjn4OCaE3f6XVxDRHv/iFnipQfXUqY2dV9gkoiYL3/dQX6ibUXqj
# Xk6trvZBQr20M+fhhFPYkxfLqu1WdK5UGbkg1MHeWyVBP56cnN6IobNpHbGY6Eg0
# RevcNGiYFZsE9csZPp855t8PVX1YPewvDq2v20wcyxmPcqStJYLzeirMJk0b9UF2
# hHmIMQRuG/pjn2U5xYNp0Ue0DmCI66irK7LXvziQjFUSa1wdi8RYIXnAmrVkGZj2
# a6/Th1Z4RYEIn1Pc/F4yV9OJAPYN1Mu1LuRiaHDdE77MdhhNW2dniOmj3+nmvWbZ
# fNAI17VybYom4MNB1Cy2gm2615iuO4G6S6kdg8fTaABRh78i8DIgT6LL/yMvbDOH
# hREfFUfowgkx9clsBF1dlAG357pYgAsbS/hqTS0K2jzv38VbhMVuWgtHdwO39ACa
# udnXvAKG9w50/N0DgI54YH/HKWxVyYIltzixRLXN1l+O5MCoXhofW4QhtrofETAx
# ghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFjPbRKH6TCTy+hS
# kfVIH4uVHepysANQTNzdxOIb4PbmMA0GCSqGSIb3DQEBAQUABIICACnHGVMOrBfQ
# 0IKLbsnuvC/NLn0WqsZEXSZM98MCzFB18cZ7u9akg186vjGiiwEY/qWZZzpL8N0v
# SiMOwDavmY9kDpfW1haqJcoOYCFiosrt8uAiDcvWsKXM0M3htk0pCv1u0YaRHBDP
# L/4gX4yBs3Kpgp5prDuW2X315oC2uAzlwoOp/iQFxtF/JkYF7qbE4LQ6jr25Al+8
# CyL6dpNoRrfTn1IHC+ml15eKrwwsg7vY+2MOqNrQOOrOLj3junDUhy/fBxEWMpM1
# g+GQZRBeeHJ4IOIDh4QPqcWwyJYGyH5a+jc+G/o3tcosWbPn1J8/EPc+ZZPZD9cd
# QpGrevXHGAT/Y54sQVzpL8tjlB0LQD+aSjogxSxWsYh5+G2gFn62MahFeuOHzbRo
# Rj2f0zySMNdQCuawE3WC5ZvT1dMs1F0yh4o0bFIWOHd7AsiP3dbC7vrGvEnT7tnU
# /0RfjW4yYSgVSK3K5uD9dQ9nPBv4YQIYTUvxpLkogOcHF/OTekd5Ryv3qjTZlAv4
# XtikRRsBhM+MZFh+yUgVk8hCB8vDgu1E0i5xPeX7bSb+JqMdqdhGKZ3N8WmsEEtR
# lniZw8Men8WML8EDT8pKTNnuVmEX5WVLKHchzsotSQkh/AVmQqAtiXPltU4zB/Cm
# zoQaaQludw2koR/Ej7FydTPfJaxLDV5toYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCCUr2QrlmjhX0ibQOw7SXVQtbwfA9LoQtx0bm5ra9ULpQIUMOzTLLmf545H
# zUdFnEAksEzE56kYDzIwMjUwODI1MTUzMTA0WjADAgEBoFikVjBUMQswCQYDVQQG
# EwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFs
# c2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMCAQICEAEA
# CyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5WhcNMzQx
# MjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBu
# di1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4PuCF6+aq
# Cj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb5gk0Xydy
# 3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJScRV1W6/6e
# fi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy5RJY+o1N
# WhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY0Lie04Du
# KbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2ZwbI6yiFH
# aS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYhKUlrMH9+
# 2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5sWtX1qvCz
# k6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGoMIIBpDAO
# BgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYE
# FIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQCMEEGCSsG
# AQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNv
# bS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5
# BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2Fj
# YXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24u
# Y29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn
# 48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xv
# YmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG9w0BAQwF
# AAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26IFq7fQMI
# rN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76TkvL+v2f4mH
# olGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftPttS+G/Mh
# NUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIlS3Ki74CU
# 15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt8DT4RQj9
# LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5lgJkgXEc
# 1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD9hQchjiG
# kyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71yzGKWnbA
# WQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGLZtJFJzGJ
# D7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVAGXCqHsh6
# 2QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZMIIEQaAD
# AgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0ds
# b2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYD
# VQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAwMDAwMFow
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOvdYNfqUdS
# x2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt0ShKwSy7
# uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrE
# iPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64
# VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16ZevRVqku
# vftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv
# +GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm19m1W/ood
# CT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIGbxsY1Tbq
# ZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMDAd6ZJflx
# bumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/MiyTdtk8EWf
# usE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9GbCX6oxQ
# kW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGGMBIGA1Ud
# EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDDvWWWMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAu
# BggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYWaxlASSUI
# HuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCyz+zCVmUd
# vX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W
# 8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWz
# Alcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59eodaZzul9
# S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8oMWsr1EG
# 8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1If5iEO0d
# MPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDU
# Y6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+
# PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+
# gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIIDa6ADAgEC
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
# AtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJYIZIAWUD
# BAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0
# MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcNAQkEMSIE
# IOz34b3l1FRkA8vYS+Ynh0LsDDctgoMDo88ogKYCdu0IMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAcOarRqRFsoWI
# y+aVHCokDOFGz6NIj+HJHOQXMZ+4djZC+5IWperEoHS6eqUkUGRFQni5biJqv4Xc
# ae32kv6YUxd/ZJVf8bqiFuMNiG8GbxdI/jT3oXSKicOF+aQ81RfriLDJp+Z66Pjv
# /MR9C/cxGlq38VqwMe6EK+9bq5/VaRGIA2zV9dQDNjuZ5ssDEuglzT3gxNQifQEy
# QIpCazvIoCe+e+oWlSgwDJWoxxpW02vo8nIi1Gs4LXQcnoIAXVWT5jBKmFULd7JQ
# ePzlPH18VnGKidE8Qq3mde9XUFplrEKGctnPmrOYG/XrEY3c6f0mvVX/zJXe0swp
# JpceOxoKtNTjif36THirJYrfsgoo4XkiK0XI8fOiW742wcpuUMZ0e8/+/I4oAtOl
# +Jcqa7ci9MFQ7Qq0yhuN3fIA8KC7kRYinfup4JJa3QvZDAQyGgbU7QozUN29fKLh
# kvTyu+WOdJiVEqCT/k5ag8rXmk6VBngvav5PxtBKKA7q5uuvsVqQ
# SIG # End signature block
