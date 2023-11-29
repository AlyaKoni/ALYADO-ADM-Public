#Requires -Version 2.0

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
