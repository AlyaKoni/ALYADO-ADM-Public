#Requires -Version 2.0

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
# MIIvGwYJKoZIhvcNAQcCoIIvDDCCLwgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBznG7jd67wJqUU
# Sw1O+f+fRieAIG2LLLG81+b9lCdIkaCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g6
# 04YfM/tV5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD
# 4ED6gVYDU/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S
# /gJXhZrh0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp
# 8nKmrVa46Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqt
# f2phU7+yR2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJ
# QWTEE/bP0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKX
# vYkPbEdx+QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4
# yMYgcMKb9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmY
# F8T4xO2k6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2
# mMIVpqWCZ1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7
# spNY6rQb3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd
# 2jANBgkqhkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy
# /fAHsVv1RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW
# 2H3Bh6zNXULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0
# MP6pBPKOL6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/
# pFL9zlcctWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcex
# U0bcV0hLQ4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf
# 6AMOGaM56A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzEC
# p9LnR+34c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9m
# UF5qE6YwQqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+Ku
# aJRsz+cnZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/Jl
# N6m6GM1jEhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutof
# dgNBzMUxghnmMIIZ4gIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHAJ3xVe
# AQKbdL74CgAqPKH9lNWRYKIhgULL0ssWXGkrMA0GCSqGSIb3DQEBAQUABIICAFfJ
# rzTju+PPBkddO5ja3YlY9Pqf1oQphkwz/a7oZKOqZgLGFJoSFBLrN6z9pgXljqJI
# Sw6FFePkgdLlBV5a21SK5X/VcfhEGmLv5oVeJjHTPRCteRqZgZFpCMefrg2uL3R6
# ZWfasxX5YkDO85KVVM9ALmwmrbV+E8XTXZCmgdlXwNq1p4vGeGDR3KzpBVFGqfxh
# DQ4QRC3YMdZ+bal65YCnCZFpSP4f3NGqggEQr3H5/XY1dhQxr5h0iCuBUMRmQhh7
# +//V0ajpbXKxLS5ztRgKp/jkADNz36a3OpH0h1ksHjp2c4nvu4j6or8jHcUVp3Cp
# nI4eLz8wHMybnLJrKlG0dnn1Jn8iz5RGSvOdwoNEftl0WL7DerCidqF84XBhZEgP
# hQMwSRqdJdCvZL2isbufP/IrHUuVp+VIUXrCFQc7MYjJ7kpDf4JDQDk2AB7LYn2N
# QGQ9wj3QHMS+9xYghA/mYWiz2kyxikQhSpUGDjIoOBgICyIJJUXVuktOSa3YSdhR
# ac+S6fmG62UQm+MGov5epRipdA4LL1DoTg3Ryu6gtMBNjsU8A/xvSi9sQ77adUSJ
# OA3RZeSLTX79Y1wrVFRTz+NSaYWS31vGWzi3q+uoya453Sb6VA2E/njR+gsiHWAz
# Sz6k6NMn19PPJH2tRzFH+EO1jTp82+etn5gbucieoYIWzTCCFskGCisGAQQBgjcD
# AwExgha5MIIWtQYJKoZIhvcNAQcCoIIWpjCCFqICAQMxDTALBglghkgBZQMEAgEw
# gegGCyqGSIb3DQEJEAEEoIHYBIHVMIHSAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCAw0o2Crfe7uVuYS938DiE2d8QLk2rh8CkuPN6tr5BhowIUeTWx
# znGraubiclzm3N8glPyZuVkYDzIwMjUwMjA2MTkxNDE4WjADAgEBoGGkXzBdMQsw
# CQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEzMDEGA1UEAwwq
# R2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2IC0gMjAyMzExoIISVDCC
# BmwwggRUoAMCAQICEAGb6t7ITWuP92w6ny4BJBYwDQYJKoZIhvcNAQELBQAwWzEL
# MAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMT
# KEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjMx
# MTA3MTcxMzQwWhcNMzQxMjA5MTcxMzQwWjBdMQswCQYDVQQGEwJCRTEZMBcGA1UE
# CgwQR2xvYmFsU2lnbiBudi1zYTEzMDEGA1UEAwwqR2xvYmFsc2lnbiBUU0EgZm9y
# IENvZGVTaWduMSAtIFI2IC0gMjAyMzExMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A
# MIIBigKCAYEA6oQ3UGg8lYW1SFRxl/OEcsmdgNMI3Fm7v8tNkGlHieUs2PGoan5g
# N0lzm7iYsxTg74yTcCC19SvXZgV1P3qEUKlSD+DW52/UHDUu4C8pJKOOdyUn4Ljz
# fWR1DJpC5cad4tiHc4vvoI2XfhagxLJGz2DGzw+BUIDdT+nkRqI0pz4Yx2u0tvu+
# 2qlWfn+cXTY9YzQhS8jSoxMaPi9RaHX5f/xwhBFlMxKzRmUohKAzwJKd7bgfiWPQ
# HnssW7AE9L1yY86wMSEBAmpysiIs7+sqOxDV8Zr0JqIs/FMBBHkjaVHTXb5zhMub
# g4htINIgzoGraiJLeZBC5oJCrwPr1NDag3rDLUjxzUWRtxFB3RfvQPwSorLAWapU
# l05tw3rdhobUOzdHOOgDPDG/TDN7Q+zw0P9lpp+YPdLGulkibBBYEcUEzOiimLAd
# M9DzlR347XG0C0HVZHmivGAuw3rJ3nA3EhY+Ao9dOBGwBIlni6UtINu41vWc9Q+8
# iL8nLMP5IKLBAgMBAAGjggGoMIIBpDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/
# BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYEFPlOq764+Fv/wscD9EHunPjWdH0/MFYG
# A1UdIARPME0wCAYGZ4EMAQQCMEEGCSsGAQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZo
# dHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8E
# AjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5BggrBgEFBQcwAYYtaHR0cDovL29jc3Au
# Z2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0MEMGCCsGAQUFBzAChjdo
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc3RzYWNhc2hhMzg0
# ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6
# MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNo
# YTM4NGc0LmNybDANBgkqhkiG9w0BAQsFAAOCAgEAlfRnz5OaQ5KDF3bWIFW8if/k
# X7LlFRq3lxFALgBBvsU/JKAbRwczBEy0tGL/xu7TDMI0oJRcN5jrRPhf+CcKAr4e
# 0SQdI8svHKsnerOpxS8M5OWQ8BUkHqMVGfjvg+hPu2ieI299PQ1xcGEyfEZu8o/R
# nOhDTfqD4f/E4D7+3lffBmvzagaBaKsMfCr3j0L/wHNp2xynFk8mGVhz7ZRe5Bqi
# EIIHMjvKnr/dOXXUvItUP35QlTSfkjkkUxiDUNRbL2a0e/5bKesexQX9oz37obDz
# K3kPsUusw6PZo9wsnCsjlvZ6KrutxVe2hLZjs2CYEezG1mZvIoMcilgD9I/snE7Q
# 3+7OYSHTtZVUSTshUT2hI4WSwlvyepSEmAqPJFYiigT6tJqJSDX4b+uBhhFTwJN7
# OrTUNMxi1jVhjqZQ+4h0HtcxNSEeEb+ro2RTjlTic2ak+2Zj4TfJxGv7KzOLEcN0
# kIGDyE+Gyt1Kl9t+kFAloWHshps2UgfLPmJV7DOm5bga+t0kLgz5MokxajWV/vbR
# /xeKriMJKyGuYu737jfnsMmzFe12mrf95/7haN5EwQp04ZXIV/sU6x5a35Z1xWUZ
# 9/TVjSGvY7br9OIXRp+31wduap0r/unScU7Svk9i00nWYF9A43aZIETYSlyzXRrZ
# 4qq/TVkAF55gZzpHEqAwggZZMIIEQaADAgECAg0B7BySQN79LkBdfEd0MA0GCSqG
# SIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMw
# EQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE4MDYy
# MDAwMDAwMFoXDTM0MTIxMDAwMDAwMFowWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQDwAuIwI/rgG+GadLOvdYNfqUdSx2E6Y3w5I3ltdPwx5HQSGZb6zidiW64H
# iifuV6PENe2zNMeswwzrgGZt0ShKwSy7uXDycq6M95laXXauv0SofEEkjo+6xU//
# NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrEiPDul/bc8xigS5kcDoenJuGIyaDlmeKe
# 9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64VJmKqDGSO/J6ffwOWN+BauGwbB5lgirU
# IceU/kKWO/ELsX9/RpgOhz16ZevRVqkuvftYPbWF+lOZTVt07XJLog2CNxkM0Kvq
# WsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv+GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50
# xHAotIB7vSqbu4ThDqxvDbm19m1W/oodCT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU
# 2EESwVX9bpHFu7FMCEue1EIGbxsY1TbqZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE
# 6giunUlnEYuC5a1ahqdm/TMDAd6ZJflxbumcXQJMYDzPAo8B/XLukvGnEt5CEk3s
# qSbldwKsDlcMCdFhniaI/MiyTdtk8EWfusE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac
# 0zd0hNkdZqs0c48efXxeltY9GbCX6oxQkW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCC
# ASUwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYE
# FOoWxmnn48tXRTkzpPBAvtDDvWWWMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3Ay
# Lmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8v
# Y3JsLmdsb2JhbHNpZ24uY29tL3Jvb3QtcjYuY3JsMEcGA1UdIARAMD4wPAYEVR0g
# ADA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBv
# c2l0b3J5LzANBgkqhkiG9w0BAQwFAAOCAgEAf+KI2VdnK0JfgacJC7rEuygYVtZM
# v9sbB3DG+wsJrQA6YDMfOcYWaxlASSUIHuSb99akDY8elvKGohfeQb9P4byrze7A
# I4zGhf5LFST5GETsH8KkrNCyz+zCVmUdvX/23oLIt59h07VGSJiXAmd6FpVK22LG
# 0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0
# +X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWzAlcfi5z8u6xM3vreU0yD/RKxtklVT3Wd
# rG9KyC5qucqIwxIwTrIIc59eodaZzul9S5YszBZrGM3kWTeGCSziRdayzW6CdaXa
# jR63Wy+ILj198fKRMAWcznt8oMWsr1EG8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpI
# iScseeI85Zse46qEgok+wEr1If5iEO0dMPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ
# 7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDUY6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx
# 773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+PvafnzkarqzSL3ogsfSsqh3iLRSd+pZq
# HcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV
# 5yBZtnjGpGqqIpswggWDMIIDa6ADAgECAg5F5rsDgzPDhWVI5v9FUTANBgkqhkiG
# 9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEG
# A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAw
# MDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9v
# dCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxT
# aWduMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlQfoc8pm+ewUyns8
# 9w0I8bRFCyyCtEjG61s8roO4QZIzFKRvf+kqzMawiGvFtonRxrL/FM5RFCHsSt0b
# WsbWh+5NOhUG7WRmC5KAykTec5RO86eJf094YwjIElBtQmYvTbl5KE1SGooagLcZ
# gQ5+xIq8ZEwhHENo1z08isWyZtWQmrcxBsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ
# 3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQBzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2M
# sonP0KBhd8hYdLDUIzr3XTrKotudCd5dRC2Q8YHNV5L6frxQBGM032uTGL5rNrI5
# 5KwkNrfw77YcE1eTtt6y+OKFt3OiuDWqRfLgnTahb1SK8XJWbi6IxVFCRBWU7qPF
# OJabTk5aC0fzBjZJdzC8cTflpuwhCHX85mEWP3fV2ZGXhAps1AJNdMAU7f05+4Py
# XhShBLAL6f7uj+FuC7IIs2FmCWqxBjplllnA8DX9ydoojRoRh3CBCqiadR2eOoYF
# AJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R/98wEfmFzzNI9cptZBQselhP00sIScWV
# ZBpjDnk99bOMylitnEJFeW4OhxlcVLFltr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlw
# g3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8G
# A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4IC
# AQCDJe3o0f2VUs2ewASgkWnmXNCE3tytok/oR3jWZZipW6g8h3wCitFutxZz5l/A
# VJjVdL7BzeIRka0jGD3d4XJElrSVXsB7jpl4FkMTVlezorM7tXfcQHKso+ubNT6x
# CCGh58RDN3kyvrXnnCxMvEMpmY4w06wh4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc
# 053y/0QMRGby0uO9RgAabQK6JV2NoTFR3VRGHE3bmZbvGhwEXKYV73jgef5d2z6q
# TFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvd
# OxOPEoziQRpIenOgd2nHtlx/gsge/lgbKCuobK1ebcAF0nu364D+JTf+AptorEJd
# w+71zNzwUHXSNmmc5nsE324GabbeCglIWYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ
# 4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Qv4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4Z
# sRg01Uyduu33H68klQR4qAO77oHl2l98i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3
# nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU4fVmR3l31VRbH60kN8tFWk6gREjI2LCZ
# xRWECfbWSUnAZbjmGnFuoKjxguhFPmzWAtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8w
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb
# 6t7ITWuP92w6ny4BJBYwCwYJYIZIAWUDBAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYL
# KoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0MR4wHDALBglghkgBZQMEAgGhDQYJKoZI
# hvcNAQELBQAwLwYJKoZIhvcNAQkEMSIEIJ8oI4tOUNKo+IcvizEW3m+PszBgOFUP
# CpTvX0/mZtyQMIGwBgsqhkiG9w0BCRACLzGBoDCBnTCBmjCBlwQgOoh6lRteuSpe
# 4U9su3aCN6VF0BBb8EURveJfgqkW0egwczBfpF0wWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb6t7ITWuP92w6ny4BJBYwDQYJ
# KoZIhvcNAQELBQAEggGAxr9mYWo+CRUKAmrV7xkN8Z3kkpOniQSpUOzPD0Q6rALZ
# 0vsaUogV+B8SmEZcLFRGVp6gT0iorcHQVpgGYmr1gwMIV+JcuUG2e3K06sLosfT5
# IPR6cNZt9IF1Qe89LaqpQtdnAVwb8MuBs4D3yXrb4yg0lLOsd3pd2ZZaaeImk7No
# 1nxPrn7z85CeOMrWHcUgaw3m3tY3RTD0ioU9pFXJEXHlN+bC/OvkY8G4+zr59se7
# f8GUTwQAMo8w2f05t6aSrooBy6ZU4So40NT8c8aOHUuvpaVAzFMMcHeGTYBhtKYk
# 6ddHngiKwQErE7REWUnQpmNJMcAQ/86v0FWP2M848E4IEcpEIccQn4sZ4HW03+Wc
# FvhiGfYE8TLCGP/RVFNg0AJ5Dtm63GLkjt1al/uOPdlz2rWFZmQ8in5JZHaVAh/m
# y6QVcf3oRjth7l+7XWK4As5KEJSsj3MXocmQcn59bQl53QJ9+dEITjUlGNEWU6fq
# dJtyLMFS9xrSv3K/x2t7
# SIG # End signature block
