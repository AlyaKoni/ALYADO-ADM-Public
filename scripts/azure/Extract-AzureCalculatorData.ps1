#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2020-2021

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
    Alya Basis Konfiguration ist Freie Software: Sie koennen es unter den
	Bedingungen der GNU General Public License, wie von der Free Software
	Foundation, Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
    veroeffentlichten Version, weiter verteilen und/oder modifizieren.
    Alya Basis Konfiguration wird in der Hoffnung, dass es nuetzlich sein wird,
	aber OHNE JEDE GEWAEHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewaehrleistung der MARKTFAEHIGKEIT oder EIGNUNG FUER EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Public License fuer weitere Details:
	https://www.gnu.org/licenses/gpl-3.0.txt

    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    18.03.2021 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\azure\Extract-AzureCalculatorData-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "MSOnline"
Install-ModuleIfNotInstalled "ImportExcel"

# Main
Write-Host "Getting actual configuration"
$resp = Invoke-WebRequest -UseBasicParsing -Method GET -Uri "https://azure.microsoft.com/en-us/pricing/calculator/"
$mtch = $resp.Content -match "var resolvedCurrencyList = (.*);"
$currencyList = ConvertFrom-Json -InputObject $Matches[1]
$mtch = $resp.Content -match "global.rawCurrencyData = (.*);"
$currencyData = ConvertFrom-Json -InputObject $Matches[1]
$mtch = $resp.Content -match "name=`"awa-stv`" content=`"(.*)`""
$version = $Matches[1]
$culture = "en-us"
$discount = "mosp"
$currency = "chf"
$csvDelemiter = ";"
$query = "?culture=$culture&discount=$discount&v=$version"
$currency = $currencyData."$currency"

Write-Host "Getting data"
$support = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v2/pricing/support/calculator/$query"
$regions = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v2/pricing/calculator/regions/$query"
$resources = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v2/calculator/resources/$query"
$solutionarchitectures = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v2/pricing/solution-architectures/calculator/$query"
$categories = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v2/pricing/categories/calculator/$query"
$bandwidth = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v2/pricing/bandwidth/calculator/$query"
$manageddisks = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v2/pricing/managed-disks/calculator/$query"
$virtualmachines = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v3/pricing/virtual-machines/calculator/$query"
$postgresql = Invoke-RestMethod -Method GET -UseBasicParsing -Uri "https://azure.microsoft.com/api/v3/pricing/postgresql/calculator/$query"

Write-Host "Building products table" -ForegroundColor $CommandInfo
$productsCsv = [System.Collections.ArrayList]@()
foreach ($categorySlug in $categories.slug)
{
    $category = $categories | where { $_.slug -eq $categorySlug }
    #Write-Host "Category: $($category.displayName)"
    foreach ($productSlug in $category.products.slug)
    {
        $product = $category.products | where { $_.slug -eq $productSlug }
        #Write-Host "  Product: $($product.displayName)"

        $pricingUrl = $product.links.pricingUrl
        $documentationUrl = $product.links.documentationUrl
        $url = $product.links.url
        $slaUrl = $product.links.slaUrl
        $roadmapUrl = $product.links.roadmapUrl
        if ($pricingUrl -eq "#") { $pricingUrl = "" }
        if ($documentationUrl -eq "#") { $documentationUrl = "" }
        if ($url -eq "#") { $url = "" }
        if ($slaUrl -eq "#") { $slaUrl = "" }
        if ($roadmapUrl -eq "#") { $roadmapUrl = "" }
        if ($pricingUrl.StartsWith("/")) { $pricingUrl = "https://azure.microsoft.com"+$pricingUrl }
        if ($documentationUrl.StartsWith("/")) { $documentationUrl = "https://azure.microsoft.com"+$documentationUrl }
        if ($url.StartsWith("/")) { $url = "https://azure.microsoft.com"+$url }
        if ($slaUrl.StartsWith("/")) { $slaUrl = "https://azure.microsoft.com"+$slaUrl }
        if ($roadmapUrl.StartsWith("/")) { $roadmapUrl = "https://azure.microsoft.com"+$roadmapUrl }

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

Write-Host "Building postgresql table" -ForegroundColor $CommandInfo
$postgresqlCsv = [System.Collections.ArrayList]@()
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
$allTypes = @()
$allTypes += "compute"
foreach ($ctype in $postgresql.computeTypes.slug)
{
    foreach ($vcores in $postgresql.vCores.slug)
    {
        $allTypes += "compute-"+$ctype+"-"+$vcores
    }
}
$allVms = @()
foreach ($sku in (Get-Member -InputObject $postgresql.skus))
{
    if (@("Equals","GetHashCode","GetType","ToString","Copy","Invoke","IsInstance","MemberType","Name","OverloadDefinitions","TypeNameOfValue","Value") -notcontains $sku.Name)
    {
        if ($sku.Name.StartsWith("flexible-server"))
        {
            $vmName = $sku.Name.Substring($sku.Name.LastIndexOf("-") + 1, $sku.Name.Length - $sku.Name.LastIndexOf("-") - 1)
            if ($allVms -notcontains $vmName -and $vmName -ne "backup" -and $vmName -ne "storage")
            {
                $allVms += $vmName
            }
        }
    }
}
foreach ($vmName in $allVms)
{
    $allTypes += "compute-"+$vmName
}
$allTypes += "storage"
foreach ($stype in $postgresql.hyperscaleStorageOptions.slug)
{
    $allTypes += "storage-"+$stype
}
$allTypes += "backup"
foreach ($btype in $postgresql.backupRedundancies.slug)
{
    $allTypes += "backup-"+$btype
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
foreach ($region in $postgresql.regions)
{
    #$region = $postgresql.regions | where { $_.slug -eq "switzerland-north" }
    #Write-Host "Region: $($region.displayName)"
    $tierSlugs =  $postgresql.tiers.slug
    $tierSlugs += ""
    foreach ($tierSlug in $tierSlugs)
    {
        $tier = $postgresql.tiers | Where { $_.slug -eq $tierSlug }
        $tierName = $tier.displayName
        if ([string]::IsNullOrEmpty($tierName)) { $tierName = $tierSlug }
        #$tier = $postgresql.tiers | where { $_.slug -eq "standardssd" }
        #Write-Host "  Tier: $($tierName)"
        if (-Not [string]::IsNullOrEmpty($tierSlug)) { $tierSlug += "-" }
        $deploymentOptionSlugs = $postgresql.deploymentOptions.slug
        foreach ($deploymentOptionSlug in $deploymentOptionSlugs)
        {
            $deploymentOption = $postgresql.deploymentOptions | Where { $_.slug -eq $deploymentOptionSlug }
            $deploymentOptionName = $deploymentOption.displayName
            if ([string]::IsNullOrEmpty($deploymentOptionName)) { $deploymentOptionName = $deploymentOptionSlug }
            #Write-Host "    DeploymentOption: $($deploymentOptionSlug)"
            $deploymentOptionSlug = $deploymentOptionSlug -replace "flexibleserver", "flexible-server"
            if ($deploymentOptionSlug -eq "server") { $deploymentOptionSlug = "" }
            if (-Not [string]::IsNullOrEmpty($deploymentOptionSlug)) { $deploymentOptionSlug += "-" }
            foreach ($skuType in $allTypes)
            {
                #Write-Host "    Type: $($skuType)"
                $skuName = "$deploymentOptionSlug$tierSlug$skuType"
                #Write-Host "    SkuName: $($skuName)"
                $sku = Get-Member -InputObject $postgresql.skus -Name $skuName
                if ($sku)
                {
                    $obj = [pscustomobject]@{
                        deploymentOption = $deploymentOptionName
                        tier = $tierName
                        type = $skuType
                        region = $region.displayName
                        memory = $null
                        storageGb = $null
                    }
                    $memory = $null
                    $storageGb = $null
                    $onePriceFound = $false
                    foreach($skuPriceNameToFind in $allSkus)
                    {
                        $skuPriceNameToFindCsv = $skuPriceNameToFind -replace "reserved", ""
                        $price = 0.0
                        foreach($skuPriceName in (Get-Member -InputObject $postgresql.skus.$skuName))
                        {
                            if (@("Equals","GetHashCode","GetType","ToString","Copy","Invoke","IsInstance","MemberType","Name","OverloadDefinitions","TypeNameOfValue","Value") -notcontains $skuPriceName.Name)
                            {
                                $offers = $postgresql.skus.$skuName."$($skuPriceName.Name)"
                                foreach($offer in $offers)
                                {
                                    if ($offer -like "*$skuPriceNameToFind")
                                    {
                                        $prices = $allOffers[$offer]
                                        $memb = Get-Member -InputObject $prices -Name $region.slug -ErrorAction SilentlyContinue
                                        if ($memb)
                                        {
                                            $price += $prices."$($region.slug)".value * $currency.conversion
                                            $onePriceFound = $true
                                        }
                                        $offerName = $offer.Substring(0, $offer.LastIndexOf("-") - 1)
                                        $mem = $postgresql.offers.$offerName.memory
                                        $gb = $postgresql.offers.$offerName.storageGb
                                        if ($memory -and $memory -notlike "*$mem*")
                                        {
                                            $memory += ",$mem"
                                        }
                                        else
                                        {
                                            $memory = $mem
                                        }
                                        if ($storageGb -and $storageGb -notlike "*$gb*")
                                        {
                                            $storageGb += ",$gb"
                                        }
                                        else
                                        {
                                            $storageGb = $gb
                                        }
                                    }
                                }
                            }
                        }
                        if ($price -eq 0.0) { $price = $null }
                        Add-Member -InputObject $obj -MemberType NoteProperty -Name $skuPriceNameToFindCsv -Value $price
                    }
                    $obj.memory = $memory
                    $obj.storageGb = $storageGb
                    if ($onePriceFound) { $postgresqlCsv.Add($obj) | Out-Null }
                }
            }
        }
    }
}

Write-Host "Building disk table" -ForegroundColor $CommandInfo
$diskCsv = [System.Collections.ArrayList]@()
foreach ($region in $manageddisks.regions)
{
    #$region = $manageddisks.regions | where { $_.slug -eq "switzerland-north" }
    #Write-Host "Region: $($region.displayName)"
    $tierSlugs =  $manageddisks.tiers.slug
    $tierSlugs += "burstable"
    $tierSlugs += "transactions"
    foreach ($tierSlug in $tierSlugs)
    {
        $tier = $manageddisks.tiers | Where { $_.slug -eq $tierSlug }
        $tierName = $tier.displayName
        if ([string]::IsNullOrEmpty($tierName)) { $tierName = $tierSlug }
        #$tier = $manageddisks.tiers | where { $_.slug -eq "standardssd" }
        #Write-Host "  Tier: $($tierName)"
        $sizeSlugs =  $manageddisks.sizes.slug
        $sizeSlugs += "hdd"
        $sizeSlugs += "ssd"
        $sizeSlugs += "snapshot"
        $sizeSlugs += "enablement"
        $sizeSlugs += "transaction"
        foreach ($sizeSlug in $sizeSlugs)
        {
            $size = $manageddisks.sizes | Where { $_.slug -eq $sizeSlug }
            $sizeName = $size.displayName
            if ([string]::IsNullOrEmpty($sizeName)) { $sizeName = $sizeSlug }
            #Write-Host "    Size: $($sizeName)"
            $sizeSlug = $sizeSlug -replace "ultra", ""
            $redundancySlugs =  $manageddisks.tierRedundancies.slug
            $redundancySlugs += ""
            foreach ($redundancySlug in $redundancySlugs)
            {
                $redundancy = $manageddisks.tierRedundancies | where { $_.slug -eq $redundancySlug }
                #$redundancy = $manageddisks.tierRedundancies | where { $_.slug -eq "lrs" }
                #Write-Host "      Redundancy: $($redundancy.displayName)"
                foreach ($addType in @("", "-disk-mount", "-one-year"))
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
                            $price = $offer.prices."$($region.slug)".value * $currency.conversion
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

Write-Host "Building compute table" -ForegroundColor $CommandInfo
$computeCsv = [System.Collections.ArrayList]@()
$allSkus = [System.Collections.ArrayList]@()
foreach ($sku in (Get-Member -InputObject $virtualmachines.skus))
{
    if (@("Equals","GetHashCode","GetType","ToString","Copy","Invoke","IsInstance","MemberType","Name","OverloadDefinitions","TypeNameOfValue","Value") -notcontains $sku.Name)
    {
        $membs = Get-Member -InputObject $virtualmachines.skus."$($sku.Name)"
        foreach($memb in $membs)
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
$allOffers = @{}
foreach ($offerName in (Get-Member -InputObject $virtualmachines.offers))
{
    if (@("Equals","GetHashCode","GetType","ToString","Copy","Invoke","IsInstance","MemberType","Name","OverloadDefinitions","TypeNameOfValue","Value") -notcontains $offerName.Name)
    {
        $offer = $virtualmachines.offers."$($offerName.Name)"
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
foreach ($operatingSystem in ($virtualmachines.operatingSystems | Sort-Object -Property "displayName" -Descending))
{
    #$operatingSystem = $virtualmachines.operatingSystems | where { $_.slug -eq "windows" }
    #Write-Host "Operating System: $($operatingSystem.displayName)"
    foreach ($tier in $virtualmachines.tiers)
    {
        #$tier = $virtualmachines.tiers | where { $_.slug -eq "standard" }
        #Write-Host "  Tier: $($tier.displayName)"
        foreach ($region in $virtualmachines.regions)
        {
            #$region = $virtualmachines.regions | where { $_.slug -eq "switzerland-north" }
            #Write-Host "    Region: $($region.displayName)"
            foreach ($groupSlug in ($virtualmachines.dropdown.slug | Sort-Object))
            {
                $group = $virtualmachines.dropdown | Where { $_.slug -eq $groupSlug }
                $groupName = $group.displayName
                if ([string]::IsNullOrEmpty($groupName)) { $groupName = $groupSlug }
                if (-Not $groupName) { $groupName = "All" }
                #Write-Host "      Group: $($groupName)"
                $groupSeries = $group.series
                foreach ($subgroupSlug in ($groupSeries.slug | Sort-Object))
                {
                    $subgroup = $groupSeries | Where { $_.slug -eq $subgroupSlug }
                    $subgroupName = $subgroup.displayName
                    if ([string]::IsNullOrEmpty($subgroupName)) { $subgroupName = $subgroupSlug }
                    #Write-Host "        Sub Group: $subgroupName"
                    $instances = $subgroup.instances
                    foreach ($instance in $instances)
                    {
                        $slug = $instance.slug
                        $memb = Get-Member -InputObject $virtualmachines.skus -Name "$($operatingSystem.slug)-$slug-$($tier.slug)" -ErrorAction SilentlyContinue
                        if ($memb)
                        {
                            #Write-Host "          Instance: $($operatingSystem.slug)-$slug-$($tier.slug)"
                            $instanceName = $instance.displayName.Split(":")[0]
                            $instanceDesc = $instance.displayName.Split(":")[1]
                            $offer = $virtualmachines.offers."$($operatingSystem.slug)-$slug-$($tier.slug)"
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
                                    instance = "$($operatingSystem.slug)-$slug-$($tier.slug)"
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
                                foreach($sku in $allSkus)
                                {
                                    $priceName = "price" + $sku
                                    $memb = Get-Member -InputObject $virtualmachines.skus."$($operatingSystem.slug)-$slug-$($tier.slug)" -Name $sku -ErrorAction SilentlyContinue
                                    if ($memb)
                                    {
                                        $price = 0.0
                                        $offers = $virtualmachines.skus."$($operatingSystem.slug)-$slug-$($tier.slug)"."$sku"
                                        foreach($offer in $offers)
                                        {
                                            $prices = $allOffers[$offer]
                                            $memb = Get-Member -InputObject $prices -Name $region.slug -ErrorAction SilentlyContinue
                                            if ($memb)
                                            {
                                                $price += $prices."$($region.slug)".value * $currency.conversion
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
                            }
                        }
                        else
                        {
                            #Write-Warning "SKU not found: $($operatingSystem.slug)-$slug-$($tier.slug)"
                        }
                    }
                }
            }
        }
    }
}

Write-Host "Exporting Excel" -ForegroundColor $CommandInfo
$excel = $computeCsv | Export-Excel -Path "$AlyaData\azure\Prices.xlsx" -WorksheetName "PricesVMs" -TableName "PricesVMs" -BoldTopRow -AutoFilter -FreezeTopRow -ClearSheet -PassThru
Close-ExcelPackage $excel
$excel = $diskCsv | Export-Excel -Path "$AlyaData\azure\Prices.xlsx" -WorksheetName "PricesDisks" -TableName "PricesDisks" -BoldTopRow -AutoFilter -FreezeTopRow -ClearSheet -PassThru
Close-ExcelPackage $excel
$excel = $postgresqlCsv | Export-Excel -Path "$AlyaData\azure\Prices.xlsx" -WorksheetName "PricesPostgreSql" -TableName "PricesPostgreSql" -BoldTopRow -AutoFilter -FreezeTopRow -ClearSheet -PassThru
Close-ExcelPackage $excel
$excel = $productsCsv | Export-Excel -Path "$AlyaData\azure\Prices.xlsx" -WorksheetName "PricesProducts" -TableName "PricesProducts" -BoldTopRow -AutoFilter -FreezeTopRow -ClearSheet -PassThru
Close-ExcelPackage $excel -Show
#$computeCsv | Export-Csv -NoTypeInformation -Path "$AlyaData\azure\PricesVMs.csv" -Encoding UTF8 -Delimiter $csvDelemiter -Force
#$diskCsv | Export-Csv -NoTypeInformation -Path "$AlyaData\azure\PricesDisks.csv" -Encoding UTF8 -Delimiter $csvDelemiter -Force
#$productsCsv | Export-Csv -NoTypeInformation -Path "$AlyaData\azure\PricesProducts.csv" -Encoding UTF8 -Delimiter $csvDelemiter -Force

#Stopping Transscript
Stop-Transcript
