#Requires -Version 2.0

[CmdletBinding()]
param(
    [string]$processOnlyOnsiteUrl = $null
)

# Starting Clean-Topic
Write-Host "Starting Clean-Topic"
$root = $PSScriptRoot

# Starting Transcript
Write-Host "Starting Transcript"
$TimeString = (Get-Date).ToString("yyyyMMddHHmmssfff")
if (-not (Test-Path "$root\logs")) {
    New-Item -Path "$root\logs" -ItemType Directory -Force | Out-Null
}
Start-Transcript -Path "$root\logs\Clean-Topic-$($TimeString).log" | Out-Null
(Get-Date).ToString("yyyyMMddHHmmssfff")

# Members
$DryRun = $false

# Checking module
Write-Host "Checking module"
$mod = Get-Module -Name "ImportExcel" -ListAvailable
if (-Not $mod) {
    Write-Warning "Module ImportExcel not found. Installing in scope CurrentUser"
    Install-Module "ImportExcel" -Scope CurrentUser -AllowClobber
}
Import-Module "ImportExcel" -ErrorAction SilentlyContinue

# Configurations
. "$root\..\SharedPNP.ps1"
if (-not (Test-Path "$root\Data")) {
    New-Item -Path "$root\Data" -ItemType Directory -Force | Out-Null
}

# Getting mappings
Write-Host "Getting site mapping"
if (-not (Test-Path "$root\..\2Migrate\Mapping\SiteMapping.xlsx")) {
    Write-Error "Missing SiteMapping.xlsx file in $root\..\2Migrate\Mapping. Please create it first."
    Stop-Transcript
    exit
}
$SiteMappings = Import-Excel "$root\..\2Migrate\Mapping\SiteMapping.xlsx" -WorksheetName "SiteMapping" -ErrorAction Stop

Write-Host "Getting clean mapping"
if (-not (Test-Path "$root\..\2Migrate\Mapping\CleanMapping.xlsx")) {
    Write-Error "Missing CleanMapping.xlsx file in $root\..\2Migrate\Mapping. Please create it first."
    Stop-Transcript
    exit
}
$CleanMappings = Import-Excel "$root\..\2Migrate\Mapping\CleanMapping.xlsx" -WorksheetName "CleanMapping" -ErrorAction Stop

# Processing
Write-Host "Processing"
$allData = @()

# Logins
$adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl

Write-Host "Loading online term set"
if (-Not $rootTermsOnline)
{
    $termSetOnline = $null
    $rootTermsOnline = $null
    $rootGroups = Get-PnPTermGroup -Connection $adminCon
    foreach ($rootGroup in $rootGroups) {
        if ($rootGroup.Name -eq "TermGroupName") {
            $termSets = Get-PnPTermSet -Connection $adminCon -TermGroup $rootGroup
            foreach ($termSet in $termSets) {
                if ($termSet.Name -eq "TermSetName") {
                    $termSetOnline = $termSet
                    $rootTermOnline = Get-PnPTerm -Connection $adminCon -TermGroup $rootGroup -TermSet $termSetOnline -Identity "Topics" -IncludeChildTerms -IncludeDeprecated -Includes Labels, Terms
                    $queue = [System.Collections.Generic.Queue[object]]::new()
                    $rootTermsOnline = @()
                    foreach($term in $rootTermOnline)
                    {
                        $queue.Enqueue($term)
                    }
                    foreach($term in $rootTermOnline.Terms)
                    {
                        $queue.Enqueue($term)
                    }
                    while ($queue.Count -gt 0)
                    {
                        $term = $queue.Dequeue()
                        $rootTermsOnline += $term
                        $rootTermOnline = Get-PnPTerm -Connection $adminCon -TermGroup $rootGroup -TermSet $termSetOnline -Identity $term -IncludeChildTerms -IncludeDeprecated -Includes Labels, Terms
                        foreach($term in $rootTermOnline.Terms)
                        {
                            $queue.Enqueue($term)
                        }
                    }
                    break
                }
            }
        }
    }
    if (-Not $termSetOnline) {
        Write-Error "Can't find TermSetName term set in online tenant"
        Stop-Transcript
        exit
    }
    if (-Not $rootTermsOnline) {
        Write-Error "Can't find Topics terms in TermSetName term set in online tenant"
        Stop-Transcript
        exit
    }

}
$expTaxonomy = [XML](Get-Content -Path "$root\data\Taxonomy.xml" -Encoding utf8BOM -Raw)

function Find-Term() {
    param (
        $terms,
        $termName,
        $termGuid,
        $termLabel
    )
    foreach ($term in $terms) {
        if ($term.Name -eq $termName -or $term.Name.Replace("&","＆") -eq $termName.Replace("&","＆") -or $term.Id -eq $termGuid -or ($termLabel -and $term.Labels | Where-Object { $_.Value -eq $termLabel })) {
            return $term
        }
    }
    foreach ($term in $terms) {
        if ($term.Terms) {
            $foundTerm = Find-Term -terms $term.Terms -termName $termName -termGuid $termGuid -termLabel $termLabel
            if ($foundTerm) {
                return $foundTerm
            }
        }
    }
    return $null
}

# Checking onprem terms in online store
foreach ($termOnPrem in $termsOnPrem) {
    $termSetOnPrem = $termSetsOnPrem | Where-Object { $_.id -eq $termOnPrem.TermSets }
    if ($termSetOnPrem.Name -ne "Topics") { continue }
    $onlineTermSet = $termSetOnline.Terms | Where-Object { $_.Name -eq $termSetOnPrem.Name }
    if ($onlineTermSet)
    {
        #Write-Host "Term $($termSetOnPrem.Name)/$($termOnPrem.ParentName)/$($termOnPrem.Name)/$($termOnPrem.Id)"
    }

    $termOnline = Find-Term -terms $rootTermsOnline -termName $termOnPrem.Name
    if (-Not $termOnline)
    {
        Write-Host "Not found"
        Write-Host "Not found Term $($termSetOnPrem.Name)/$($termOnPrem.ParentName)/$($termOnPrem.Name)/$($termOnPrem.Id)"
    }
}

try {
    foreach ($SiteMapping in $SiteMappings) {
        if ($SiteMapping.OLSite -eq "NOT RELEVANT") {
            continue
        }
        if (-Not [string]::IsNullOrWhiteSpace($processOnlyOnsiteUrl) -and $SiteMapping.OLSite.TrimEnd("/") -ne $processOnlyOnsiteUrl.TrimEnd("/")) {
            continue
        }
        try {

            # Cleaning map
            if ($SiteMapping.OPList -ne "Documents") { continue }
            Write-Host "Cleaning $($SiteMapping.OPSite)/$($SiteMapping.OPList) $($SiteMapping.OLSite)/$($SiteMapping.OLList)"
            $srcSiteUrl = $SiteMapping.OPSite
            $srcListName = $SiteMapping.OPList
            $dstSiteUrl = $SiteMapping.OLSite
            $dstListName = $SiteMapping.OLList
            $dstListFolder = $SiteMapping.OLFolder

            Write-Host "  Connecting"
            $dstCon = LoginTo-PnP -Url $dstSiteUrl
            
            Write-Host "  Getting lists"
            $dstList = Get-PnPList -Connection $dstCon -Identity $dstListName
            if (-Not $dstList) {
                Write-Warning "Can't find destination list $dstListName, skipping"
                $allData += [PSCustomObject]@{
                    ResultType = "DestinationListNotFound"
                    OLSite     = $SiteMapping.OLSite
                    OLList     = $SiteMapping.OLList
                    ItemID     = $dstSiteUrl
                    Data       = $dstListName
                }
                continue
            }

            # Getting source data
            Write-Host "  Getting source data"
            $srcSiteFileName = $srcSiteUrl -replace "[^a-zA-Z0-9]", "" 
            $srcListFileName = $srcListName -replace "[^a-zA-Z0-9]", "" 
            $srcFileNameItems = "$root\data\$($srcSiteFileName)_$($srcListFileName)-items.json"
            if (-Not (Test-Path $srcFileNameItems))
            {
                throw "On-Premises data file not found: $srcFileNameItems"
            }
            $siteData = Get-Content -Path $srcFileNameItems | ConvertFrom-Json -AsHashTable
            $items = $siteData.d.results
            Write-Host "    $($items.Count) items from On-Premises"

            # Processing items
            Write-Host "  Processing items"
            foreach ($srcItem in $items) {
                try {
                    $srcValue = [bool]$srcItem["MigAttrName1"]
                    #TODO check too much items
                    if (-Not $srcValue) { continue }
                    Write-Host "    Item $($srcItem.ID)"

                    $srcFileUrl = $AlyaSharePointOnPremUrl + $srcItem.File.ServerRelativeUrl
                    if ([string]::IsNullOrWhiteSpace($dstListFolder)) {
                        $dstFileUrl = $srcFileUrl -replace [RegEx]::Escape(($SiteMapping.OPSite + "/lists/Published")), ($SiteMapping.OLSite + "/Shared Documents")
                        $dstFileUrl = $dstFileUrl -replace [RegEx]::Escape(($SiteMapping.OPSite + "/lists/Images")), ($SiteMapping.OLSite + "/Shared Documents")
                        $dstFileUrl = $dstFileUrl -replace [RegEx]::Escape(($SiteMapping.OPSite + "/lists/Documents")), ($SiteMapping.OLSite + "/Shared Documents")
                    } else {
                        $dstFileUrl = $srcFileUrl -replace [RegEx]::Escape(($SiteMapping.OPSite + "/lists/Published")), ($SiteMapping.OLSite + "/Shared Documents/$dstListFolder")
                        $dstFileUrl = $dstFileUrl -replace [RegEx]::Escape(($SiteMapping.OPSite + "/lists/Images")), ($SiteMapping.OLSite + "/Shared Documents/$dstListFolder")
                        $dstFileUrl = $dstFileUrl -replace [RegEx]::Escape(($SiteMapping.OPSite + "/lists/Documents")), ($SiteMapping.OLSite + "/Shared Documents/$dstListFolder")
                    }
                    Write-Host "      dstFileUrl: $dstFileUrl"
                    
                    $dstItem = Get-PnPFile -Connection $dstCon -Url $dstFileUrl.Replace("https://customer.sharepoint.com","") -AsListItem -ErrorAction SilentlyContinue
                    if (-Not $dstItem -or -Not $dstItem.Id) {
                        $dstItem = Get-PnPFile -Connection $dstCon -Url ([uri]::EscapeUriString($dstFileUrl.Replace("https://customer.sharepoint.com",""))) -AsListItem -ErrorAction SilentlyContinue
                    }
                    if (-Not $dstItem -or -Not $dstItem.Id) {
                        $dstFileRootUrl = $SiteMapping.OLSite + "/Shared Documents/" + (Split-Path -Leaf $dstFileUrl)
                        $dstItem = Get-PnPFile -Connection $dstCon -Url $dstFileRootUrl.Replace("https://customer.sharepoint.com","") -AsListItem -ErrorAction SilentlyContinue
                        if (-Not $dstItem -or -Not $dstItem.Id) {
                            $dstItem = Get-PnPFile -Connection $dstCon -Url ([uri]::EscapeUriString($dstFileRootUrl.Replace("https://customer.sharepoint.com",""))) -AsListItem -ErrorAction SilentlyContinue
                        }
                        if (-Not $dstItem -or -Not $dstItem.Id)
                        {
                            $dstItem = Get-PnPFile -Connection $dstCon -Url $dstFileRootUrl -AsListItem -ErrorAction SilentlyContinue
                        }
                        if (-Not $dstItem -or -Not $dstItem.Id)
                        {
                            Write-Warning "Can't find destination item for source item $($srcItem.ID) with file URL $srcFileUrl, skipping"
                            $allData += [PSCustomObject]@{
                                ResultType = "DestinationItemNotFound"
                                OLSite     = $SiteMapping.OLSite
                                OLList     = $SiteMapping.OLList
                                ItemID     = $srcItem.ID
                                Data       = "$srcFileUrl|$dstFileUrl"
                            }
                            continue
                        }
                        else
                        {
                            $folderUrl = [uri]::UnescapeDataString((Split-Path $dstFileUrl -Parent).Replace("\","/"))
                            $actUrl = $SiteMapping.OLSite + "/Shared Documents/"
                            do {
                                $actUrlRel = $actUrl.Replace("https://customer.sharepoint.com", "").TrimEnd("/")
                                $folderParent = Get-PnPFolder -Connection $dstCon -Url $actUrlRel
                                $newPart = $folderUrl.Replace($actUrl, "").Trim("/").Split("/")[0].Trim("/")
                                $folder = Get-PnPFolder -Connection $dstCon -Url ($actUrlRel + "/" + $newPart) -AsListItem -ErrorAction SilentlyContinue
                                if (-Not $folder -or -Not $folder.id)
                                {
                                    $null = Add-PnPFolder -Connection $dstCon -Folder $folderParent -Name $newPart
                                }
                                $actUrl = $actUrl.TrimEnd("/") + "/" + $newPart
                            } while ($actUrl -ne $folderUrl)
                            $moveUrl = ($dstFileRootUrl -replace $SiteMapping.OLSite, "").TrimStart("/")
                            $targUrl = ($dstFileUrl -replace $SiteMapping.OLSite, "").TrimStart("/")
                            Write-Host "      Moving $($moveUrl) to $($targUrl)"
                            $null = Move-PnPFile -Connection $dstCon -SourceUrl $moveUrl -TargetUrl $targUrl -Force
                            $dstItem = Get-PnPFile -Connection $dstCon -Url $dstFileUrl.Replace("https://customer.sharepoint.com","") -AsListItem -ErrorAction SilentlyContinue
                            if (-Not $dstItem -or -Not $dstItem.Id) {
                                $dstItem = Get-PnPFile -Connection $dstCon -Url ([uri]::EscapeUriString($dstFileUrl.Replace("https://customer.sharepoint.com",""))) -AsListItem -ErrorAction SilentlyContinue
                            }
                        }
                    }

                    $srcValue = $srcItem["CSWorkspaceTopic"]
                    if (-Not $srcValue) {
                        Write-Host "      No CSWorkspaceTopic, skipping"
                        continue
                    }

                    $dstTerms = @()
                    foreach ($termVal in $srcValue.results) {
                        $termOnPrem = $expTaxonomy.SelectSingleNode("//Term[@Id='$($termVal.TermGuid)']")
                        if (-Not $termOnPrem) {
                            Write-Warning "Can't find term $($termVal.Label)/$($termVal.TermGuid) in on-premises tenant, skipping"
                            $allData += [PSCustomObject]@{
                                ResultType = "OnPremTermNotFound"
                                OLSite     = $SiteMapping.OLSite
                                OLList     = $SiteMapping.OLList
                                ItemID     = $srcItem.ID
                                Data       = "$($termVal.Label)/$($termVal.TermGuid)"
                            }
                            continue
                        }
                        $termOnline = Find-Term -terms $rootTermsOnline -termName $termOnPrem.Name
                        if (-Not $termOnline) {
                            Write-Warning "Can't find term $($termOnPrem.ParentName)$($termOnPrem.Name) in online tenant, skipping"
                            $allData += [PSCustomObject]@{
                                ResultType = "OnlineTermNotFound"
                                OLSite     = $SiteMapping.OLSite
                                OLList     = $SiteMapping.OLList
                                ItemID     = $srcItem.ID
                                Data       = "$($termOnPrem.ParentName)/$($termOnPrem.Name)/$($termOnPrem.TermGuid)"
                            }
                            continue
                        }
                        Write-Host "      Found term '$($termOnPrem.Name)' in on-premises and online tenant"
                        $dstTerms += $termOnline
                    }

                    if ($dstTerms.Count -lt 1) {
                        Write-Host "      No terms to set, skipping"
                        continue
                    }

                    if ($dstTerms.Count -eq 1) {
                        Write-Host "      Setting AttrName8 term $($dstTerms.Name)"
                        if (-Not $DryRun) {
                            Set-PnPTaxonomyFieldValue -Connection $dstCon -ListItem $dstItem -InternalFieldName "AttrName8" -TermId $dstTerms.Id
                            $dstItem.Update()
                            Invoke-PnpQuery -Connection $dstCon
                        }
                    }
                    else {
                        Write-Host "      Setting AttrName8 term $($dstTerms.Name -join ',')"
                        $terms = @{}
                        foreach($term in $dstTerms) {
                            $terms[$term.Id.ToString()] = $term.Name
                        }
                        if (-Not $DryRun) {
                            Set-PnPTaxonomyFieldValue -Connection $dstCon -ListItem $dstItem -InternalFieldName "AttrName8" -Terms $terms
                            $dstItem.Update()
                            Invoke-PnpQuery -Connection $dstCon
                        }
                    }

                }
                catch {
                    $hadError = $true
                    $allData += [PSCustomObject]@{
                        ResultType = "Exception"
                        OLSite     = $SiteMapping.OLSite
                        OLList     = $SiteMapping.OLList
                        ItemID     = $srcItem.ID
                        Data       = $_
                    }
                    Write-Error "Error processing item $($SiteMapping.OLSite)/$($SiteMapping.OLList)/$($srcItem.ID): $_" -ErrorAction Continue
                }
            }

        }
        catch {
            $allData += [PSCustomObject]@{
                ResultType = "Exception"
                OLSite     = $SiteMapping.OLSite
                OLList     = $SiteMapping.OLList
                ItemID     = $null
                Data       = $_
            }
            Write-Error "Error processing $($SiteMapping.OLSite)/$($SiteMapping.OLList): $_" -ErrorAction Continue
        }
    }
}
catch {
    Write-Warning "Error: $_"
}

$allData | Export-Clixml -Path "$root\data\Clean-Topics-$($TimeString).xml" -Force
$excel = $allData | Export-Excel -Path "$root\data\Clean-Topics-$($TimeString).xlsx" -WorksheetName "Report" -TableName "Report" -BoldTopRow -AutoFilter -FreezeTopRowFirstColumn -ClearSheet -PassThru
Close-ExcelPackage $excel

# Stopping Transcript
(Get-Date).ToString("yyyyMMddHHmmssfff")
Stop-Transcript

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDTJmkxWh1a0CRl
# rP2sCNb9p6eFdz+VGVXh+j/HvaEpSqCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# dgNBzMUxgiEGMIIhAgIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIOJN85u7
# H5KcYYDgg7yRDx2PWPUoa8/4F4zqvnoHvlbZMA0GCSqGSIb3DQEBAQUABIICADY1
# ODEFJpdY2GZC/bZqtxUzlEjb/2Do22GDFg51BymLKMlJcQLAxSPZ33tIsSB7qVzh
# 5QlJKh+l3md01/t9/vXXRFuf7dN7YLgPI8DFzu1wFPSHi42qAjUUxeGShjpYz4mC
# f7q7gBJoZ7I1l+S+yLypuVg0DB6JlImC2imW4KsUQPqgwFWk0ipmvulekOCkkRpv
# 0QIgm2VZOAq24CmA7vceeicUFMatcPvYGKakd4BgMJBMYDBdZnX5Erxvn/8el4nF
# QcY/KXCrtxVgIzBxjDP893Tns0uj1CFR/2QooBZM4y26+hgMe1H1atAOR9qRGCwx
# IG4EHxsChaLt8Jx1/wI6LkTsw+CiIvPl11ENRNdriuRpgWSvZq0bCG25vbHbOfiz
# yyirHSEaoA1g2cnv4sSuw6EI44wEa0EovRi/chE6ZeeoC6Fp1FIKY3Iid9G26ZfB
# iTUhk6bgnrbPhDhUf6ia9YZDwriOpijtud5mIOaytTz0BIzHFHFccO5qmMnZRcvm
# QWQLrzAeN55O0jAKZq7IcgqdNPKl5KG7yEYHnHvoOIB5tK23MR9+ZD0vjqaSk9C3
# 8z0Bl6qGH/37m2ychXSrRtrKnC+eJjnZY1HjeWYufDPdb7cpf8dVTaAd2zzmIc38
# r62AB++Cv8UwaYwUU6QCinkHuyWw56O7fRMzNkyVoYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCCjB47vuuTRdUrWC9d/CtDR6Rdd8znvlqaW6cruSyxE8gIULBDA
# 5TcLpFVYp7L636detXttL9cYDzIwMjYwODI5MTUzMTIwWjADAgEBoF2kWzBZMQsw
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
# BDEyBDDD6IfYLUnmxjhxUicvA0/VUdiCcRInjs+XdmCjSAaGbMr+7NS/4yqyiNBB
# yi+DpKYwgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGAj6yatdLzY0iHI//3tiSukAuob40q4pv1YNGIoSkDwMQd
# E8ySCAoTa/cTcnO4/w7X1SVdAUCydSfg9tnEcziPhfEPgUEkkTUdWoswX/AikHaj
# IElVFoOsa+dBUBCUXJMB9C1pjQ/pLXLZCfVy/6anwjBMtV4YNC3R1LzAsXYMk6ol
# THZ+D7tyuyhVM/x1FDuwmkJ9mUCPlEMvN8wxG5kGbo/MYmA4tdsR882THemFqpsL
# S8EU8n0PIRRjzg6uyrtBVxdwqjsLSCX3anZDYtya/CfwEkehl0Q4bXoQi9OKfTKQ
# 4MTxJvf3PaMADmqjo9g2EEIGNJcNBivlgaOgrQJO+WlzNBS6XDgUUV0E9OHS8iCV
# gsw1ReWNyJLgd827FpfbHlxH76u4o8ON8glePv6Xmujjq/aMc1cLFLB8YSUCL54S
# CSCId2mUyhSV+2g7x/PGkbTsI5hJ/+fkBBGZYdQNUOlthqwL6GJWr8KY4eNTr/Pr
# JaujNtN0jGvW2OOEEw49
# SIG # End signature block
