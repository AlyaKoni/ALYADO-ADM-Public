#Requires -Version 2.0

[CmdletBinding()]
param(
    [string]$processOnlyOnsiteUrl = $null
)

# Starting Clean-Topic
Write-Host "Starting Clean-Topic"
$root = $PSScriptRoot

# Starting Transscript
Write-Host "Starting Transscript"
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
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB5HKWCgQaoGn3y
# t29H85hEhJ8RX7VbtGDOotHEyX253aCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIPAefsNwdlc7XMwc
# lmathv8LzsQqxdRed4kdLtlyxeUMMA0GCSqGSIb3DQEBAQUABIICAJ7EsJepbiyp
# NkiQJLSfltp4xz+eYSk4FFlaocDCbeADYzYK6VvFH9LlzcDG6+09doR8M5OPQgcF
# paUY+iRfqouFOdZnasmuSNN4Vf1/qCIrccMybInWlLYLfTtu2uh3OVWadu5fEUjx
# dVhG6HPg5am3YvdNiOWs1FODYCvMGFpt1SPontlgmIUWXsRrS0E8oklNOduXYys2
# 2IXoPJKAvVOfja594Egjuv6VO+eHVxH5Bh7ceMYljsoSGwVTJOYWJvQmxNaFTECf
# uczW375vAVmxzlqsGckCVkakl8sJ++vx0Std210LFuXZWzlung9FruH8y6Ts++LR
# Dr60Y/06Vny8VNpnt1IgLa24GFyPDnGoFxvfeKL+RavPUNRlSEde9kRDwSDEesHx
# 8TiHpBKzDU1nz/q7sueKwfr5HEmE3vt0P6t9iTG6aJrQUkUVMbRG9aMbgrs0oT2c
# s29UKrtx8fgzYxw741x5FwKRByjXpFlLJoS5dgj5KUk8D8rtdxeoRud2WR78r+u7
# iKdHtmcuXEy7jPNsGBcDtsKb6rN89JpdFx2GZhOzN4prFOqPLW6+JF1jd5bCLOI1
# p1j0Zy06FhZy53Qoj2vI5WTTIjropwdotOalEG7MDZzyfLgfO5A3IkQjBTOdgW8Q
# xo+ltwloWoRuppcHsKLc4Rxl4z2ZIc9RoYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCD0xbx48onnJXDxHK3TEFt5fVRRGQNEZj6CQh1vj5d82wIUIR6EsNqofZTa
# Wmdz+EcKXLq6TacYDzIwMjYwMzAzMTM1NDIyWjADAgEBoFikVjBUMQswCQYDVQQG
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
# IOZ1kvQ9U3cNI0SH0qgmbgAZzkBE8NSlaV8/QBWy23ALMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAmlfR/JxBAfpE
# rsxd4b8YLAG9seJ/svysC0aAw2AMGtF7MNlZu7/5Frzm98h6wp+qJFwKNYQBMBtO
# sl0MIDhsvZiPHh+Rq1+AmBFAziMGf1SUb8LDuan6ZGCc56KGvCqRmNTqQxAzy6h5
# bbfL9kHiqTHowbr7XX9t+ubMr5RhM00PGCmmVV5n0RxrEGB379MV34sAN4nwfqPh
# cZCYTgjmaJKfzps0h7x4KzlItpsAJvcssYbuXUMUvOutqKxp7mMfEmy69RMhQnts
# zbqwvWObtgg7A1sm9z34sdy2aS+jq7Ge/hl8+LgeqoVKG3Sz71JLhfXrlbyTUAkC
# zVyHEX6gQvYKHywfwG56gKPkFGY+4Xp88DtoWjjT1XvPpZQ23MHU/reUN0KOO1R5
# KAmvZ9W65rzhlhvXc+GoNK8Pq7qrgwpp9XdLNJDteQyTOR8Pv2lTtPSWWoHgNnqE
# Tz+cM2aYcJi1/Yo3QjAWrOk1rOQZq0dJDibOxAo6OCaY2Q32ylMW
# SIG # End signature block
