#Requires -Version 2.0

[CmdletBinding()]
param(
    [string]$processOnlyOnsiteUrl = $null
)

# Starting Clean-Sites
Write-Host "Starting Clean-Sites"
$root = $PSScriptRoot

# Starting Transscript
Write-Host "Starting Transscript"
$TimeString = (Get-Date).ToString("yyyyMMddHHmmssfff")
if (-not (Test-Path "$root\logs")) {
    New-Item -Path "$root\logs" -ItemType Directory -Force | Out-Null
}
Start-Transcript -Path "$root\logs\Clean-Sites-$($TimeString).log" | Out-Null
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
$requiredFields = @(
    "ReqAttrName1",
    "ReqAttrName2",
    "ReqAttrName3",
    "ReqAttrName4"
)

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

Write-Host "Getting termstore mapping"
if (-not (Test-Path "$root\..\2Migrate\Mapping\TermStoreMapping.xlsx")) {
    Write-Error "Missing TermStoreMapping.xlsx file in $root\..\2Migrate\Mapping. Please create it first."
    Stop-Transcript
    exit
}
$TermStoreMappings = @{}
$TermStoreMappings."ReqAttrName2" = Import-Excel "$root\..\2Migrate\Mapping\TermStoreMapping.xlsx" -WorksheetName "ReqAttrName2" -ErrorAction Stop
$TermStoreMappings."ReqAttrName4" = Import-Excel "$root\..\2Migrate\Mapping\TermStoreMapping.xlsx" -WorksheetName "ReqAttrName4" -ErrorAction Stop
$TermStoreMappings."AttrName5" = Import-Excel "$root\..\2Migrate\Mapping\TermStoreMapping.xlsx" -WorksheetName "AttrName5" -ErrorAction Stop
$TermStoreMappings."ReqAttrName3" = Import-Excel "$root\..\2Migrate\Mapping\TermStoreMapping.xlsx" -WorksheetName "ReqAttrName3" -ErrorAction Stop
$TermStoreMappings."AttrName6" = Import-Excel "$root\..\2Migrate\Mapping\TermStoreMapping.xlsx" -WorksheetName "AttrName6" -ErrorAction Stop

# Processing
Write-Host "Processing"
$allData = @()

Write-Host "Login"
$adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl

Write-Host "Loading term sets"
if (-Not ($termData -and $termData.Keys.Count -gt 0)) {
    $termData = @{}
    $rootGroups = Get-PnPTermGroup -Connection $adminCon
    foreach ($rootGroup in $rootGroups) {
        $termData[$rootGroup.Name] = @{
            TermGroup = $rootGroup
            TermSets  = @{}
        }
        $termSets = Get-PnPTermSet -Connection $adminCon -TermGroup $rootGroup
        foreach ($termSet in $termSets) {
            #TODO Possibly recursion?
            $termData[$rootGroup.Name].TermSets[$termSet.Name] = @{
                TermSet = $termSet
                Terms   = Get-PnPTerm -Connection $adminCon -TermGroup $rootGroup -TermSet $termSet -IncludeChildTerms -IncludeDeprecated -Includes Labels, Terms
            }
        }
    }
}

function Find-Term() {
    param (
        $terms,
        $termName,
        $termGuid,
        $termLabel
    )
    foreach ($term in $terms) {
        if ($term.Name -eq $termName -or $term.Id -eq $termGuid -or ($termLabel -and $term.Labels | Where-Object { $_.Value -eq $termLabel })) {
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

function Get-Term() {
    param (
        $termGroupName,
        $termSetName,
        $termName,
        $termGuid,
        $termLabel
    )
    $termGroups = @()
    if (-Not [string]::IsNullOrEmpty($termGroupName)) {
        $termGroups += $termData[$termGroupName]
    }
    else {
        $termGroups += $termData.Values
    }
    $termSets = @()
    if (-Not [string]::IsNullOrEmpty($termSetName)) {
        $termSets += $termGroups | ForEach-Object { $_.TermSets[$termSetName] } | Where-Object { $_ -ne $null }
    }
    else {
        $termSets += $termGroups | ForEach-Object { $_.TermSets.Values } | Where-Object { $_ -ne $null }
    }
    foreach ($termSet in $termSets) {
        $term = Find-Term -terms $termSet.Terms -termName $termName -termGuid $termGuid -termLabel $termLabel
        if ($term) {
            return $term
        }
    }
    return $null
}

$SiteMappingsUnq = $SiteMappings | Select-Object -Property OLSite, OLList -Unique
try {
    foreach ($SiteMapping in $SiteMappingsUnq) {
        if ($SiteMapping.OLSite -eq "NOT RELEVANT") {
            continue
        }
        if (-Not [string]::IsNullOrWhiteSpace($processOnlyOnsiteUrl) -and $SiteMapping.OLSite.TrimEnd("/") -ne $processOnlyOnsiteUrl.TrimEnd("/")) {
            continue
        }
        try {

            # Cleaning map
            Write-Host "Cleaning $($SiteMapping.OPSite) to $($SiteMapping.OLSite)/$($SiteMapping.OLList)" -ForegroundColor Magenta
            $dstSiteUrl = $SiteMapping.OLSite
            $dstListName = $SiteMapping.OLList

            Write-Host "  Connecting site"
            $siteCon = LoginTo-PnP -Url $dstSiteUrl
            
            Write-Host "  Getting list"
            $dstList = Get-PnPList -Connection $siteCon -Identity $dstListName
            if (-Not $dstList) {
                throw "Can't find destination list"
            }

            # Checking unwanted properties
            Write-Host "  Checking unwanted properties"
            $foundProps = $false
            foreach ($CleanMapping in $CleanMappings) {
                $field = Get-PnPField -Connection $siteCon -List $dstList -Identity $CleanMapping.Old -ErrorAction SilentlyContinue
                if ($field) {
                    $foundProps = $true
                    break
                }
            }

            # Getting items
            $hadError = $false
            if ($foundProps) {

                Write-Host "  Getting fields"
                $fields = Get-PnPField -Connection $siteCon -List $dstList

                Write-Host "  Changing docuemnt type"
                $field = $fields | Where-Object { $_.InternalName -like "ReqAttrName4" }
                $ctx = Get-PnPContext -Connection $siteCon
                $taxField = [Microsoft.SharePoint.Client.Taxonomy.TaxonomyField]$field

                if ($taxField.TermSetId -ne $termData.Intranet.TermSets."Document Type".TermSet.Id) {
                    $taxField.TermSetId = $termData.Intranet.TermSets."Document Type".TermSet.Id
                    $taxField.SspId = $field.SspId
                    $taxField.Update()
                    $ctx.ExecuteQuery()
                }

                Write-Host "  Getting items"
                $items = [System.Collections.ArrayList]@()
                $pages = 0
                $null = Get-PnPListItem -Connection $siteCon -List $dstList -PageSize 500 -ScriptBlock {
                    Param($objs)
                    $retries = 10
                    do {
                        try {
                            $pages++
                            $objs.Context.ExecuteQuery()
                            foreach ($obj in $objs) {
                                $null = $items.Add($obj)
                            }
                            break
                        }
                        catch {
                            Write-Host "Page $pages retry $($retries): $($_.Exception.Message)"
                            Start-Sleep -Seconds 5
                            $retries--
                            if ($retries -lt 0) {
                                throw
                            }
                        }
                    } while ($true)
                }
                Write-Host "    $($items.Count) items"

                # Processing items
                Write-Host "  Processing items"
                foreach ($item in $items) {
                    try {
                        Write-Host "    Updating item $($SiteMapping.OLSite)/$($SiteMapping.OLList)/$($item.Id)"
                        $itemNeedsUpdate = $false
                        $transFields = $CleanMappings.New
                        $taxFields = $fields | Where-Object { $_.InternalName -in $transFields }
                        foreach ($taxField in $taxFields) {
                            $fieldNameNew = $taxField.InternalName
                            $termSetId = $taxField.TermSetId
                            $termSet = $termData.Values.TermSets.Values | Where-Object { $_.TermSet.Id -eq $termSetId }
                            if (-Not $termSet) {
                                Write-Warning "Can't find term set with id $termSetId for field $($fieldNameNew) in item $($SiteMapping.OLSite)/$($SiteMapping.OLList)/$($item.Id). Skipping field validation."
                                $hadError = $true
                                $allData += [PSCustomObject]@{
                                    ResultType = "TermSetNotFound"
                                    OLSite     = $SiteMapping.OLSite
                                    OLList     = $SiteMapping.OLList
                                    ItemID     = $item.Id
                                    Data       = $termSetId
                                }
                                continue
                            }

                            $oldFieldName = $CleanMappings | Where-Object { $_.New -eq $fieldNameNew } | Select-Object -ExpandProperty Old
                            $oldFieldValue = $item[$oldFieldName]
                            if ($oldFieldName -eq "AttrName8" -and @($oldFieldValue).Count -gt 1)
                            {
                                $oldFieldValue = @($oldFieldValue)[0]
                            }
                            $map = $TermStoreMappings[$fieldNameNew] | Where-Object { $_.TermIDAlt -in @($oldFieldValue.TermGuid) }
                            if (-Not $map) {
                                Write-Debug "Can't find mapping for term with id $($oldFieldValue.TermGuid) in field $($oldFieldName)/$($fieldNameNew) in item $($SiteMapping.OLSite)/$($SiteMapping.OLList)/$($item.Id). Skipping field validation."
                                $hadError = $true
                                $allData += [PSCustomObject]@{
                                    ResultType = "MissingMappingForTerm"
                                    OLSite     = $SiteMapping.OLSite
                                    OLList     = $SiteMapping.OLList
                                    ItemID     = $item.Id
                                    Data       = $oldFieldValue.TermGuid
                                }
                                continue
                            }
                            $termGuidsNew = @()
                            $termGroupName = $null
                            $termSetName = $null
                            foreach ($m in $map) {
                                $termGuidsNew += $m.TermIDNeu
                                $termGroupName = $m.TermGroupNeu
                                $termSetName = $m.TermSetNeu
                                $termNew = Get-Term -termGroupName $termGroupName -termSetName $termSetName -termGuid $m.TermIDNeu
                                if (-Not $termNew) {
                                    $termNew = Get-Term -termGuid $m.TermIDNeu
                                }
                                if (-Not $termNew) {
                                    Write-Warning "Can't find mapped term with id $($m.TermIDNeu) in field $($oldFieldName)/$($fieldNameNew) in item $($SiteMapping.OLSite)/$($SiteMapping.OLList)/$($item.Id). Skipping field validation."
                                    $hadError = $true
                                    $allData += [PSCustomObject]@{
                                        ResultType = "MissingMappingForTerm"
                                        OLSite     = $SiteMapping.OLSite
                                        OLList     = $SiteMapping.OLList
                                        ItemID     = $item.Id
                                        Data       = $m.TermIDNeu
                                    }
                                    $termGuidsNew = $null
                                    break
                                }
                            }
                            if ($null -eq $termGuidsNew) {
                                continue
                            }

                            $hasMissing = $true
                            # $fieldValuesNew = @($item[$fieldNameNew].TermGuid)
                            # $fieldValuesOrig = $fieldValuesNew
                            # $hasMissing = $false
                            # foreach ($termGuidNew in $termGuidsNew) {
                            #     if ($termGuidNew -notin $fieldValuesNew) {
                            #         $hasMissing = $true
                            #         #$fieldValuesNew += $termGuidNew
                            #     }
                            # }
                            if ($hasMissing) {
                                $allData += [PSCustomObject]@{
                                    ResultType = "ValueChanged"
                                    OLSite     = $SiteMapping.OLSite
                                    OLList     = $SiteMapping.OLList
                                    ItemID     = $item.Id
                                    Data       = "$($oldFieldName)/$($fieldValuesOrig -join ',') -> $($fieldNameNew)/$($fieldValuesNew -join ',')"
                                }
                                $termGuidsNew = $termGuidsNew | Where-Object { $_ -ne $null }
                                if ($termGuidsNew.Count -eq 0) {
                                    Write-Host "      Setting $fieldNameNew to NULL"
                                    if (-Not $DryRun) {
                                        #TODO Set-PnPTaxonomyFieldValue -Connection $siteCon -ListItem $item -InternalFieldName $fieldNameNew -TermId $null
                                    }
                                }
                                elseif ($termGuidsNew.Count -eq 1) {
                                    Write-Host "      Setting $fieldNameNew to $($termGuidsNew)"
                                    if (-Not $DryRun) {
                                        Set-PnPTaxonomyFieldValue -Connection $siteCon -ListItem $item -InternalFieldName $fieldNameNew -TermId $termGuidsNew
                                    }
                                }
                                else {
                                    if ($fieldNameNew -eq "ReqAttrName2")
                                    {
                                        $a = 1
                                    }
                                    $terms = @{}
                                    foreach ($fieldValueNew in $termGuidsNew) {
                                        if (-Not $fieldValueNew) { continue }
                                        $termNew = Get-Term -termGroupName $termGroupName -termSetName $termSetName -termGuid $fieldValueNew
                                        if (-Not $termNew) {
                                            $termNew = Get-Term -termGuid $fieldValueNew
                                        }
                                        $terms[$fieldValueNew] = $termNew.Name
                                    }
                                    Write-Host "      Setting $fieldNameNew to $($terms.Values -join '|')"
                                    if (-Not $DryRun) {
                                        Set-PnPTaxonomyFieldValue -Connection $siteCon -ListItem $item -InternalFieldName $fieldNameNew -Terms $terms
                                    }
                                }
                                $itemNeedsUpdate = $true
                            }
                        }

                        if ($itemNeedsUpdate) {
                            $allData += [PSCustomObject]@{
                                ResultType = "ItemUpdated"
                                OLSite     = $SiteMapping.OLSite
                                OLList     = $SiteMapping.OLList
                                ItemID     = $item.Id
                                Data       = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss:fff")
                            }
                            Write-Host "    Updating"
                            if (-Not $DryRun) {
                                $item.Update()
                                Invoke-PnpQuery -Connection $siteCon
                            }
                        }

                    }
                    catch {
                        $hadError = $true
                        $allData += [PSCustomObject]@{
                            ResultType = "Exception"
                            OLSite     = $SiteMapping.OLSite
                            OLList     = $SiteMapping.OLList
                            ItemID     = $item.Id
                            Data       = $_
                        }
                        Write-Error "Error processing item $($SiteMapping.OLSite)/$($SiteMapping.OLList)/$($item.Id): $_" -ErrorAction Continue
                    }
                }
            }

            # Finishing map
            if (-Not $hadError) {

                # Processing unwanted properties
                Write-Host "  Processing unwanted properties"
                foreach ($CleanMapping in $CleanMappings) {
                    $field = Get-PnPField -Connection $siteCon -List $dstList -Identity $CleanMapping.Old -ErrorAction SilentlyContinue
                    if ($field) {
                        $allData += [PSCustomObject]@{
                            ResultType = "FieldRemoved"
                            OLSite     = $SiteMapping.OLSite
                            OLList     = $SiteMapping.OLList
                            ItemID     = $null
                            Data       = $CleanMapping.Old
                        }
                        Write-Host "    Removing field $($CleanMapping.Old)"
                        if (-Not $DryRun) {
                            Remove-PnPField -Connection $siteCon -Identity $CleanMapping.Old -List $dstList -Force -Connection $siteCon
                        }
                    }
                }

                # Processing mandatory fields
                Write-Host "  Processing mandatory fields"
                foreach ($requiredField in $requiredFields) {
                    $field = Get-PnPField -Connection $siteCon -List $dstList -Identity $requiredField -ErrorAction SilentlyContinue
                    if (-Not $field) {
                        Write-Warning "    Field $requiredField not found"
                        continue
                    }
                    if ($field.Required) {
                        Write-Host "    Field $requiredField is already required"
                    }
                    else {
                        Write-Host "    Setting field $requiredField as required"
                        $allData += [PSCustomObject]@{
                            ResultType = "FieldSetRequired"
                            OLSite     = $SiteMapping.OLSite
                            OLList     = $SiteMapping.OLList
                            ItemID     = $null
                            Data       = $requiredField
                        }
                        if (-Not $DryRun) {
                            Set-PnPField  -Connection $siteCon -Identity $field -List $dstList -Required $true
                        }
                    }
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

$allData | Export-Clixml -Path "$root\data\Clean-$($TimeString).xml" -Force
$excel = $allData | Export-Excel -Path "$root\data\Clean-$($TimeString).xlsx" -WorksheetName "Report" -TableName "Report" -BoldTopRow -AutoFilter -FreezeTopRowFirstColumn -ClearSheet -PassThru
Close-ExcelPackage $excel

# Stopping Transcript
(Get-Date).ToString("yyyyMMddHHmmssfff")
Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAxYiW0E+m6F/D5
# B3FX+5t4Y97dBcZbKqz9BsTKsJ/v0qCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBCyMDDEfYxdPwEK
# GyDY0XAdUwtp7av8Z1qot5SbwjqkMA0GCSqGSIb3DQEBAQUABIICADCg2d7XkYv/
# ouC22GSzS0BWPoEBsX7YZvgEjZC1/goSngEkldhUSKLy5PpvEG3Ka3CF8fQTs0gD
# W0OHjODtVLM+lQXZBS+5/wq+MtimCt/CosXFrxF0anMi85pcNZQofXwdsxV3sQFE
# wbSznGvIXANX6pV0Xjb8ZH280xTi9VJExc071TzdtaGj+c//jZ3BQ+U9Ix1ytsgx
# /voE5AtWvp2DEOyjvwG0dtmuU0sw1uArdIjK7+xoKDn9ON7WV5WmQitUIN0viOmv
# IcuVYG5pAZNRB5DgQcmvQfJbxu8OXvowTAAhuJJdcE6FceJhjPc5noHWDJOrYOfE
# ijIGFfwfdAz3RcRuQ+JQICFzWlA3rps4yNxWRXmPxUpC8l1uWW+T5KirHLX0+Xo6
# FODE2J9AjyLAg7UGuNhH63A4e0KAPi0hSwMqP9Rr1RsP7XUA+dTy2NofcY187qOU
# mMZc1DR8T/KyGTHmGL36muHi4F7HLLKBzpF58ypKH6WHWlzd+AtfsX1mLIS8vSz0
# rAC0xP6Ozfk8ukIa1Ti50bNSAiHk/KYVAdGaNM6LGq8LoZbX3NZhpcp4TOS3IoZG
# sxm51n6+9yDE2QYefaJUVclBYHEec9mncywdO/rQFan5k64Q3cBYNvo+QNDhlAD/
# rc/10HWEeUXhRzlPIvBle4/nFh4vF4cZoYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCD6Y5K43hlf53UhKF4L8iOeZsz95aR+wR91TQ+V2RjmEgIUICeSTjPu5UqW
# 9VAun/WZAxnAQK4YDzIwMjYwMjI0MTg0NTAzWjADAgEBoFikVjBUMQswCQYDVQQG
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
# IDtLcojOLyLQIRAO1Vr7JnJ/+KJv6tvIo9W7lHCspu8GMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAb4I202Wr2KzU
# y7izyaI6xdbcURBAcMFKRwSHxv8Onkzkomawj+gG9SvYQumYTKVsvONEV5uC4kaw
# LvMKYq5eVPeflc7yNQ1k9F+kBo8oDBvsyG+Is6rICW6pKrEloAspG7Bx9Z5MCHWO
# hYTIlgYWCShhwDYQl6L5Y9NbgxCgMX6TaoVwoMla3bn15M/YCR/V8wQG4lCwv/2f
# JOJk4t+bamHyAWOaaiYcOS+BxjesLCmGd/Qo8JaKmvyfiKqzJz2Bd0tPXr9tjvTX
# P23XccUvJC0GyfnZWUaex52R5BP/xbldGZc4fUowPMfJMY5lnA6BpWp9fXhXQ6/x
# i6AGAF70DLNXxX0zcDu/i3822bay7m4p8DnSHlIyteNY20YxpJnUress7GLVz5mF
# B1YeMdP3ksXX8Xb4MMSmRxhE2qFGOoThPb/Arz90Y9xD+cxsf/BR4IrAEOTMUU/L
# KWA/ukkxYLnnqc7a8nRCed1UwlLrj70qXZrbtwevKoyDxVDdwIQJ
# SIG # End signature block
