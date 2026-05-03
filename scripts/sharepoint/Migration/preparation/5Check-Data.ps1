#Requires -Version 2.0

# Starting Check-Data
Write-Host "Starting Check-Data"
$root = $PSScriptRoot

# Starting Transscript
Write-Host "Starting Transscript"
$TimeString = (Get-Date).ToString("yyyyMMddHHmmssfff")
if (-not (Test-Path "$root\logs"))
{
    New-Item -Path "$root\logs" -ItemType Directory -Force | Out-Null
}
Start-Transcript -Path "$root\logs\Check-Data-$($TimeString).log" | Out-Null
(Get-Date).ToString("yyyyMMddHHmmssfff")

# Configurations
. "$root\..\..\SharedSNAPIN.ps1"
if (-not (Test-Path "$root\data"))
{
    New-Item -Path "$root\data" -ItemType Directory -Force | Out-Null
}

# Getting exported data
Write-Host "Getting exported data"
if (-not (Test-Path "$root\data\Sites.xml"))
{
    Write-Error "Missing Sites.xml file in $root\data. Please run 3Get-Sites first."
    Stop-Transcript
    exit
}
if (-not (Test-Path "$root\data\Taxonomy.xml"))
{
    Write-Error "Missing Taxonomy.xml file in $root\data. Please run 2Get-Taxonomy first."
    Stop-Transcript
    exit
}
if (-not (Test-Path "$root\data\Profiles.xml"))
{
    Write-Error "Missing Profiles.xml file in $root\data. Please run 1Get-Profiles first."
    Stop-Transcript
    exit
}
if (-not (Test-Path "$root\data\Peoples.xml"))
{
    Write-Error "Missing Peoples.xml file in $root\data. Please run 4Get-Peoples first."
    Stop-Transcript
    exit
}
$expTaxonomy = [XML](Get-Content -Path "$root\data\Taxonomy.xml" -Encoding utf8BOM -Raw)
$expSites = Import-Clixml -Path "$root\data\Sites.xml"
$expProfiles = Import-Clixml -Path "$root\data\Profiles.xml"
$expPeoples = Import-Clixml -Path "$root\data\Peoples.xml"

# Processing
Write-Host "Processing"
$allData = [System.Collections.ArrayList]@()
foreach ($webAppKey in $expSites.Keys)
{
    try
    {
        Write-Host "WebApplication: $($webAppKey)"
        $webApp = Get-SPWebApplication -Identity $expSites."$($webAppKey)".Id
        if (-not $webApp)
        {
            $allData.Add([PSCustomObject]@{
                ProblemType = "NotFound#Web"
                WebApp      = $webAppKey
                Site        = $null
                Web         = $null
                List        = $null
                Item        = $null
                Field       = $null
                Value       = $expSites."$($webAppKey)".Id
            })
            Write-Warning "Web Application $($webAppKey) not found in the farm."
            continue
        }
    
        foreach ($siteKey in $expSites."$($webAppKey)".Sites.Keys)
        {
            try
            {
                Write-Host "Site: $($siteKey)"
                $site = Get-SPSite -Identity $expSites."$($webAppKey)".Sites."$($siteKey)".ID
                if (-not $site)
                {
                    $allData.Add([PSCustomObject]@{
                        ProblemType = "NotFound#Site"
                        WebApp      = $webAppKey
                        Site        = $siteKey
                        Web         = $null
                        List        = $null
                        Item        = $null
                        Field       = $null
                        Value       = $expSites."$($webAppKey)".Sites."$($siteKey)".ID
                    })
                    Write-Warning "Site Collection $($siteKey) not found in Web Application $($webAppKey)."
                    continue
                }
        
                foreach ($webKey in $expSites."$($webAppKey)".Sites."$($siteKey)".Webs.Keys)
                {
                    try
                    {
                        Write-Host "Web: $($webKey)"
                        $web = Get-SPWeb -Identity $expSites."$($webAppKey)".Sites."$($siteKey)".Webs."$($webKey)".ID
                        if (-not $web)
                        {
                            $allData.Add([PSCustomObject]@{
                                ProblemType = "NotFound#Web"
                                WebApp      = $webAppKey
                                Site        = $siteKey
                                Web         = $webKey
                                List        = $null
                                Item        = $null
                                Field       = $null
                                Value       = $expSites."$($webAppKey)".Sites."$($siteKey)".Webs."$($webKey)".ID
                            })
                            Write-Warning "Web $($webKey) not found in Site Collection $($siteKey) in Web Application $($webAppKey)."
                            continue
                        }
            
                        foreach ($listKey in $expSites."$($webAppKey)".Sites."$($siteKey)".Webs."$($webKey)".Lists.Keys)
                        {
                            try
                            {
                                Write-Host "List: $($listKey)"
                                $list = $web.Lists[$expSites."$($webAppKey)".Sites."$($siteKey)".Webs."$($webKey)".Lists."$($listKey)".ID]
                                if (-not $list)
                                {
                                    $allData.Add([PSCustomObject]@{
                                        ProblemType = "NotFound#List"
                                        WebApp      = $webAppKey
                                        Site        = $siteKey
                                        Web         = $webKey
                                        List        = $listKey
                                        Item        = $null
                                        Field       = $null
                                        Value       = $expSites."$($webAppKey)".Sites."$($siteKey)".Webs."$($webKey)".Lists."$($listKey)".ID
                                    })
                                    Write-Warning "List $($listKey) not found in Web $($webKey) in Site Collection $($siteKey) in Web Application $($webAppKey)."
                                    continue
                                }
                
                                $fields = $expSites."$($webAppKey)".Sites."$($siteKey)".Webs."$($webKey)".Lists."$($listKey)".Fields
                                if (-not $fields -or $fields.Count -eq 0)
                                {
                                    Write-Warning "Missing fields in list $($listKey) in Web $($webKey) in Site Collection $($siteKey) in Web Application $($webAppKey)."
                                    continue
                                }
                
                                $uniqueFields = $fields | Where-Object { $_.EnforceUniqueValues -eq $true }
                                $requiredFields = $fields | Where-Object { $_.Required -eq $true }
                                $taxFields = $fields | Where-Object { $_.TypeAsString -eq "Managed Metadata" -or $_.TypeAsString -eq "TaxonomyFieldType" -or $_.TypeAsString -eq "TaxonomyFieldTypeMulti" }
                                $peopleFields = $fields | Where-Object { $_.TypeAsString -eq "User" -or $_.TypeAsString -eq "UserMulti" }
                                $choiceFields = $fields | Where-Object { $_.TypeAsString -eq "Choice" -or $_.TypeAsString -eq "MultiChoice" -and $_.FillInChoices -eq $false }
                                $lookupFields = $fields | Where-Object { $_.TypeAsString -eq "Lookup" -or $_.TypeAsString -eq "LookupMulti" }
                
                                Write-Host "Checking data integrity..."
                                $checkedOutFiles = $list.GetCheckedOutFiles()
                                $list.Context.Load($checkedOutFiles)
                                $list.Context.ExecuteQuery()
                                foreach($file in $checkedOutFiles)
                                {
                                    $allData.Add([PSCustomObject]@{
                                            ProblemType = "InvalidCheckedOutState"
                                            WebApp      = $webAppKey
                                            Site        = $siteKey
                                            Web         = $webKey
                                            List        = $listKey
                                            Item        = $item.ID
                                            Field       = $file.LeafName
                                            Value       = $file.CheckedOutByUser.Email
                                        })
                                    Write-Warning "User '$($file.CheckedOutByUser.Email)' has checked out file '$($file.LeafName)' from item '$($item.ID)' in list '$($listKey)' in Web '$($webKey)' in Site Collection '$($siteKey)' in Web Application '$($webAppKey)'."
                                }
                                $uniqueValues = [System.Collections.ArrayList]@()
                                foreach ($item in $list.Items)
                                {
                                    foreach ($field in $taxFields)
                                    {
                                        try
                                        {
                                            $value = $item[$field.InternalName]
                                            if ($value)
                                            {
                                                $termIds = @()
                                                if ($field.TypeAsString -eq "TaxonomyFieldTypeMulti" -or $field.TypeAsString -eq "Managed Metadata")
                                                {
                                                    $termEntries = $value -split ";#"
                                                    for ($i = 0; $i -lt $termEntries.Count; $i += 2)
                                                    {
                                                        $termIds += $termEntries[$i]
                                                    }
                                                }
                                                else
                                                {
                                                    $termIds += $value
                                                }
                                                foreach ($termId in $termIds)
                                                {
                                                    $term = $expTaxonomy.SelectSingleNode("//Term[@Id='$termId']")
                                                    if (-not $term)
                                                    {
                                                        $allData.Add([PSCustomObject]@{
                                                                ProblemType = "InvalidTaxonomyFieldValue"
                                                                WebApp      = $webAppKey
                                                                Site        = $siteKey
                                                                Web         = $webKey
                                                                List        = $listKey
                                                                Item        = $item.ID
                                                                Field       = $field.InternalName
                                                                Value       = $termId
                                                            })
                                                        Write-Warning "Term ID '$termId' not found in taxonomy found in taxonomy field '$($field.InternalName)' in item '$($item.ID)' in list '$($listKey)' in Web '$($webKey)' in Site Collection '$($siteKey)' in Web Application '$($webAppKey)'."
                                                    }
                                                }
                                            }
                                        }
                                        catch
                                        {
                                            $allData.Add([PSCustomObject]@{
                                                    ProblemType = "InvalidTaxonomyFieldValue#Exception"
                                                    WebApp      = $webAppKey
                                                    Site        = $siteKey
                                                    Web         = $webKey
                                                    List        = $listKey
                                                    Item        = $item.ID
                                                    Field       = $field.InternalName
                                                    Value       = $_.Exception.Message
                                                })
                                            Write-Warning "Exception '$($_.Exception.Message)' found in taxonomy field '$($field.InternalName)' in item '$($item.ID)' in list '$($listKey)' in Web '$($webKey)' in Site Collection '$($siteKey)' in Web Application '$($webAppKey)'."
                                        }
                                    }
                                    foreach ($field in $lookupFields)
                                    {
                                        # TODO implement lookup value checks?
                                    }
                                    foreach ($field in $requiredFields)
                                    {
                                        try
                                        {
                                            $value = $item[$field.InternalName]
                                            if (-not $value)
                                            {
                                                $allData.Add([PSCustomObject]@{
                                                        ProblemType = "MissingRequiredFieldValue"
                                                        WebApp      = $webAppKey
                                                        Site        = $siteKey
                                                        Web         = $webKey
                                                        List        = $listKey
                                                        Item        = $item.ID
                                                        Field       = $field.InternalName
                                                    })
                                                Write-Warning "Missing value in required field '$($field.InternalName)' in item '$($item.ID)' in list '$($listKey)' in Web '$($webKey)' in Site Collection '$($siteKey)' in Web Application '$($webAppKey)'."
                                            }
                    
                                        }
                                        catch
                                        {
                                            $allData.Add([PSCustomObject]@{
                                                    ProblemType = "MissingRequiredFieldValue#Exception"
                                                    WebApp      = $webAppKey
                                                    Site        = $siteKey
                                                    Web         = $webKey
                                                    List        = $listKey
                                                    Item        = $item.ID
                                                    Field       = $field.InternalName
                                                    Value       = $_.Exception.Message
                                                })
                                            Write-Warning "Exception '$($_.Exception.Message)' found in required field '$($field.InternalName)' in item '$($item.ID)' in list '$($listKey)' in Web '$($webKey)' in Site Collection '$($siteKey)' in Web Application '$($webAppKey)'."
                                        }
                                    }
                                    foreach ($field in $uniqueFields)
                                    {
                                        try
                                        {
                                            $value = $item[$field.InternalName]
                                            if ($value -and -not $uniqueValues.Contains($value))
                                            {
                                                $uniqueValues.Add($value) | Out-Null
                                            }
                                            elseif ($value -and $uniqueValues.Contains($value))
                                            {
                                                $allData.Add([PSCustomObject]@{
                                                        ProblemType = "DuplicateUniqueFieldValue"
                                                        WebApp      = $webAppKey
                                                        Site        = $siteKey
                                                        Web         = $webKey
                                                        List        = $listKey
                                                        Item        = $item.ID
                                                        Field       = $field.InternalName
                                                        Value       = $value
                                                    })
                                                Write-Warning "Duplicate value '$value' found in unique field '$($field.InternalName)' in item '$($item.ID)' in list '$($listKey)' in Web '$($webKey)' in Site Collection '$($siteKey)' in Web Application '$($webAppKey)'."
                                            }
                                        }
                                        catch
                                        {
                                            $allData.Add([PSCustomObject]@{
                                                    ProblemType = "DuplicateUniqueFieldValue#Exception"
                                                    WebApp      = $webAppKey
                                                    Site        = $siteKey
                                                    Web         = $webKey
                                                    List        = $listKey
                                                    Item        = $item.ID
                                                    Field       = $field.InternalName
                                                    Value       = $_.Exception.Message
                                                })
                                            Write-Warning "Exception '$($_.Exception.Message)' found in unique field '$($field.InternalName)' in item '$($item.ID)' in list '$($listKey)' in Web '$($webKey)' in Site Collection '$($siteKey)' in Web Application '$($webAppKey)'."
                                        }
                                    }
                                    foreach ($field in $choiceFields)
                                    {
                                        try
                                        {
                                            $value = $item[$field.InternalName]
                                            if ($value)
                                            {
                                                $validChoices = $field.Choices
                                                if ($field.TypeAsString -eq "MultiChoice")
                                                {
                                                    $itemChoices = $value -split ";#"
                                                    foreach ($choice in $itemChoices)
                                                    {
                                                        if (-not $validChoices.Contains($choice))
                                                        {
                                                            $allData.Add([PSCustomObject]@{
                                                                    ProblemType = "InvalidChoiceFieldValue"
                                                                    WebApp      = $webAppKey
                                                                    Site        = $siteKey
                                                                    Web         = $webKey
                                                                    List        = $listKey
                                                                    Item        = $item.ID
                                                                    Field       = $field.InternalName
                                                                    Value       = $choice
                                                                })
                                                            Write-Warning "Invalid choice value '$choice' found in choice field '$($field.InternalName)' in item '$($item.ID)' in list '$($listKey)' in Web '$($webKey)' in Site Collection '$($siteKey)' in Web Application '$($webAppKey)'."
                                                        }
                                                    }
                                                }
                                                else
                                                {
                                                    if (-not $validChoices.Contains($value))
                                                    {
                                                        $allData.Add([PSCustomObject]@{
                                                                ProblemType = "InvalidChoiceFieldValue"
                                                                WebApp      = $webAppKey
                                                                Site        = $siteKey
                                                                Web         = $webKey
                                                                List        = $listKey
                                                                Item        = $item.ID
                                                                Field       = $field.InternalName
                                                                Value       = $value
                                                            })
                                                        Write-Warning "Invalid choice value '$value' found in choice field '$($field.InternalName)' in item '$($item.ID)' in list '$($listKey)' in Web '$($webKey)' in Site Collection '$($siteKey)' in Web Application '$($webAppKey)'."
                                                    }
                                                }
                                            }
                                        }
                                        catch
                                        {
                                            $allData.Add([PSCustomObject]@{
                                                    ProblemType = "InvalidChoiceFieldValue#Exception"
                                                    WebApp      = $webAppKey
                                                    Site        = $siteKey
                                                    Web         = $webKey
                                                    List        = $listKey
                                                    Item        = $item.ID
                                                    Field       = $field.InternalName
                                                    Value       = $_.Exception.Message
                                                })
                                            Write-Warning "Exception '$($_.Exception.Message)' found in choice field '$($field.InternalName)' in item '$($item.ID)' in list '$($listKey)' in Web '$($webKey)' in Site Collection '$($siteKey)' in Web Application '$($webAppKey)'."
                    
                                        }
                                    }
                                    foreach ($peopleField in $peopleFields)
                                    {
                                        try
                                        {
                                            $value = $item[$peopleField.InternalName]
                                            if ($value)
                                            {
                                                $userIds = @()
                                                if ($peopleField.TypeAsString -eq "UserMulti")
                                                {
                                                    $userEntries = $value -split ";#"
                                                    for ($i = 0; $i -lt $userEntries.Count; $i += 2)
                                                    {
                                                        $userIds += $userEntries[$i]
                                                    }
                                                }
                                                else
                                                {
                                                    $userIds += $value
                                                }
                                                $user = $null
                                                foreach ($userId in $userIds)
                                                {
                                                    $user = $site.RootWeb.SiteUsers | Where-Object { $_.ID -eq $userId }
                                                    if (-not $user)
                                                    {
                                                        $allData.Add([PSCustomObject]@{
                                                                ProblemType = "InvalidPeopleFieldValue#MissingInList"
                                                                WebApp      = $webAppKey
                                                                Site        = $siteKey
                                                                Web         = $webKey
                                                                List        = $listKey
                                                                Item        = $item.ID
                                                                Field       = $peopleField.InternalName
                                                                Value       = $userId
                                                            })
                                                        Write-Warning "User ID '$userId' missing in user list found in people field '$($peopleField.InternalName)' in item '$($item.ID)' in list '$($listKey)' in Web '$($webKey)' in Site Collection '$($siteKey)' in Web Application '$($webAppKey)'."
                                                    }
                                                    if ($null -ne $user)
                                                    {
                                                        $expProfile = $expProfiles | Where-Object { $_.AccountName -eq $user.LoginName -or $_.WorkEmail -eq $user.EMail } # TODO additional checks?
                                                        if (-not $expProfile)
                                                        {
                                                            $allData.Add([PSCustomObject]@{
                                                                    ProblemType = "InvalidPeopleFieldValue#MissingInProfiles"
                                                                    WebApp      = $webAppKey
                                                                    Site        = $siteKey
                                                                    Web         = $webKey
                                                                    List        = $listKey
                                                                    Item        = $item.ID
                                                                    Field       = $peopleField.InternalName
                                                                    Value       = $user.LoginName
                                                                })
                                                            Write-Warning "User '$($user.LoginName)' missing in user profiles found in people field '$($peopleField.InternalName)' in item '$($item.ID)' in list '$($listKey)' in Web '$($webKey)' in Site Collection '$($siteKey)' in Web Application '$($webAppKey)'."
                                                        }
                                                    }
                                                    if ($null -ne $expProfile -or $null -ne $user)
                                                    {
                                                        if ($null -ne $expProfile)
                                                        {
                                                            $accountName = $expProfile.AccountName
                                                        }
                                                        else
                                                        {
                                                            $accountName = $user.LoginName
                                                        }
                                                        if ($accountName.Contains("\"))
                                                        {
                                                            $accountName = $accountName.Split("\")[1]
                                                        }
                                                        $accountName = "$accountName@customer.root"

                                                        $expPerson = $expPeoples | Where-Object { $_.AccountName -eq $accountName -or $_.WorkEmail -eq $accountName -or $_.UserName -eq $accountName }
                                                        if (-not $expPerson)
                                                        {
                                                            if ($null -ne $expProfile)
                                                            {
                                                                if ([string]::IsNullOrEmpty($expProfile.WorkEmail) -eq $false)
                                                                {
                                                                    $expPerson = $expPeoples | Where-Object { $_.WorkEmail -eq $expProfile.WorkEmail -or $_.AccountName -eq $expProfile.WorkEmail }
                                                                }
                                                            }
                                                            else
                                                            {
                                                                if ([string]::IsNullOrEmpty($user.Email) -eq $false)
                                                                {
                                                                    $expPerson = $expPeoples | Where-Object { $_.WorkEmail -eq $user.Email -or $_.AccountName -eq $user.Email }
                                                                }
                                                            }
                                                            # TOTO try other variations?
                                                        }
                                                        if (-not $expPerson)
                                                        {
                                                            $allData.Add([PSCustomObject]@{
                                                                    ProblemType = "InvalidPeopleFieldValue#MissingInEntraID"
                                                                    WebApp      = $webAppKey
                                                                    Site        = $siteKey
                                                                    Web         = $webKey
                                                                    List        = $listKey
                                                                    Item        = $item.ID
                                                                    Field       = $peopleField.InternalName
                                                                    Value       = $accountName
                                                                })
                                                            Write-Warning "User '$($accountName)' missing in Entra ID found in people field '$($peopleField.InternalName)' in item '$($item.ID)' in list '$($listKey)' in Web '$($webKey)' in Site Collection '$($siteKey)' in Web Application '$($webAppKey)'."
                                                        }
                                                    }
                                                }
                                            }
                    
                                        }
                                        catch
                                        {
                                            $allData.Add([PSCustomObject]@{
                                                    ProblemType = "InvalidPeopleFieldValue#Exception"
                                                    WebApp      = $webAppKey
                                                    Site        = $siteKey
                                                    Web         = $webKey
                                                    List        = $listKey
                                                    Item        = $item.ID
                                                    Field       = $peopleField.InternalName
                                                    Value       = $_.Exception.Message
                                                })
                                            Write-Warning "Exception '$($_.Exception.Message)' found in people field '$($peopleField.InternalName)' in item '$($item.ID)' in list '$($listKey)' in Web '$($webKey)' in Site Collection '$($siteKey)' in Web Application '$($webAppKey)'."
                                        }
                                    }
                                }
                
                            }
                            catch
                            {
                                $allData.Add([PSCustomObject]@{
                                        ProblemType = "List#Exception"
                                        WebApp      = $webAppKey
                                        Site        = $siteKey
                                        Web         = $webKey
                                        List        = $listKey
                                        Item        = $null
                                        Field       = $null
                                        Value       = $_.Exception.Message
                                    })
                                Write-Warning "Exception '$($_.Exception.Message)' found when processing list '$($listKey)' in Web '$($webKey)' in Site Collection '$($siteKey)' in Web Application '$($webAppKey)'."
                            }            
                        }
            
                    }
                    catch
                    {
                        $allData.Add([PSCustomObject]@{
                                ProblemType = "Web#Exception"
                                WebApp      = $webAppKey
                                Site        = $siteKey
                                Web         = $webKey
                                List        = $null
                                Item        = $null
                                Field       = $null
                                Value       = $_.Exception.Message
                            })
                        Write-Warning "Exception '$($_.Exception.Message)' found when processing web '$($webKey)' in Site Collection '$($siteKey)' in Web Application '$($webAppKey)'."
            
                    }        
                }
        
            }
            catch
            {
                $allData.Add([PSCustomObject]@{
                        ProblemType = "Site#Exception"
                        WebApp      = $webAppKey
                        Site        = $siteKey
                        Web         = $null
                        List        = $null
                        Item        = $null
                        Field       = $null
                        Value       = $_.Exception.Message
                    })
                Write-Warning "Exception '$($_.Exception.Message)' found when processing site collection '$($siteKey)' in Web Application '$($webAppKey)'."
            }    
        }
    
    }
    catch
    {
        $allData.Add([PSCustomObject]@{
                ProblemType = "WebApplication#Exception"
                WebApp      = $webAppKey
                Site        = $null
                Web         = $null
                List        = $null
                Item        = $null
                Field       = $null
                Value       = $_.Exception.Message
            })
        Write-Warning "Exception '$($_.Exception.Message)' found when processing web application '$($webAppKey)'."
    }
}

$allData | Export-Clixml -Path "$root\data\Report.xml" -Force

# Stopping Transcript
(Get-Date).ToString("yyyyMMddHHmmssfff")
Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAmSE++XbXsfgGo
# 71DxhfGvWV76MenUnu86XiCYN7YsnaCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIEteZcwlSkjuqB/7
# BOhQI2fNWC8ExbBMTniBsYEmJUi4MA0GCSqGSIb3DQEBAQUABIICACseI3DIzz+j
# jPLoLHOwN5fjyQClYVIKyVvL6lVTwXEoHGvgTFd0OsM9zjkQxWs8lgdBw4beNS0d
# pCQ1FjwBnppL0DPQWKo1cIiW6n2jGP0Feo294Oi5q0r2u/XlhDzANZoI5E0/BCpU
# Dd7MLCyMkKS8+vCuc25dco4IYNs5YyTReTL387nydFRTUOCHUiiKtluFWx8EqOjD
# ZxxeISZqytwB0rUU3pgNR8VVXVIl6IrqVEmWGWcy99cSwcrBTPoC2KJHP79GAqJd
# 7ivteTac1OQgXBIcPJp+1BhTjvggKzUjQXjuTOKKynVBB4na6LKfn+oB4x+Xi5+p
# RRS5zXMCL9y6J2sKGNu7qg3stQlqsN3JUx0Tz4/qSr7JSgidHVuvCR2SiLMrr1v9
# GmARde+1RdNnXiegQo094Z2n7coTsiNtvqTVUsUGet6nHOfK/wglcInujvaA1pp0
# M4lkD+5NWtSZSXQsk1sxVRRRKf7NgjPpRy4T6Rym55eu7oIz9s02lJqoj6InGOkg
# 37Ag2Yi9KF6FGWOMdVGG1QncExFsKPpNrpVQH82UrgpOfhF3LBrcNWi9TbXVrbIK
# w9Urbs2R1K++83Ke8nJi8LgccuqTAH6a7JGM0gvbYL/ZBURtLB9qpR+eIyY1iAj7
# /Dd5gV/dmX3Du13ThObW/tHG/eVAyuPIoYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCDxgBD4IVcOViiBr46A6Fg3j7nMpzehCyrixh+GgCLwKQIUGb3lYJVV1LfB
# 8NzpPhiDIkbVoRIYDzIwMjYwMjA5MTQwMDEwWjADAgEBoFikVjBUMQswCQYDVQQG
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
# IP/ldTQ5zlm4UHtUrXd8pGCxgIIwmvFgiufIURQmUHe7MIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGACoOS3/T5fDfT
# oK0hbREM/WXzFMTOBI3dRe2VFVuxhIViGaPTwbzAxWe1R/EQeO8r9EhBuaCDiysn
# u3SAP741Pj0VZHTUMfzJIuldmaaDOmDIqxuCevuYP0PrUQ3zR1MpnIAY2CMUAKwj
# wo1CnhfsL00je1NPH5JLI4m9qLJKR2Oq7Dx0naAsi/6co8EI8rzI4Jxm8l2WmCZB
# Ui1+nLAGQOBxSbuu1iMFwUNEXhEVVH9Hpw3683oanEWlGIdeJJ3kpE+WEqwjZaAh
# X4IsW2ugfs6b8k87+c1dT/L2qvCjlU2J8tiaDCaUODeqQSn0uCP+zG7WcIQXIDzZ
# SFFuGfXuUJkpT59AR8S6JNFBZEWXV78S+HrtkWdA1SZ4a/VIvz0Ikq4S7bINceh3
# poDehM3jdVBDtC+mzNvrGlwOdY+62LId3luYip73g8z5tMOWnLBa+siN2eqkIkYE
# VQQ7nAWuy3d53eVG75iyejq2b+nby2FpAhPlnlxtN0Vd2zpJBQex
# SIG # End signature block
