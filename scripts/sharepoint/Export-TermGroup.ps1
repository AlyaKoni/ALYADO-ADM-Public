﻿#Requires -Version 7.0

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
    15.10.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [ValidateNotNull()]
    [string]$siteUrl = $null,
    [ValidateNotNull()]
    [string]$termStoreName = $null,
    [ValidateNotNull()]
    [string]$termGroupName = $null
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Export-TermGroup-$($AlyaTimeString).log" | Out-Null

# Checking modules
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "AzureAdPreview"
Install-PackageIfNotInstalled "Microsoft.SharePointOnline.CSOM"
Add-Type -Path "$($AlyaTools)\Packages\Microsoft.SharePointOnline.CSOM\lib\net45\Microsoft.SharePoint.Client.dll"
Add-Type -Path "$($AlyaTools)\Packages\Microsoft.SharePointOnline.CSOM\lib\net45\Microsoft.SharePoint.Client.Runtime.dll"
Add-Type -Path "$($AlyaTools)\Packages\Microsoft.SharePointOnline.CSOM\lib\net45\Microsoft.SharePoint.Client.Taxonomy.dll"

# Members
[Byte[]]$amp = 0xEF,0xBC,0x86

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad

$mms = [Microsoft.SharePoint.Client.Taxonomy.TaxonomySession]::GetTaxonomySession($ctx)
$ctx.Load($mms)
$termStore = $mms.TermStores.GetByName($termStoreName)
$ctx.Load($termStore)
$ctx.Load($termStore.Groups)
$ctx.ExecuteQuery()
$termGroup = $termStore.Groups | Where-Object { $_.Name -eq $termGroupName }
$ctx.Load($termGroup)
$ctx.Load($termGroup.TermSets)
$ctx.ExecuteQuery()

# Create xml
$resultInXml = New-Object xml
$decl = $resultInXml.CreateXmlDeclaration("1.0", "UTF-8", $null)
$rootNode = $resultInXml.CreateElement("ManagedMetadataExport")
$rootNode.SetAttribute("TermGroupType", "Global")
$rootNode.SetAttribute("Created", ((Get-Date).ToString("o")))
$null = $resultInXml.InsertBefore($decl, $resultInXml.DocumentElement)
$null = $resultInXml.AppendChild($rootNode)

# Write out the TermStore properties
Write-Host "Exporting termstore $($termStore.Name)"
$TermStoreElem = $resultInXml.CreateElement("TermStore");
$TermStoreElem.SetAttribute("DefaultLanguage", $termStore.DefaultLanguage)
$TermStoreElem.SetAttribute("WorkingLanguage", $termStore.WorkingLanguage)
$TermStoreElem.SetAttribute("GUID", $termStore.ID)
$TermStoreElem.SetAttribute("Name", $termStore.Name)
$null = $rootNode.AppendChild($TermStoreElem)
			 
#Write out TermStoreAdministrators as subcategory of TermStore
$TermStoreAdministratorsElem = $resultInXml.CreateElement("TermStoreAdministrators");
$null = $TermStoreElem.AppendChild($TermStoreAdministratorsElem);	 
foreach ($Administrator in $termStore.TermStoreAdministrators)
{
    $TermStoreAdministratorElem = $resultInXml.CreateElement("TermStoreAdministrator");
    $TermStoreAdministratorElem.SetAttribute("DenyRightsMask", $Administrator.DenyRightsMask);
    $TermStoreAdministratorElem.SetAttribute("GrantRightsMask", $Administrator.GrantRightsMask);
    $TermStoreAdministratorElem.SetAttribute("DisplayName", $Administrator.DisplayName);
    $TermStoreAdministratorElem.SetAttribute("IsWindowsAuthenticationMode", $Administrator.IsWindowsAuthenticationMode);
    $TermStoreAdministratorElem.SetAttribute("PrincipalName", $Administrator.PrincipalName);
    $TermStoreAdministratorElem.SetAttribute("RawSid", $Administrator.RawSid);
    $TermStoreAdministratorElem.SetAttribute("BinaryId", $Administrator.BinaryId);
    $TermStoreAdministratorElem.SetAttribute("BinaryIdType", $Administrator.BinaryIdType);
    $null = $TermStoreAdministratorsElem.AppendChild($TermStoreAdministratorElem);
}
			 
# Write out the TermGroup properties
Write-Host "Exporting termgroup $termGroupName"
$TermGroupElem = $resultInXml.CreateElement("TermGroup");
$TermGroupElem.SetAttribute("Description", $termGroup.Description);
$TermGroupElem.SetAttribute("IsSystemGroup", $termGroup.IsSystemGroup);
$TermGroupElem.SetAttribute("IsSiteCollectionGroup", $termGroup.IsSiteCollectionGroup);
$TermGroupElem.SetAttribute("IsReadOnlySiteCollectionGroup", $termGroup.IsReadOnlySiteCollectionGroup);
$TermGroupElem.SetAttribute("SiteCollectionAccessIds", $termGroup.SiteCollectionAccessIds);
$TermGroupElem.SetAttribute("SiteCollectionReadOnlyAccessUrls", $termGroup.SiteCollectionReadOnlyAccessUrls);
$TermGroupElem.SetAttribute("Id", $termGroup.Id);
$TermGroupElem.SetAttribute("Name", $termGroupName);
$null = $TermStoreElem.AppendChild($TermGroupElem);

# Write out all managers of TermGroup as subcategory of TermGroup
$TermGroupManagers = $termGroup.GroupManagerPrincipalNames
$TermGroupManagersElem = $resultInXml.CreateElement("GroupManagers");
$null = $TermGroupElem.AppendChild($TermGroupManagersElem);
foreach ($TermGroupManager in $TermGroupManagers)
{
    $TermGroupManagerElem = $resultInXml.CreateElement("GroupManager");
    $TermGroupManagerElem.SetAttribute("PrincipalName", $TermGroupManager);
    $null = $TermGroupManagersElem.AppendChild($TermGroupManagerElem);
}
			 
# Write out all contributors of TermGroup as subcategory of TermGroup
$TermGroupContributorsElem = $resultInXml.CreateElement("Contributors");
$null = $TermGroupElem.AppendChild($TermGroupContributorsElem);
foreach ($Contributor in $termGroup.Contributors)
{
    $TermGroupContributorElem = $resultInXml.CreateElement("Contributor");
    $TermGroupContributorElem.SetAttribute("DenyRightsMask", $Contributor.DenyRightsMask);
    $TermGroupContributorElem.SetAttribute("GrantRightsMask", $Contributor.GrantRightsMask);
    $TermGroupContributorElem.SetAttribute("DisplayName", $Contributor.DisplayName);
    $TermGroupContributorElem.SetAttribute("IsWindowsAuthenticationMode", $Contributor.IsWindowsAuthenticationMode);
    $TermGroupContributorElem.SetAttribute("PrincipalName", $Contributor.PrincipalName);
    $TermGroupContributorElem.SetAttribute("RawSid", $Contributor.RawSid);
    $TermGroupContributorElem.SetAttribute("BinaryId", $Contributor.BinaryId);
    $TermGroupContributorElem.SetAttribute("BinaryIdType", $Contributor.BinaryIdType);
    $null = $TermGroupContributorsElem.AppendChild($TermGroupContributorElem);
}

# Term set export function
function Export-SPTermSet
{
    param (
        [Microsoft.SharePoint.Client.Taxonomy.TermCollection]$terms,
        [int]$level = 1,
        [string]$previousTerms = "",
        [string]$termSetName,
        $parentElement
    )

    if ($terms.Count -gt 0 )
    {
	    $TermsElem = $resultInXml.CreateElement("Terms");
	    $TermsElem.SetAttribute("Level", $level)
	    $null = $parentElement.AppendChild($TermsElem);
    }

    if ($level -ge 1 -or $level -le 15)
    {
        if ($terms.Count -gt 0 )
        {
            $termSetName = ""
            if ($level -eq 1)
            {
                $termSetName =  """" + $termSetName.Replace([System.Text.Encoding]::UTF8.GetString($amp), "&") + """"
            }
		
            foreach($term in $terms)
            {
                $ctx.Load($term)
                $ctx.Load($term.Terms)
                $ctx.Load($term.ReusedTerms)
                $ctx.Load($term.TermSets)
                $ctx.Load($term.Labels)
                $ctx.Load($term.Parent)
			    $descriptionDE = $term.GetDescription(1031)
			    $descriptionEN = $term.GetDescription(1033)
			    $descriptionFR = $term.GetDescription(1036)
			    $descriptionIT = $term.GetDescription(1040)
                $ctx.ExecuteQuery()

                $termName = $term.Name.Replace([System.Text.Encoding]::UTF8.GetString($amp), "&")
                $currentTerms = $previousTerms + ",""" + $termName + """"
				
			    #Output TopTerm Properties to XML
			    $TermElem = $resultInXml.CreateElement("Term")
			    $TermElem.SetAttribute("IsAvailableForTagging", $term.IsAvailableForTagging)
			    $TermElem.SetAttribute("Description", $term.Description.Replace([System.Text.Encoding]::UTF8.GetString($amp), "&"))
			    $TermElem.SetAttribute("DescriptionDE", $descriptionDE.Value.Replace([System.Text.Encoding]::UTF8.GetString($amp), "&"))
			    $TermElem.SetAttribute("DescriptionEN", $descriptionEN.Value.Replace([System.Text.Encoding]::UTF8.GetString($amp), "&"))
			    $TermElem.SetAttribute("DescriptionFR", $descriptionFR.Value.Replace([System.Text.Encoding]::UTF8.GetString($amp), "&"))
			    $TermElem.SetAttribute("DescriptionIT", $descriptionIT.Value.Replace([System.Text.Encoding]::UTF8.GetString($amp), "&"))
			    $TermElem.SetAttribute("CustomSortOrder", $term.CustomSortOrder)
			    $TermElem.SetAttribute("IsDeprecated", $term.IsDeprecated)
			    $TermElem.SetAttribute("IsKeyword", $term.IsKeyword)
			    $TermElem.SetAttribute("IsHashTag", $term.IsHashTag)
			    $TermElem.SetAttribute("IsReused", $term.IsReused)
			    $TermElem.SetAttribute("IsRoot", $term.IsRoot)
			    $TermElem.SetAttribute("IsSourceTerm", $term.IsSourceTerm)
			    $TermElem.SetAttribute("TermSets", $term.TermSets.Id.Guid)
			    $TermElem.SetAttribute("MergedTermIds", $term.MergedTermIds)
			    $TermElem.SetAttribute("Owner", $term.Owner)
			    $TermElem.SetAttribute("IsPinned", $term.IsPinned)
			    $TermElem.SetAttribute("IsPinnedRoot", $term.IsPinnedRoot)
			    $TermElem.SetAttribute("PinSourceTermSet", $term.PinSourceTermSet)
			    $TermElem.SetAttribute("ReusedTerms", $term.ReusedTerms.Id)
			    $TermElem.SetAttribute("SourceTerm", $term.SourceTerm.Id)
			    $TermElem.SetAttribute("ParentId", $term.Parent.Id)
			    $TermElem.SetAttribute("ParentName", $term.Parent.Name.Replace([System.Text.Encoding]::UTF8.GetString($amp), "&"))
			    $TermElem.SetAttribute("Id", $term.Id)
			    $TermElem.SetAttribute("Name", $termName)
				
			    #Write above Attributes to XML
                $null = $TermsElem.AppendChild($TermElem)

			    #Create Labels Subcategory on TopTermElement
                if ($term.Labels.Count -gt 0)
                {
			        $TermLabelsElem = $resultInXml.CreateElement("Labels")
			        $null = $TermElem.AppendChild($TermLabelsElem)
			        $TermLabels = $term.Labels
			        foreach ($TermLabel in $TermLabels)
                    {
                        <#if ($TermLabel.Language -ne $termStore.DefaultLanguage -and $term.Name -eq $TermLabel.Value)
                        {
                            Write-Host "TermName equals label lang: $($TermLabel.Language) value: $($term.Name)" -ForegroundColor Red
                        }#>
				        $TermLabelElem = $resultInXml.CreateElement("Label")
				        $TermLabelElem.SetAttribute("IsDefaultForLanguage", $TermLabel.IsDefaultForLanguage)
				        $TermLabelElem.SetAttribute("Language", $TermLabel.Language)
				        $TermLabelElem.SetAttribute("Value", $TermLabel.Value)
				        $null = $TermLabelsElem.AppendChild($TermLabelElem)
			        }
			    }
				
			    #Create Custom Properties Subcategory on TopTerm Element
                if ($term.CustomProperties.Keys.Count -gt 0)
                {
			        $TermCustomPropertiesElem = $resultInXml.CreateElement("CustomProperties")
			        $null = $TermElem.AppendChild($TermCustomPropertiesElem)
				
			        $TermCustomPropertyKeys = $term.CustomProperties.Keys
			        foreach ($Key in $TermCustomPropertyKeys)
                    {
				        $TermCustomPropertyElem = $resultInXml.CreateElement("CustomProperty")
				        $TermCustomPropertyElem.SetAttribute("Name", $Key)
				        $TermCustomPropertyElem.SetAttribute("Value", $term.CustomProperties[$Key])
				        $null = $TermCustomPropertiesElem.AppendChild($TermCustomPropertyElem)
			        }
			    }
				
			    #Create Local Custom Properties Subcategory on TopTerm Element
                if ($term.LocalCustomProperties.Keys.Count -gt 0)
                {
			        $TermLocalCustomPropertiesElem = $resultInXml.CreateElement("LocalCustomProperties")
			        $null = $TermElem.AppendChild($TermLocalCustomPropertiesElem)
			        $TermLocalCustomPropertyKeys = $term.LocalCustomProperties.Keys
			        foreach ($Key in $TermLocalCustomPropertyKeys)
                    {
				        $TermLocalCustomPropertyElem = $resultInXml.CreateElement("LocalCustomProperty")
				        $TermLocalCustomPropertyElem.SetAttribute("Name", $Key)
				        $TermLocalCustomPropertyElem.SetAttribute("Value", $term.LocalCustomProperties[$Key])
				        $null = $TermLocalCustomPropertiesElem.AppendChild($TermLocalCustomPropertyElem)
			        }
			    }
				
                Export-SPTermSet -terms $term.Terms -level ($level + 1) -previousTerms ($previousTerms + $currentTerms) -termSetName $termSetName -parentElement $TermElem
            }
        }
    }
}

# Start looping through Term sets
Write-Host "Looping termsets"
$TermSetsElem = $resultInXml.CreateElement("TermSets");
$null = $TermGroupElem.AppendChild($TermSetsElem);
foreach ($termSet in $termGroup.TermSets)
{        
    $ctx.Load($termSet)
    $ctx.Load($termSet.Terms)
    $ctx.ExecuteQuery()
    # Write out the TermSet properties
    Write-Host "Exporting termset $($termSet.Name)"
    $TermSetElem = $resultInXml.CreateElement("TermSet");
    $TermSetElem.SetAttribute("Description", $termSet.Description)
    $TermSetElem.SetAttribute("IsAvailableForTagging", $termSet.IsAvailableForTagging)
    $TermSetElem.SetAttribute("IsOpenForTermCreation", $termSet.IsOpenForTermCreation)
    $TermSetElem.SetAttribute("Owner", $termSet.Owner)
    $TermSetElem.SetAttribute("CustomSortOrder", $termSet.CustomSortOrder)
    $TermSetElem.SetAttribute("Stakeholders", $termSet.Stakeholders)
    $TermSetElem.SetAttribute("Contact", $termSet.Contact)
    $TermSetElem.SetAttribute("Id", $termSet.Id)
    $TermSetElem.SetAttribute("Name", $termSet.Name)
    $null = $TermSetsElem.AppendChild($TermSetElem);

    #Create Custom Properties Subcategory on NavigationTermSet Element
    $TermSetCustomPropertiesElem = $resultInXml.CreateElement("CustomProperties")
    $null = $TermSetElem.AppendChild($TermSetCustomPropertiesElem)

    #activated CustomProperties of WebsitenavigationTermSet
    $TermSetCustomPropertyKeys = $termSet.CustomProperties.Keys
    foreach ($Key in $TermSetCustomPropertyKeys)
    {
	    $VariableValue = $termSet.CustomProperties[$Key]
	    $TermSetCustomPropertyElem = $resultInXml.CreateElement("CustomProperty")
	    $TermSetCustomPropertyElem.SetAttribute("Name", $Key)
	    $TermSetCustomPropertyElem.SetAttribute("Value", $VariableValue)
	    $null = $TermSetCustomPropertiesElem.AppendChild($TermSetCustomPropertyElem)
    }

    # Start exporting the Terms of the TermSet
    Export-SPTermSet -terms $termSet.Terms -termSetName $termSet.Name -level 1 -parentElement $TermSetElem

}

$resultInXml.Save("$(AlyaData)\sharepoint\TermGroup_$($termGroupName)_Export.xml")
Write-Host Finished

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIvGwYJKoZIhvcNAQcCoIIvDDCCLwgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBIxG8sKcfmW/+D
# 7nfR+b1EVo7PO3TcCl5v4IvzS1JVb6CCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINixe6GW
# WTREb/toUsmwrIsPqrgbfI2mUeM54miEq5BDMA0GCSqGSIb3DQEBAQUABIICAAXD
# UvHnl3TJAQckcEYMapYZNQ4H7H2QbcThFYiNJLi2NEuhe6VwgmfA4kZldZtENB2y
# Cz7O/dpX2YsCR0tSPZAkMCU362j7fS/WDIbzXYuIGl5aEfK58KmGtXCZ+Wqp+eQF
# OwZfBRkrsLomi9G77GwHcTEcDJkhLYF4O6X4cSc3Fm08wr7HF6GRngndvRg0XXLh
# suexQf/tKYPXx7OBKhdtefJCLt/fO/dHYUW8Cq8giMGbrImk0hL2Aw+MOFZDyxyJ
# R/oRT7H2Z2lagygwy7nKlY+sk2Vq1xVYLcTX0amemhljXHgZ3y57UwehbQyEaqc+
# gkTuowBmrF0geo8FO1qHnftkD7X10yBGnESNWdiGgbkJcLZUEMZkmGQ+YG0IsGMf
# xMYiWYN/JKNHtEKKskwxZv60RcfhqeaSG20u3a82gQxAhsyHzwgxFuwOk/PM+F73
# TqF6vpwjUHcRjVRFgq8t2gQNZ2XijwQkFRaRIy4+19YkGXzE78fk5Fb2gyAoAGCt
# lUOafPZ706u11FqFezXUex9UncpyyDEd+CFo919n43h//j7itBMNzewGHOMHW+3L
# IZoAj7xNag+P4ZLzBCfhbGISMswvw3A5YGYRTou6cOlPwkxyCfj8huV+Y1AfJG7C
# otLtOz3k1dYFOSlVXUpDUDneR2xy46NVIRCFD8m3oYIWzTCCFskGCisGAQQBgjcD
# AwExgha5MIIWtQYJKoZIhvcNAQcCoIIWpjCCFqICAQMxDTALBglghkgBZQMEAgEw
# gegGCyqGSIb3DQEJEAEEoIHYBIHVMIHSAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCAWNBdfwUMznsfdcvJ2kbJpKK0KKCTi0Oa7E+1kSJlsjgIUYCaB
# 0cRBYBij8z9/o62uMx44PAkYDzIwMjUwMjA2MTkzMzQ2WjADAgEBoGGkXzBdMQsw
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
# hvcNAQELBQAwLwYJKoZIhvcNAQkEMSIEIFw/j/ED9yzN9u4fZf4gBgTOeHd58q/1
# acPiDa0dDLzCMIGwBgsqhkiG9w0BCRACLzGBoDCBnTCBmjCBlwQgOoh6lRteuSpe
# 4U9su3aCN6VF0BBb8EURveJfgqkW0egwczBfpF0wWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb6t7ITWuP92w6ny4BJBYwDQYJ
# KoZIhvcNAQELBQAEggGATrNDWhjWj1lrHiz332Fnoaqq0Fs9kiM1htoYcSeDoPBy
# 3KUPKzfyKDCmhyYxVPJlVoFZ+hdObvz21UKpdFq5c6vshbQZFCJMACW9XxnUJtmJ
# hnf+XxEB/nrnLthCQp0U6TMdAGRA7XIXjLt2Rkzpv87o5NF5ybV9ik72zZTWr153
# clhcE+cYol3G0awB/3ji6H6H1NCIg7TedEyEJL/t0VXZSvVgO03YRIYOgAizSBHs
# y9y1q5rjRkpLJzp002VeehAuAj9Ugft90PVoPnSmGLf7//wI6ndvtggocnuOXTO1
# aDaY+OlxwMbrSLmh3NJYWQQrNeDCix4x1lT2Dm9+9n7TNSYag5p2+j4LRnSsUwnb
# RkUTpyl3iBScjDFb9Iitty/7FBh2+034HJk85BX9z2sGzC5ylQMwj0fjuwdb/yni
# M+nrhPiXUzdpyGk6GNmxwTNuPWr7xVUpjHf3C6LEytQjhP6no114nX8RzEKXQKjw
# XoVaf2TccbkLsoV4QnsY
# SIG # End signature block
