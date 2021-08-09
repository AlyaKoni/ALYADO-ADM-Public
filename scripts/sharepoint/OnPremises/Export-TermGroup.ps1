#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2021

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
    Date       Author     Description
    ---------- -------------------- ----------------------------
    13.03.2019 Konrad Brunner       Initial Version

#>

# Parameters
[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [string]$termStoreName,
    [Parameter(Mandatory=$false)]
    [switch]$termGroupName
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\onprem\Export-TermGroup-$($AlyaTimeString).log" | Out-Null

#Checking modules
Check-Module "Microsoft.SharePoint.PowerShell"
Add-PSSnapin "Microsoft.SharePoint.PowerShell" -ErrorAction Stop

# =============================================================
# SharePoint OnPrem stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Export-TermGroup | OnPrem" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

#Main
if (-Not $termStoreName)
{
    Write-Host "Please provide the name of the term store:"
    $termStoreName = Read-Host
}
if (-Not $termGroupName)
{
    Write-Host "Please provide the name of the term group to export:"
    $termGroupName = Read-Host
}

[Byte[]]$amp = 0xEF,0xBC,0x86

$taxSite = Get-SPSite (Get-SPWebApplication -IncludeCentralAdministration | ? {$_.IsAdministrationWebApplication -eq $True}).Url
$taxonomySession = Get-SPTaxonomySession -site $taxSite
$termStore =  $taxonomySession.TermStores | where Name -eq $termStoreName
$termGroup = $termStore.Groups | where Name -eq $termGroupName

# Create xml
$resultInXml = New-Object xml
$decl = $resultInXml.CreateXmlDeclaration("1.0", "UTF-8", $null)
$rootNode = $resultInXml.CreateElement("ManagedMetadataExport")
$rootNode.SetAttribute("TermGroupType", "Global")
$rootNode.SetAttribute("Created", ((Get-Date).ToString("o")))
$tmp = $resultInXml.InsertBefore($decl, $resultInXml.DocumentElement)
$tmp = $resultInXml.AppendChild($rootNode);

# Write out the TermStore properties
Write-Host "Exporting termstore $termStore.Name"
$TermStoreElem = $resultInXml.CreateElement("TermStore");
$TermStoreElem.SetAttribute("DefaultLanguage", $termStore.DefaultLanguage);
$TermStoreElem.SetAttribute("WorkingLanguage", $termStore.WorkingLanguage);
$TermStoreElem.SetAttribute("GUID", $termStore.ID);
$TermStoreElem.SetAttribute("Name", $termStore.Name);
$tmp = $rootNode.AppendChild($TermStoreElem);
			 
#Write out TermStoreAdministrators as subcategory of TermStore
$TermStoreAdministratorsElem = $resultInXml.CreateElement("TermStoreAdministrators");
$tmp = $TermStoreElem.AppendChild($TermStoreAdministratorsElem);	 
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
    $tmp = $TermStoreAdministratorsElem.AppendChild($TermStoreAdministratorElem);
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
$tmp = $TermStoreElem.AppendChild($TermGroupElem);

# Write out all managers of TermGroup as subcategory of TermGroup
$TermGroupManagers = $termGroup.GroupManagerPrincipalNames
$TermGroupManagersElem = $resultInXml.CreateElement("GroupManagers");
$tmp = $TermGroupElem.AppendChild($TermGroupManagersElem);
foreach ($TermGroupManager in $TermGroupManagers)
{
    $TermGroupManagerElem = $resultInXml.CreateElement("GroupManager");
    $TermGroupManagerElem.SetAttribute("PrincipalName", $TermGroupManager);
    $tmp = $TermGroupManagersElem.AppendChild($TermGroupManagerElem);
}
			 
# Write out all contributors of TermGroup as subcategory of TermGroup
$TermGroupContributorsElem = $resultInXml.CreateElement("Contributors");
$tmp = $TermGroupElem.AppendChild($TermGroupContributorsElem);
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
    $tmp = $TermGroupContributorsElem.AppendChild($TermGroupContributorElem);
}

# Term set export function
function Export-SPTermSet
{
    param (
        [Microsoft.SharePoint.Taxonomy.TermCollection]$terms,
        [int]$level = 1,
        [string]$previousTerms = ""
    )

    if ($terms.Count -gt 0)
    {
	    $TermsElem = $resultInXml.CreateElement("Terms");
	    $TermsElem.SetAttribute("Level", $level)
	    $tmp = $TermSetElem.AppendChild($TermsElem);
    }

    if ($level -ge 1 -or $level -le 15)
    {
        if ($terms.Count -gt 0 )
        {
            $termSetName = ""
            if ($level -eq 1)
            {
                $termSetName =  """" + $terms[0].TermSet.Name.Replace([System.Text.Encoding]::UTF8.GetString($amp), "&") + """"
            }
		
            foreach($term in $terms)
            {
                $termName = $term.Name.Replace([System.Text.Encoding]::UTF8.GetString($amp), "&")
                $currentTerms = $previousTerms + ",""" + $termName + """"
				
			    #Output TopTerm Properties to XML
			    $TermElem = $resultInXml.CreateElement("Term")
			    $TermElem.SetAttribute("IsAvailableForTagging", $term.IsAvailableForTagging)
			    $TermElem.SetAttribute("Description", $term.GetDescription())
			    $TermElem.SetAttribute("CustomSortOrder", $term.CustomSortOrder)
			    $TermElem.SetAttribute("IsDeprecated", $term.IsDeprecated)
			    $TermElem.SetAttribute("IsKeyword", $term.IsKeyword)
			    $TermElem.SetAttribute("IsHashTag", $term.IsHashTag)
			    $TermElem.SetAttribute("IsReused", $term.IsReused)
			    $TermElem.SetAttribute("IsRoot", $term.IsRoot)
			    $TermElem.SetAttribute("IsSourceTerm", $term.IsSourceTerm)
                <#if ($term.TermSets.Count -gt 1)
                {
                    throw "Please implement TermSets"
                }#>
			    $TermElem.SetAttribute("TermSets", $term.TermSets.Id.Guid)
			    $TermElem.SetAttribute("MergedTermIds", $term.MergedTermIds)
			    $TermElem.SetAttribute("Owner", $term.Owner)
			    $TermElem.SetAttribute("IsPinned", $term.IsPinned)
			    $TermElem.SetAttribute("IsPinnedRoot", $term.IsPinnedRoot)
			    $TermElem.SetAttribute("PinSourceTermSet", $term.PinSourceTermSet)
			    $TermElem.SetAttribute("ReusedTerms", $term.ReusedTerms.Id)
			    $TermElem.SetAttribute("SourceTerm", $term.SourceTerm.Id)
			    $TermElem.SetAttribute("ParentId", $term.Parent.Id)
			    $TermElem.SetAttribute("ParentName", $term.Parent.Name)
			    $TermElem.SetAttribute("Id", $term.Id)
			    $TermElem.SetAttribute("Name", $termName)
				
			    #Write above Attributes to XML
			    $tmp = $TermsElem.AppendChild($TermElem)
				
			    #Create Labels Subcategory on TopTermElement
			    $TermLabelsElem = $resultInXml.CreateElement("Labels")
			    $tmp = $TermElem.AppendChild($TermLabelsElem)
				
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
				    $tmp = $TermLabelsElem.AppendChild($TermLabelElem)
			    }
				
			    #Create Custom Properties Subcategory on TopTerm Element
			    $TermCustomPropertiesElem = $resultInXml.CreateElement("CustomProperties")
			    $tmp = $TermElem.AppendChild($TermCustomPropertiesElem)
				
			    $TermCustomPropertyKeys = $term.CustomProperties.Keys
			    foreach ($Key in $TermCustomPropertyKeys)
                {
				    $TermCustomPropertyElem = $resultInXml.CreateElement("CustomProperty")
				    $TermCustomPropertyElem.SetAttribute("Name", $Key)
				    $TermCustomPropertyElem.SetAttribute("Value", $term.CustomProperties[$Key])
				    $tmp = $TermCustomPropertiesElem.AppendChild($TermCustomPropertyElem)
			    }
				
			    #Create Local Custom Properties Subcategory on TopTerm Element
			    $TermLocalCustomPropertiesElem = $resultInXml.CreateElement("LocalCustomProperties")
			    $tmp = $TermElem.AppendChild($TermLocalCustomPropertiesElem)
			    $TermLocalCustomPropertyKeys = $term.LocalCustomProperties.Keys
			    foreach ($Key in $TermLocalCustomPropertyKeys)
                {
				    $TermLocalCustomPropertyElem = $resultInXml.CreateElement("LocalCustomProperty")
				    $TermLocalCustomPropertyElem.SetAttribute("Name", $Key)
				    $TermLocalCustomPropertyElem.SetAttribute("Value", $term.LocalCustomProperties[$Key])
				    $tmp = $TermLocalCustomPropertiesElem.AppendChild($TermLocalCustomPropertyElem)
			    }
				
                #if ($level -lt 15)
                #{
                    Export-SPTermSet $term.Terms ($level + 1) ($previousTerms + $currentTerms)
                #}
            }
        }
    }
}

# Start looping through Term sets
Write-Host "Looping termsets"
$TermSetsElem = $resultInXml.CreateElement("TermSets");
$tmp = $TermGroupElem.AppendChild($TermSetsElem);
foreach ($termSet in $termGroup.TermSets)
{        
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
    $tmp = $TermSetsElem.AppendChild($TermSetElem);

    #Create Custom Properties Subcategory on NavigationTermSet Element
    $TermSetCustomPropertiesElem = $resultInXml.CreateElement("CustomProperties")
    $tmp = $TermSetElem.AppendChild($TermSetCustomPropertiesElem)

    #activated CustomProperties of WebsitenavigationTermSet
    $TermSetCustomPropertyKeys = $termSet.CustomProperties.Keys
    foreach ($Key in $TermSetCustomPropertyKeys)
    {
	    $VariableValue = $termSet.CustomProperties[$Key]
	    $TermSetCustomPropertyElem = $resultInXml.CreateElement("CustomProperty")
	    $TermSetCustomPropertyElem.SetAttribute("Name", $Key)
	    $TermSetCustomPropertyElem.SetAttribute("Value", $VariableValue)
	    $tmp = $TermSetCustomPropertiesElem.AppendChild($TermSetCustomPropertyElem)
    }

    # Start exporting the Terms of the TermSet
    Export-SPTermSet $termSet.Terms

}

$grpFile = "$($AlyaData)\sharepoint\Export-TermGroup-$($termGroupName)-$($AlyaTimeString).xml"
$resultInXml.Save($grpFile)
Write-Host Finished -ForegroundColor $successColor

#Stopping Transscript
Stop-Transcript