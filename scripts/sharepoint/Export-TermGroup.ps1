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
Install-ModuleIfNotInstalled "PnP.PowerShell"

# Members
[Byte[]]$amp = 0xEF,0xBC,0x86

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad
$adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl
$adminCnt = Get-PnPContext
$ctx= Get-PnPContext
$ctx.ExecuteQuery()

$mms = [Microsoft.SharePoint.Client.Taxonomy.TaxonomySession]::GetTaxonomySession($ctx)
$ctx.Load($mms)
$termStore = $mms.TermStores.GetByName($termStoreName)
$ctx.Load($termStore)
$ctx.Load($termStore.Groups)
$ctx.ExecuteQuery()
$termGroup = $termStore.Groups | where { $_.Name -eq $termGroupName }
$ctx.Load($termGroup)
$ctx.Load($termGroup.TermSets)
$ctx.ExecuteQuery()

# Create xml
$resultInXml = New-Object xml
$decl = $resultInXml.CreateXmlDeclaration("1.0", "UTF-8", $null)
$rootNode = $resultInXml.CreateElement("ManagedMetadataExport")
$rootNode.SetAttribute("TermGroupType", "Global")
$rootNode.SetAttribute("Created", ((Get-Date).ToString("o")))
$tmp = $resultInXml.InsertBefore($decl, $resultInXml.DocumentElement)
$tmp = $resultInXml.AppendChild($rootNode)

# Write out the TermStore properties
Write-Host "Exporting termstore $($termStore.Name)"
$TermStoreElem = $resultInXml.CreateElement("TermStore");
$TermStoreElem.SetAttribute("DefaultLanguage", $termStore.DefaultLanguage)
$TermStoreElem.SetAttribute("WorkingLanguage", $termStore.WorkingLanguage)
$TermStoreElem.SetAttribute("GUID", $termStore.ID)
$TermStoreElem.SetAttribute("Name", $termStore.Name)
$tmp = $rootNode.AppendChild($TermStoreElem)
			 
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
	    $tmp = $parentElement.AppendChild($TermsElem);
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
                $tmp = $TermsElem.AppendChild($TermElem)

			    #Create Labels Subcategory on TopTermElement
                if ($term.Labels.Count -gt 0)
                {
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
			    }
				
			    #Create Custom Properties Subcategory on TopTerm Element
                if ($term.CustomProperties.Keys.Count -gt 0)
                {
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
			    }
				
			    #Create Local Custom Properties Subcategory on TopTerm Element
                if ($term.LocalCustomProperties.Keys.Count -gt 0)
                {
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
			    }
				
                Export-SPTermSet -terms $term.Terms -level ($level + 1) -previousTerms ($previousTerms + $currentTerms) -termSetName $termSetName -parentElement $TermElem
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
    Export-SPTermSet -terms $termSet.Terms -termSetName $termSet.Name -level 1 -parentElement $TermSetElem

}

$resultInXml.Save("$(AlyaData)\sharepoint\TermGroup_$($termGroupName)_Export.xml")
Write-Host Finished

#Stopping Transscript
Stop-Transcript
