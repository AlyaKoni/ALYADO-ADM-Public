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


#>

Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction Stop

function fixTermStoreRights()
{
    $termStore.AddTermStoreAdministrator("i:0e.t|sts.alyaconsulting.ch_upn|konrad.brunner@alyaconsulting.ch")
    $termStore.AddTermStoreAdministrator("i:0#.w|alyaconsulting\konradbrunner")
    $termStore.AddTermStoreAdministrator("alyaconsulting\konradbrunner")
    $termStore.CommitAll()

    $termStore.Groups | Foreach-Object {
        $grp = $_
        Write-Output "Working on group $($grp.name)"
        $mangrs = $grp.GroupManagers
        $mangrs | Foreach-Object {
            $mangr = $_
            if ($mangr.PrincipalName -eq "i:0e.t|sts.alyaconsulting.ch_upn|first1last1@alyaconsulting.ch" -or $mangr.PrincipalName -eq "alyaconsulting\first1last1")
            {
                Write-Output "  Replacing $($mangr.PrincipalName)"
                $grp.AddGroupManager("i:0e.t|sts.alyaconsulting.ch_upn|first1.last1@alyaconsulting.ch")
                $grp.DeleteGroupManager($mangr.PrincipalName)
            }
            if ($mangr.PrincipalName -eq "i:0e.t|sts.alyaconsulting.ch_upn|first2last2@alyaconsulting.ch" -or $mangr.PrincipalName -eq "alyaconsulting\first1last2")
            {
                Write-Output "  Replacing $($mangr.PrincipalName)"
                $grp.AddGroupManager("i:0e.t|sts.alyaconsulting.ch_upn|first2.last2@alyaconsulting.ch")
                $grp.DeleteGroupManager($mangr.PrincipalName)
            }
        }
        $contrs = $grp.Contributors
        $contrs | Foreach-Object {
            $contr = $_
            if ($contr.PrincipalName -eq "i:0e.t|sts.alyaconsulting.ch_upn|first1last1@alyaconsulting.ch" -or $contr.PrincipalName -eq "alyaconsulting\first1last1")
            {
                Write-Output "  Replacing $($contr.PrincipalName)"
                $grp.AddContributor("i:0e.t|sts.alyaconsulting.ch_upn|first1.last1@alyaconsulting.ch")
                $grp.DeleteContributor($contr.PrincipalName)
            }
            if ($contr.PrincipalName -eq "i:0e.t|sts.alyaconsulting.ch_upn|first2last2@alyaconsulting.ch" -or $contr.PrincipalName -eq "alyaconsulting\first1last2")
            {
                Write-Output "  Replacing $($contr.PrincipalName)"
                $grp.AddContributor("i:0e.t|sts.alyaconsulting.ch_upn|first2.last2@alyaconsulting.ch")
                $grp.DeleteContributor($contr.PrincipalName)
            }
        }
        $grp.TermSets | Foreach-Object {
            $set = $_
            if ($set.Owner -like "i:0*")
            {
                $set.Owner = "alyaconsulting\SPOnPremAdmin"
            }
        }
    }
    $termStore.CommitAll()

}

$taxonomySession = Get-SPTaxonomySession -Site "https://site1internal.alyaconsulting.ch"
$termStore = $taxonomySession.TermStores["Managed Metadata Service Site1"]
fixTermStoreRights

$taxonomySession = Get-SPTaxonomySession -Site "https://site2internal.alyaconsulting.ch"
$termStore = $taxonomySession.TermStores["Managed Metadata Service Site2"]
fixTermStoreRights
