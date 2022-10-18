#Requires -Version 2.0
Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction Stop

function fixTermStoreRights()
{
    $termStore.AddTermStoreAdministrator("i:0e.t|sts.alyaconsulting.ch_upn|konrad.brunner@alyaconsulting.ch")
    $termStore.AddTermStoreAdministrator("i:0#.w|alyaconsulting\konradbrunner")
    $termStore.AddTermStoreAdministrator("alyaconsulting\konradbrunner")
    $termStore.CommitAll()

    $termStore.Groups | foreach {
        $grp = $_
        Write-Output "Working on group $($grp.name)"
        $mangrs = $grp.GroupManagers
        $mangrs | foreach {
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
        $contrs | foreach {
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
        $grp.TermSets | foreach {
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
