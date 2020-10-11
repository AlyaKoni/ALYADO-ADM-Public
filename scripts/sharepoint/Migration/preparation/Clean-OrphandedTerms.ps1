#Requires -Version 2.0
Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction Stop

$siteUrl = “http://site1internal.alyaconsulting.ch”
$sesstion = Get-SPTaxonomySession -Site $siteUrl
$termStore = $session.TermStores[“Managed Metadata Service Site1”]
$systemGroup = $termStore.SystemGroup
$termSet = $systemGroup.TermSets[“Orphaned Terms”]
$terms = $termSet.Terms
$terms | % { $_.Delete() }
$termStore.CommitAll();
