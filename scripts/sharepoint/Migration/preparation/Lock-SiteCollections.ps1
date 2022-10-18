#Requires -Version 2.0
Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction Stop

$site = Get-SPSite -Identity "https://site1internal.alyaconsulting.ch/sites/mgmt-report-fm"
$site.ReadLocked
$site.ReadOnly
$site.IsReadLocked
$site.LockIssue
$site.WriteLocked

Set-SPSite -Identity "https://site1internal.alyaconsulting.ch/" -LockState ReadOnly
Set-SPSite -Identity "https://site1internal.alyaconsulting.ch/sites/site001" -LockState ReadOnly
Set-SPSite -Identity "https://site1internal.alyaconsulting.ch/sites/site002" -LockState ReadOnly
Set-SPSite -Identity "https://site1internal.alyaconsulting.ch/sites/site003" -LockState ReadOnly
Set-SPSite -Identity "https://site1internal.alyaconsulting.ch/sites/site004" -LockState ReadOnly
