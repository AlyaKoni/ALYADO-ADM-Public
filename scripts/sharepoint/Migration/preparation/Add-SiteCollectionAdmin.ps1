#Requires -Version 2.0
Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction Stop

Get-SPWebApplication | Foreach-Object { 
    $webApp = $_ 
	foreach($siteCol in $webApp.Sites) {
	    foreach($siteCol in $webApp.Sites) {
        	    New-SPUser -UserAlias "i:0e.t|sts.alyaconsulting.ch_upn|konrad.brunner@alyaconsulting.ch" -Web $siteCol.Url -SiteCollectionAdmin
        	    New-SPUser -UserAlias "i:0#.w|alyaconsulting\konradbrunner" -Web $siteCol.Url -SiteCollectionAdmin
        	    New-SPUser -UserAlias "alyaconsulting\konradbrunner" -Web $siteCol.Url -SiteCollectionAdmin
	    }
	}
}
