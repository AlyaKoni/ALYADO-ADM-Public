#Requires -Version 2.0
Add-PSSnapin Microsoft.SharePoint.PowerShell -ErrorAction Stop

$userOrGroup = "alyaconsulting\konradbrunner" 
$displayName = "Brunner Konrad" 

Get-SPWebApplication | foreach { 
    $webApp = $_ 
    $policy = $webApp.Policies.Add($userOrGroup, $displayName) 
    $policyRole = $webApp.PolicyRoles.GetSpecialRole([Microsoft.SharePoint.Administration.SPPolicyRoleType]::FullControl) 
    $policy.PolicyRoleBindings.Add($policyRole) 
    $webApp.Update() 
}

Get-SPWebApplication | foreach { 
    $webApp = $_ 
	foreach($siteCol in $webApp.Sites) {
        	New-SPUser -UserAlias "i:0e.t|sts.alyaconsulting.ch_upn|konrad.brunner@alyaconsulting.ch" -Web $siteCol.Url -SiteCollectionAdmin
        	New-SPUser -UserAlias "i:0#.w|alyaconsulting\konradbrunner" -Web $siteCol.Url -SiteCollectionAdmin
        	New-SPUser -UserAlias "alyaconsulting\konradbrunner" -Web $siteCol.Url -SiteCollectionAdmin
	}
}

