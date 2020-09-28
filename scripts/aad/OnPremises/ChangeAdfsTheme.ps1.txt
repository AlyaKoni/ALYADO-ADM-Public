Get-AdfsWebTheme -Name default
Get-AdfsGlobalWebContent 
Set-AdfsWebTheme -TargetName default -Logo @{path="$PSScriptRoot\alya-logo.png"}  
Set-AdfsWebTheme -TargetName default -Illustration @{path="$PSScriptRoot\alya-illustration.png"}
Set-AdfsGlobalWebContent –CompanyName "Alya Consulting"
#Set-AdfsGlobalWebContent -SignInPageDescriptionText "<p>Sign-in to Contoso requires device registration. Click <A href='http://fs1.contoso.com/deviceregistration/'>here</A> for more information.</p>"
Set-AdfsGlobalWebContent -PrivacyLink https://alyaconsulting.ch/Home/Privacy -PrivacyLinkText Privacy
Set-AdfsGlobalWebContent -HomeLink https://alyaconsulting.ch/ -HomeLinkText Home
Set-AdfsGlobalWebContent -HelpDeskLink https://alyaconsulting.ch/Home/Support -HelpDeskLinkText Help
