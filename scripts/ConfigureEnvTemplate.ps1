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


    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    14.09.2020 Konrad Brunner       Initial version
#>

[CmdletBinding()]
Param(
)

Write-Host "Loading custom configuration" -ForegroundColor Cyan

<# TENANT SETTINGS #>
$AlyaTenantId = "PleaseSpecify" #Example:"11111111-2222-3333-4444-555555555555"
$AlyaTenantNameId = "PleaseSpecify" #Example:"alyaconsulting"
$AlyaTenantName = "PleaseSpecify" #Example:"$($AlyaTenantNameId).onmicrosoft.com"
$AlyaCompanyName = "PleaseSpecify" #Example:"AlyaConsulting"
$AlyaCompanyNameFull = "PleaseSpecify" #Example:"Alya Consulting Inh. Konrad Brunner"
$AlyaCompanyNameShort = "PleaseSpecify" #Example:"alya"
$AlyaCompanyNameShortM365 = $AlyaCompanyNameShort.ToUpper()
$AlyaDomainName = "PleaseSpecify" #Example:"alyaconsulting.ch"
$AlyaAdditionalDomainNames = @()
$AlyaLocalDomainName = "PleaseSpecify" #Example:"alyaconsulting.ch"
$AlyaEnvName = "PleaseSpecify" #Example:"$($AlyaCompanyNameShort)1stp"
$AlyaEnvNameTest = "PleaseSpecify" #Example:"$($AlyaCompanyNameShort)1stt"
$AlyaSubscriptionName = "PleaseSpecify" #Example:"$($AlyaEnvName)"
$AlyaSubscriptionNameTest = $AlyaSubscriptionName #Example:"$($AlyaEnvNameTest)"
$AlyaNamingPrefix = "PleaseSpecify" #Example:"$($AlyaEnvName)"
$AlyaNamingPrefixTest = "PleaseSpecify" #Example:"$($AlyaEnvNameTest)"
$AlyaAllSubscriptions = @(
    $AlyaSubscriptionName, 
    $AlyaSubscriptionNameTest
)
$AlyaLocation = "PleaseSpecify" #Example:"westeurope"
$AlyaWebPage = "PleaseSpecify" #Example:"https://alyaconsulting.ch"
$AlyaPrivacyUrl = "PleaseSpecify" #Example:"https://alyaconsulting.ch/Home/Privacy"
$AlyaPrivacyEmail = "PleaseSpecify" #Example:"datenschutz@$($AlyaDomainName)"
$AlyaSecurityEmail = "PleaseSpecify" #Example:"security@$($AlyaDomainName)"
$AlyaGeneralInformEmail = "PleaseSpecify" #Example:"cloud@$($AlyaDomainName)"
$AlyaSupportEmail = "PleaseSpecify" #Example:"support@$($AlyaDomainName)"
$AlyaGeneralPhoneNumber = "PleaseSpecify" #Example:"+41625620462"
$AlyaSecurityPhoneNumber = $AlyaGeneralPhoneNumber
$AlyaTimeZone = "PleaseSpecify" #Example:"W. Europe Standard Time"
$AlyaGeoId = "PleaseSpecify" #Example:223
$AlyaDefaultUsageLocation = "PleaseSpecify" #Example:"CH"
$AlyaB2BCompStart = "PleaseSpecify" #Example:"["
$AlyaB2BCompEnd = "PleaseSpecify" #Example:"]"
$AlyaLicenseType = "PleaseSpecify" #Example:"BusinessPremium" #"BusinessBasic","BusinessStandard","BusinessPremium","EnterpriseOE1","EnterpriseOE3","EnterpriseOE5","EnterpriseME3orOE3EMS","EnterpriseME5orOE5EMS"
$AlyaAddLicenses = @() #"M365DefenderP1","SMIME","MsLegacyStore"
$AlyaPasswordResetEnabled = $AlyaLicenseType -in @("BusinessPremium","EnterpriseME3orOE3EMS","EnterpriseME5orOE5EMS")
$AlyaVMLicenseTypeClient = "PleaseSpecify" #Example:"None" #Windows_Client=HybridBenefit, None=PAYG
$AlyaVMLicenseTypeServer = "PleaseSpecify" #Example:"None" #Windows_Server=HybridBenefit, None=PAYG
$AlyaServerOuProd = $null #Example:"OU=PROD,OU=Avd,OU=SERVERS,OU=CLOUD,DC=ALYACONSULTING,DC=LOCAL"
$AlyaServerOuTest = $null #Example:"OU=TEST,OU=Avd,OU=SERVERS,OU=CLOUD,DC=ALYACONSULTING,DC=LOCAL"

<# LOGOS AND BACKGROUNDS #>
$AlyaLogoUrlFavicon = "PleaseSpecify" #Example:"https://alyainfpstrg001.blob.core.windows.net/logos/Favicon.png" # exact 32x32 and max 5KB
$AlyaLogoUrlQuad = "PleaseSpecify" #Example:"https://alyainfpstrg001.blob.core.windows.net/logos/LogoQuad.png" # exact 240x240 and max 50KB
$AlyaLogoUrlQuadDark = "PleaseSpecify" #Example:"https://alyainfpstrg001.blob.core.windows.net/logos/LogoQuadD.png" # exact 240x240 and max 50KB
$AlyaLogoUrlRect = "PleaseSpecify" #Example:"https://alyainfpstrg001.blob.core.windows.net/logos/LogoRect.png" # max 280×60 and max 10KB
$AlyaLogoUrlRectDark = "PleaseSpecify" #Example:"https://alyainfpstrg001.blob.core.windows.net/logos/LogoRectD.png" # max 280×60 and max 10KB
$AlyaLogoUrlLong = "PleaseSpecify" #Example:"https://alyainfpstrg001.blob.core.windows.net/logos/LogoLong.png" # max 560×60 and max 20KB
$AlyaLogoUrlLongDark = "PleaseSpecify" #Example:"https://alyainfpstrg001.blob.core.windows.net/logos/LogoLongD.png" # max 560×60 and max 20KB
$AlyaLoginBackgroundUrl = "PleaseSpecify" #Example:"https://alyainfpstrg001.blob.core.windows.net/backgrounds/CloudLogin.jpg" # exact 1920×1080 and max 300 KB

<# SUPPORT #>
$AlyaSupportTitle = "Alya Support"
$AlyaSupportTel = "+41625620463"
$AlyaSupportMail = "support@alyaconsulting.ch"
$AlyaSupportUrl = "https://alyaconsulting.ch/Home/Support"

<# BRANDING #>
$AlyaAzureBrandingBackgroundColor = "#FFFFFF" # $AlyaSpThemeDef.white
$AlyaAzureBrandingTextColor = "#000000" # $AlyaSpThemeDef.neutralPrimary
$AlyaAzureBrandingPrimaryColor = "#0000FF" # $AlyaSpThemeDef.themePrimary
$AlyaAzureBrandingSignInPageTextDe = "Willkommen in der Microsoft Cloud von '$AlyaCompanyNameFull'"
$AlyaAzureBrandingSignInPageTextEn = "Welcome to the Microsoft Cloud from '$AlyaCompanyNameFull'"
$AlyaAzureBrandingSignInPageTextFr = "Bienvenue dans le cloud Microsoft de '$AlyaCompanyNameFull'"
$AlyaAzureBrandingSignInPageTextIt = "Benvenuti nel cloud Microsoft da '$AlyaCompanyNameFull'"
$AlyaAzureBrandingSignInPageTextDefault = @"
$AlyaAzureBrandingSignInPageTextDe

$AlyaAzureBrandingSignInPageTextEn
"@
$AlyaAzureBrandingUsernameHintTextDe = "vorname.nachname@$AlyaDomainName"
$AlyaAzureBrandingUsernameHintTextEn = "first.last@$AlyaDomainName"
$AlyaAzureBrandingUsernameHintTextFr = "prénom.nomDeFamille@$AlyaDomainName"
$AlyaAzureBrandingUsernameHintTextIt = "nome.cognome@$AlyaDomainName"
$AlyaAzureBrandingUsernameHintTextDefault = "vorname.nachname@$AlyaDomainName"
$AlyaAzureBrandingBackgroundImage = $AlyaLoginBackgroundUrl # exact 1920×1080 and max 300 KB; local file path or url
$AlyaAzureBrandingFavicon = $AlyaLogoUrlFavicon # exact 32x32 and max 5KB; local file path or url
$AlyaAzureBrandingSquareLogo = $AlyaLogoUrlQuad # exact 240x240 and max 50KB; local file path or url
$AlyaAzureBrandingSquareLogoDark = $AlyaLogoUrlQuadDark # exact 240x240 and max 50KB; local file path or url
$AlyaAzureBrandingBannerLogo = $AlyaLogoUrlLong # max 280×60 and max 10KB; local file path or url

<# RESOURCE IDS #>
$AlyaResIdMainNetwork = "PleaseSpecify" #Example:"000"
$AlyaResIdMainInfra = "PleaseSpecify" #Example:"001"
$AlyaResIdAuditing = "PleaseSpecify" #Example:"002"
$AlyaResIdAutomation = "PleaseSpecify" #Example:"003"
$AlyaResIdAdResGrp = "PleaseSpecify" #Example:"005"
$AlyaResIdJumpHostResGrp = "PleaseSpecify" #Example:"010"
$AlyaResIdWebSiteResGrp = "PleaseSpecify" #Example:"011"
$AlyaResIdLetsEncryptResGrp = "PleaseSpecify" #Example:"012"
$AlyaResIdWormResGrp = "PleaseSpecify" #Example:"015"
$AlyaResIdItsmResGrp = "PleaseSpecify" #Example:"016"
$AlyaResIdZefixResGrp = "PleaseSpecify" #Example:"021"
$AlyaResIdAvdImageResGrp = "PleaseSpecify" #Example:"040"
$AlyaResIdLogAnalytics = "PleaseSpecify" #Example:"002"
$AlyaResIdVirtualNetwork = "PleaseSpecify" #Example:"000"
$AlyaResIdMainKeyVault = "PleaseSpecify" #Example:"001"
$AlyaResIdDiagnosticStorage = "PleaseSpecify" #Example:"003"
$AlyaResIdAuditStorage = "PleaseSpecify" #Example:"002"
$AlyaResIdPublicStorage = "PleaseSpecify" #Example:"001"
$AlyaResIdPrivateStorage = "PleaseSpecify" #Example:"004"
$AlyaResIdWormStorage = "PleaseSpecify" #Example:"015"
$AlyaResIdZefixStorage = "PleaseSpecify" #Example:"021"
$AlyaResIdItsmStorage = "PleaseSpecify" #Example:"016"
$AlyaResIdRecoveryVault = "PleaseSpecify" #Example:"001"
$AlyaResIdAutomationAccount = "PleaseSpecify" #Example:"001"
$AlyaResIdWormFunctionApp = "PleaseSpecify" #Example:"015"
$AlyaResIdItsmFuncApp = "PleaseSpecify" #Example:"016"
$AlyaResIdZefixFunctionApp = "PleaseSpecify" #Example:"021"
$AlyaResIdAdSrv1 = "PleaseSpecify" #Example:"001"
$AlyaResIdAdSrv2 = "PleaseSpecify" #Example:"002"
$AlyaResIdForwarderSrv = "PleaseSpecify" #Example:"003"
$AlyaResIdAdminCenterSrv = "PleaseSpecify" #Example:"004"
$AlyaResIdAdSNet = "PleaseSpecify" #Example:"04"
$AlyaResIdJumpHost = "PleaseSpecify" #Example:"010"
$AlyaResIdJumpHostSNet = "PleaseSpecify" #Example:"05"
$AlyaResIdVpnGateway = "PleaseSpecify" #Example:"001"
$AlyaResIdAvdImageClient = "PleaseSpecify" #Example:"041"
$AlyaResIdAvdImageServer = "PleaseSpecify" #Example:"042"
$AlyaResIdAvdImageSNet = "PleaseSpecify" #Example:"05"
$AlyaResIdAvdHostSNet = "PleaseSpecify" #Example:"01"

<# RESOURCE SETTINGS #>
$AlyaResEnableInsightsAndAlerts = $false

<# SHARING SETTINGS #>
$AlyaSharingPolicy = "PleaseSpecify" #Example:"KnownAccountsOnly" #  # None(Disabled), AdminOnly(ExistingExternalUserSharingOnly), KnownAccountsOnly(ExternalUserSharingOnly), ByLink(ExternalUserAndGuestSharing)
$AlyaOnlyEmailVerifiedUsers = "PleaseSpecify" #Example:$true
$AlyaFullTrustCrossTenantDirectConnectAccess = $null #@(@{Name = "Alya Consulting";Id = "5757de31-29c4-4f39-9bd1-478cec348035"})

<# APPLICATION SETTINGS #>
$AlyaAllowUsersToCreateLOBApps = "PleaseSpecify" #Example:$false

<# JUMP HOST SETTINGS #>
$AlyaJumpHostSKU = "PleaseSpecify" #Example:"Standard_D2s_v3"
$AlyaJumpHostAcceleratedNetworking = "PleaseSpecify" #Example:$false
$AlyaJumpHostEdition = "PleaseSpecify" #Example:"2019-Datacenter"
$AlyaJumpHostBackupEnabled = "PleaseSpecify" #Example:$false
$AlyaJumpHostStartTime = "PleaseSpecify" #Example:$null
$AlyaJumpHostStopTime = "PleaseSpecify" #Example:"20:00"
$AlyaJumpHostBackupPolicy = "PleaseSpecify" #Example:"NightlyPolicy"

<# GROUP SETTINGS #>
$AlyaMfaDisabledGroupName = "PleaseSpecify" #Example:"$($AlyaCompanyNameShortM365)SG-ADM-MFADISABLED"
$AlyaMfaEnabledGroupName = $null #Example:"$($AlyaCompanyNameShortM365)SG-ADM-MFAENABLED"
$AlyaSsprEnabledGroupName = "PleaseSpecify" #Example:"$($AlyaCompanyNameShortM365)SG-ADM-SSPRENABLED"
$AlyaPwdResetDisabledGroupName = "PleaseSpecify" #Example:"$($AlyaCompanyNameShortM365)SG-ADM-PWDCHNGDISABLED"
$AlyaMfaDisabledForGroups = "PleaseSpecify" #Example:@("$($AlyaCompanyNameShortM365)MG-ADM-AlleExternen")
$AlyaAllInternals = "PleaseSpecify" #Example:"$($AlyaCompanyNameShortM365)MG-ADM-AlleInternen"
$AlyaAllExternals = "PleaseSpecify" #Example:"$($AlyaCompanyNameShortM365)MG-ADM-AlleExternen"

<# NETWORK SETTINGS #>
$AlyaAzureNetwork = "PleaseSpecify" #Example:"172.16.0.0/16"
$AlyaProdNetwork = "PleaseSpecify" #Example:"172.16.72.0/24"
$AlyaTestNetwork = "PleaseSpecify" #Example:"172.16.172.0/24"
$AlyaSubnetPrefixLength = "PleaseSpecify" #Example:26
$AlyaGatewayPrefixLength = "PleaseSpecify" #Example:28
$AlyaDeployGateway = "PleaseSpecify" #Example:$false

<# AVD SETTINGS #>
<#
$AlyaAvdRDBroker = "PleaseSpecify" #Example:"https://rdbroker.wvd.microsoft.com"
$AlyaAvdShareServer = "PleaseSpecify" # TODO from vars
$AlyaAvdShareRoot = "PleaseSpecify"
$AlyaAvdDomainAdminUPN = "PleaseSpecify" #Example:@("konrad.brunner@$($AlyaDomainName)")
$AlyaAvdOuProd = "PleaseSpecify" #Example:"OU=PROD,OU=Avd,OU=COMPUTERS,OU=CLOUD,DC=ALYACONSULTING,DC=LOCAL"
$AlyaAvdOuTest = "PleaseSpecify" #Example:"OU=TEST,OU=Avd,OU=COMPUTERS,OU=CLOUD,DC=ALYACONSULTING,DC=LOCAL"
$AlyaAvdAdmins = "PleaseSpecify" #Example:@("konrad.brunner@$($AlyaDomainName)")
$AlyaAvdStartTime = "PleaseSpecify" #Example:"06:00"
$AlyaAvdStopTime = "PleaseSpecify" #Example:"23:00"
#>

<# SHAREPOINT ONPREM SETTINGS #>
$AlyaSharePointOnPremMySiteUrl = "PleaseSpecify" #Example:"https://mysite.$($AlyaLocalDomainName)"
$AlyaSharePointOnPremClaimPrefix = "PleaseSpecify" #Example:"w:"
$AlyaSharePointOnPremVersion = "PleaseSpecify" #Example:"2019"

<# SHAREPOINT SETTINGS #>
$AlyaSharePointUrl = "https://$($AlyaTenantNameId).sharepoint.com"
$AlyaSharePointAdminUrl = "https://$($AlyaTenantNameId)-admin.sharepoint.com"
$AlyaSharePointNewSiteOwner = "PleaseSpecify" #Example:"konrad.brunner@$($AlyaDomainName)"
$AlyaSharePointNewSiteAdditionalOwner = "PleaseSpecify" #Example:"konrad.brunner@$($AlyaDomainName)"
$AlyaSharePointNewSiteCollectionAdmins = @( $AlyaSharePointNewSiteOwner, $AlyaSharePointNewSiteAdditionalOwner )
#https://fabricweb.z5.web.core.windows.net/pr-deploy-site/refs/heads/7.0/theming-designer/index.html
$AlyaSpThemeDef = @{ 
    "themePrimary" = "#000000";
    "themeLighterAlt" = "#898989";
    "themeLighter" = "#737373";
    "themeLight" = "#595959";
    "themeTertiary" = "#373737";
    "themeSecondary" = "#2f2f2f";
    "themeDarkAlt" = "#252525";
    "themeDark" = "#151515";
    "themeDarker" = "#0b0b0b";
    "neutralLighterAlt" = "#faf9f8";
    "neutralLighter" = "#f3f2f1";
    "neutralLight" = "#edebe9";
    "neutralQuaternaryAlt" = "#e1dfdd";
    "neutralQuaternary" = "#d0d0d0";
    "neutralTertiaryAlt" = "#c8c6c4";
    "neutralTertiary" = "#595959";
    "neutralSecondary" = "#373737";
    "neutralPrimaryAlt" = "#2f2f2f";
    "neutralPrimary" = "#000000";
    "neutralDark" = "#151515";
    "black" = "#0b0b0b";
    "white" = "#ffffff";
}

<# TEAMS SETTINGS #>
$AlyaTeamsNewTeamOwner = $AlyaSharePointNewSiteOwner
$AlyaTeamsNewTeamAdditionalOwner = $AlyaSharePointNewSiteAdditionalOwner
$AlyaTeamsNewAdmins = $AlyaSharePointNewSiteCollectionAdmins

<# OFFICE GROUP SETTINGS #>
$AlyaGroupManagerGroupName = "PleaseSpecify" #Example:"$($AlyaCompanyNameShortM365)SG-ADM-M365GROUPMANAGERS" # Only members can create groups
#TODO $AlyaGroupManagerMembers = @()
$AlyaOfficeGroupsNewGroupOwner = $AlyaSharePointNewSiteOwner
$AlyaOfficeGroupsNewGroupAdditionalOwner = $AlyaSharePointNewSiteOwner

<# AIP SETTINGS #>
$AlyaAipApiServiceLocation = "PleaseSpecify" #Example:
$AlyaAipOnboardingPolicy = 0 # 0=norestriction 1=onlyLicenseUser else group name to use
$AlyaAipCustomPageUrl = "PleaseSpecify"

<# INTUNE SETTINGS #>
$AlyaDeviceCategories = @("Standard")
$AlyaDeviceAdminsGroupName = "PleaseSpecify" # Only these members can manage devices #Example:"$($AlyaCompanyNameShortM365)SG-DEV-ADMINS"
$AlyaAllowDeviceRegistration = "PleaseSpecify" # All, None or a group name
$AlyaWinPEBackgroundJpgImage = "PleaseSpecify"
$AlyaDesktopBackgroundUrl = "PleaseSpecify"
$AlyaLockScreenBackgroundUrl = "PleaseSpecify"
$AlyaWelcomeScreenBackgroundUrl = "PleaseSpecify"
$AlyaAppPrefix = "WIN"

<# WORM BACKUP SETTINGS #>
$AlyaWormStorageAccountName = "PleaseSpecify"
$AlyaWormCreateBackupWebHookUrl = "PleaseSpecify"
$AlyaWormDoneBackupWebHookUrl = "PleaseSpecify"
$AlyaWormStartMergingWebHookUrl = "PleaseSpecify"
$AlyaWormSasTokenContainer = "PleaseSpecify"
$AlyaWormSasTokenBlob = "PleaseSpecify"

<# ORDER CATALOG SETTINGS #>
$AlyaOrderEmailCustomer = "PleaseSpecify"
$AlyaOrderEmailAlya = "PleaseSpecify"

<# PSTN SETTINGS #>
$AlyaPstnGateway = "PleaseSpecify" #Example:"pstn.provider.ch"
$AlyaPstnPort = "PleaseSpecify" #Example:"5080"
$AlyaPstnPolicyName = "PleaseSpecify" #Example:"ProviderName"

<# COLORS #>
$CommandInfo = "Cyan"
$CommandSuccess = "Green"
$CommandError = "Red"
$CommandWarning = "Yellow"
$AlyaColor = "White"
$TitleColor = "Green"
$MenuColor = "Magenta"
$QuestionColor = "Magenta"
