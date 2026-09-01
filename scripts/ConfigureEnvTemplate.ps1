#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2026

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
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
    06.02.2026 Konrad Brunner       Added powershell documentation
    14.09.2020 Konrad Brunner       Initial version
#>

<#
.SYNOPSIS
Initializes and defines environment-specific configuration variables for Alya Consulting’s base configuration setup.

.DESCRIPTION
The ConfigureEnvTemplate.ps1 script provides a template for defining environment variables used across Alya Consulting’s cloud and on-premises automation setup. It includes placeholders for tenant, branding, resource, security, networking, and service-specific configurations. This script acts as a foundation for tailoring deployments to organization-specific requirements and Azure/Microsoft 365 environments. Users are expected to replace "PleaseSpecify" placeholders with actual configuration values before executing the configuration scripts that rely on these definitions.

.INPUTS
None. All configuration details are statically defined within the script.

.OUTPUTS
The script outputs an informational message to the console indicating that the custom configuration is being loaded.

.EXAMPLE
PS> .\ConfigureEnvTemplate.ps1
Displays "Loading custom configuration XXX" and initializes all configuration variables for the environment.

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
)

Write-Host "Loading custom configuration XXX" -ForegroundColor Cyan

<# ENVIRONMENT SETTINGS #>
#$AlyaAzureEnvironment = "AzureChinaCloud"
#$AlyaPnpEnvironment = "China"
#$AlyaGraphEnvironment = "China"
#$AlyaExchangeEnvironment = "O365China"
#$AlyaSharePointEnvironment = "China"
#$AlyaTeamsEnvironment = "TeamsChina"
#$AlyaGraphAppId = "PleaseSpecify"
#$AlyaGraphEndpoint = "https://microsoftgraph.chinacloudapi.cn"
#$AlyaADGraphEndpoint = "https://graph.chinacloudapi.cn"
#$AlyaOpenIDEndpoint = "https://login.chinacloudapi.cn"
#$AlyaLoginEndpoint = "https://login.partner.microsoftonline.cn"
#$AlyaM365AdminPortalRoot = "https://portal.partner.microsoftonline.cn/AdminPortal"

<# TENANT SETTINGS #>
$AdminUserName = "PleaseSpecify" #Example:"konrad.brunner@alyaconsulting.ch"
$AlyaTenantId = "PleaseSpecify" #Example:"11111111-2222-3333-4444-555555555555"
$AlyaTenantNameId = "PleaseSpecify" #Example:"alyaconsulting"
$AlyaTenantName = "PleaseSpecify" #Example:"$($AlyaTenantNameId).onmicrosoft.com"
$AlyaCompanyName = "PleaseSpecify" #Example:"AlyaConsulting"
$AlyaCompanyNameFull = "PleaseSpecify" #Example:"Alya Consulting Inh. Konrad Brunner"
$AlyaCompanyNameShort = "PleaseSpecify".ToLower() #Example:"alya"
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
$AlyaLocation = "PleaseSpecify" #Example:"switzerlandnorth"
$AlyaWebPage = "PleaseSpecify" #Example:"https://alyaconsulting.ch"
$AlyaPrivacyUrl = "PleaseSpecify" #Example:"https://alyaconsulting.ch/Home/Privacy"
$AlyaPrivacyEmail = "PleaseSpecify" #Example:"cloud.privacy@$($AlyaDomainName)"
$AlyaSecurityEmail = "PleaseSpecify" #Example:"cloud.security@$($AlyaDomainName)"
$AlyaGeneralInformEmail = "PleaseSpecify" #Example:"cloud.general@$($AlyaDomainName)"
$AlyaSupportEmail = "PleaseSpecify" #Example:"cloud.support@$($AlyaDomainName)"
$AlyaGeneralPhoneNumber = "PleaseSpecify" #Example:"+41625620462"
$AlyaSecurityPhoneNumber = $AlyaGeneralPhoneNumber
$AlyaTimeZone = "PleaseSpecify" #Example:"W. Europe Standard Time"
$AlyaGeoId = "PleaseSpecify" #Example:223
$AlyaDefaultUsageLocation = "PleaseSpecify" #Example:"CH"
$AlyaB2BCompStart = "PleaseSpecify" #Example:"["
$AlyaB2BCompEnd = "PleaseSpecify" #Example:"]"
$AlyaLicenseType = "PleaseSpecify" #Example:"BusinessPremium" #"BusinessBasic","BusinessStandard","BusinessPremium","EnterpriseOE1","EnterpriseOE3","EnterpriseOE5","EnterpriseME3orOE3EMSorA3","EnterpriseME5orOE5EMS"
$AlyaAddLicenses = @() #"M365DefenderP1","SMIME","MsLegacyStore"
$AlyaPasswordResetEnabled = $AlyaLicenseType -in @("BusinessPremium","EnterpriseME3orOE3EMSorA3","EnterpriseME5orOE5EMS")
$AlyaVMLicenseTypeClient = "PleaseSpecify" #Example:"None" #Windows_Client=HybridBenefit, None=PAYG
$AlyaVMLicenseTypeServer = "PleaseSpecify" #Example:"None" #Windows_Server=HybridBenefit, None=PAYG
$AlyaServerOuProd = $null #Example:"OU=PROD,OU=Avd,OU=SERVERS,OU=CLOUD,DC=ALYACONSULTING,DC=LOCAL"
$AlyaServerOuTest = $null #Example:"OU=TEST,OU=Avd,OU=SERVERS,OU=CLOUD,DC=ALYACONSULTING,DC=LOCAL"
$AlyaTokenLifetimeMFA = 30
$AlyaTokenLifetimeAUTH = 30
$AlyaMacPackageInstallCertName = "AlyaConsulting"

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
$AlyaSupportActive = $true
$AlyaMaintenanceActive = $true

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
$AlyaAzureBrandingBackgroundImage = $AlyaLoginBackgroundUrl # exact 1920x1080 and max 300 KB; local file path or url
$AlyaAzureBrandingFavicon = $AlyaLogoUrlFavicon # exact 32x32 and max 5KB; local file path or url
$AlyaAzureBrandingSquareLogo = $AlyaLogoUrlQuad # exact 240x240 and max 50KB; local file path or url
$AlyaAzureBrandingSquareLogoDark = $AlyaLogoUrlQuadDark # exact 240x240 and max 50KB; local file path or url
$AlyaAzureBrandingBannerLogo = $AlyaLogoUrlRect # max 280x60 and max 10KB; local file path or url

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
$AlyaResIdAvdImageResGrp = "PleaseSpecify" #Example:"050"
$AlyaResIdAvdManagementResGrp = "PleaseSpecify" #Example:"040"
$AlyaResIdLogAnalytics = "PleaseSpecify" #Example:"002"
$AlyaResIdVirtualNetwork = "PleaseSpecify" #Example:"000"
$AlyaResIdMainKeyVault = "PleaseSpecify" #Example:"001"
$AlyaResIdCommunicationService = "PleaseSpecify" #Example:"001"
$AlyaResIdCommunicationEmailService = "PleaseSpecify" #Example:"001"
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
$AlyaResIdAvdSessionHostsResGrp = "PleaseSpecify" #Example:"060"
$AlyaResIdAvdWorkspace = "PleaseSpecify" #Example:"001"
$AlyaResIdAvdHostpool = "PleaseSpecify" #Example:"001"
$AlyaResIdAvdAppGroup = "PleaseSpecify" #Example:"001"
$AlyaResIdAvdImageClient = "PleaseSpecify" #Example:"051"
$AlyaResIdAvdImageServer = "PleaseSpecify" #Example:"52"
$AlyaAvdResIdVirtualNetwork = $AlyaResIdVirtualNetwork
$AlyaAvdResIdVirtualNetworkTest = $AlyaResIdVirtualNetwork
$AlyaResIdAvdHostSNetTest = "PleaseSpecify" #Example:"04"

<# RESOURCE SETTINGS #>
$AlyaResEnableInsightsAndAlerts = $false
$AlyaAuditLogsRetentionYears = 2

<# SHARING SETTINGS #>
$AlyaSharingPolicy = "PleaseSpecify" #Example:"KnownAccountsOnly" #None(Disabled), AdminOnly(ExistingExternalUserSharingOnly), KnownAccountsOnly(ExternalUserSharingOnly), ByLink(ExternalUserAndGuestSharing)
$AlyaAllowEmailVerifiedUsers = "PleaseSpecify" #Example:$true
$AlyaFullTrustCrossTenantAccess = @( 
    <#@{ Name = "Alya Consulting"; TenantId = "5757de31-29c4-4f39-9bd1-478cec348035";
        EnableCollaboration = $true; EnableDirectConnect = $true; 
        IsMfaAccepted = $true; IsCompliantDeviceAccepted = $false; IsHybridAzureADJoinedDeviceAccepted = $false;
        AllowUsersSync = $false; AutomaticRedemption = $false }#>
)

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

<# SECURITY SETTINGS #>
$AlyaBreakingGlassUserName = "PleaseSpecify" #Example:"john.doe@$($AlyaDomainName)"

<# GROUP SETTINGS #>
$AlyaNoMfaDefaultsGroupName = "PleaseSpecify" #Example:"$($AlyaCompanyNameShortM365)SG-ADM-NOMFADEFAULTS"
$AlyaMfaDisabledGroupName = "PleaseSpecify" #Example:"$($AlyaCompanyNameShortM365)SG-ADM-MFADISABLED(CLOUD)"
$AlyaMfaDisabledGroupNameOnPrem = "PleaseSpecify" #Example:"$($AlyaCompanyNameShortM365)SG-ADM-MFADISABLEDONPREM"
$AlyaMfaDisabledForGroups = @() #Example:@("$($AlyaCompanyNameShortM365)MG-ADM-AlleExternen")
$AlyaMfaEnabledGroupName = "PleaseSpecify" #Example:"$($AlyaCompanyNameShortM365)SG-ADM-MFAENABLED(CLOUD)"
$AlyaMfaEnabledGroupNameOnPrem = "PleaseSpecify" #Example:"$($AlyaCompanyNameShortM365)SG-ADM-MFAENABLEDONPREM"
$AlyaKeyAuthEnabledGroupName = "$($AlyaCompanyNameShortM365)SG-ADM-KEYENABLED"
$AlyaKeyAuthEnabledKeys = @("de1e552d-db1d-4423-a619-566b625cdc84","90a3ccdf-635c-4729-a248-9b709135078f","0bb43545-fd2c-4185-87dd-feb0b2916ace", "0bb43545-fd2c-4185-87dd-feb0b2916ace", "149a2021-8ef6-4133-96b8-81f8d5b7f1f5", "19083c3d-8383-4b18-bc03-8f1c9ab2fd1b", "19083c3d-8383-4b18-bc03-8f1c9ab2fd1b", "1ac71f64-468d-4fe0-bef1-0e5f2f551f18", "20ac7a17-c814-4833-93fe-539f0d5e3389", "24673149-6c86-42e7-98d9-433fb5b73296", "2fc0579f-8113-47ea-b116-bb5a8db9202a", "34744913-4f57-4e6e-a527-e9ec3c4b94e6", "3a662962-c6d4-4023-bebb-98ae92e78e20", "3b24bf49-1d45-4484-a917-13175df0867b", "4599062e-6926-4fe7-9566-9e8fb1aedaa0", "47ab2fb4-66ac-4184-9ae1-86be814012d5", "57f7de54-c807-4eab-b1c6-1c9be7984e92", "6ab56fad-881f-4a43-acb2-0be065924522", "6d44ba9b-f6ec-2e49-b930-0c8fe920cb73", "6ec5cff2-a0f9-4169-945b-f33b563f7b99", "72c6b72d-8512-4c66-8359-9d3d10d9222f", "73bb0cd4-e502-49b8-9c6f-b59445bf720b", "7409272d-1ff9-4e10-9fc9-ac0019c124fd", "79f3c8ba-9e35-484b-8f47-53a5a0f5c630", "7b96457d-e3cd-432b-9ceb-c9fdd7ef7432", "7d1351a6-e097-4852-b8bf-c9ac5c9ce4a3", "83c47309-aabb-4108-8470-8be838b573cb", "85203421-48f9-4355-9bc8-8a53846e5083", "8c39ee86-7f9a-4a95-9ba3-f6b097e5c2ee", "905b4cb4-ed6f-4da9-92fc-45e0d4e9b5c7", "90636e1f-ef82-43bf-bdcf-5255f139d12f", "97e6a830-c952-4740-95fc-7c78dc97ce47", "9ff4cc65-6154-4fff-ba09-9e2af7882ad2", "a02167b9-ae71-4ac7-9a07-06432ebb6f1c", "a25342c0-3cdc-4414-8e46-f4807fca511c", "a25342c0-3cdc-4414-8e46-f4807fca511c", "a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa", "ad08c78a-4e41-49b9-86a2-ac15b06899e2", "b7d3f68e-88a6-471e-9ecf-2df26d041ede", "b90e7dc1-316e-4fee-a25a-56a666a670fe", "b92c3f9a-c014-4056-887f-140a2501163b", "c1f9a0bc-1dd2-404a-b27f-8e29047a43fd", "c5ef55ff-ad9a-4b9f-b580-adebafe026d0", "cb69481e-8ff7-4039-93ec-0a2729a154a8", "d7781e5d-e353-46aa-afe2-3ca49f13332a", "d8522d9f-575b-4866-88a9-ba99fa02f35b", "dd86a2da-86a0-4cbe-b462-4bd31f57bc6f", "e77e3c64-05e3-428b-8824-0cbeb04b829d", "ed042a3a-4b22-4455-bb69-a267b652ae7e", "ee882879-721c-4913-9775-3dfcce97072a", "f8a011f3-8c0a-4d15-8006-17111f9edc7d", "fa2b99dc-9e39-4257-8f92-4a30d23c4118", "fcc0118f-cd45-435b-8da1-9782b2da0715") # All yubikeys
$AlyaSsprEnabledGroupName = "PleaseSpecify" #Example:"$($AlyaCompanyNameShortM365)SG-ADM-SSPRENABLED"
$AlyaPwdResetDisabledGroupName = "PleaseSpecify" #Example:"$($AlyaCompanyNameShortM365)SG-ADM-PWDCHNGDISABLED"
$AlyaAllInternals = "PleaseSpecify" #Example:"$($AlyaCompanyNameShortM365)MG-ADM-AlleInternen"
$AlyaAllExternals = "PleaseSpecify" #Example:"$($AlyaCompanyNameShortM365)MG-ADM-AlleExternen"

<# OFFICE GROUP SETTINGS #>
$AlyaGroupManagerGroupName = "PleaseSpecify" #Example:"$($AlyaCompanyNameShortM365)SG-ADM-M365GROUPMANAGERS(CLOUD)" # Only members can create groups
$AlyaGroupManagerGroupNameOnPrem = "PleaseSpecify" #Example:"$($AlyaCompanyNameShortM365)SG-ADM-M365GROUPMANAGERSONPREM" # Only members can create groups
$AlyaOfficeGroupsNewGroupOwner = "PleaseSpecify" #Example:"konrad.brunner@$($AlyaDomainName)"
$AlyaOfficeGroupsNewGroupAdditionalOwner = "PleaseSpecify" #Example:"konrad.brunner@$($AlyaDomainName)"

<# NETWORK SETTINGS #>
$AlyaAzureNetwork = "PleaseSpecify" #Example:"172.16.0.0/16"
$AlyaProdNetwork = "PleaseSpecify" #Example:"172.16.72.0/24"
$AlyaTestNetwork = "PleaseSpecify" #Example:"172.16.172.0/24"
$AlyaSubnetPrefixLength = "PleaseSpecify" #Example:26
$AlyaGatewayPrefixLength = "PleaseSpecify" #Example:28
$AlyaDeployVPNGateway = "PleaseSpecify" #Example:$true
$AlyaDeployNATGateway = "PleaseSpecify" #Example:$true
$AlyaVPNGatewayClientCertCount = "PleaseSpecify" #Example:10
$AlyaVPNGatewayClientIpRange = "PleaseSpecify" #Example:"172.173.174.0/24"
$AlyaVPNGatewayClientCertCount = "PleaseSpecify" #Example:10

<# AVD SETTINGS #>
<#
$AlyaAvdRDBroker = "PleaseSpecify" #Example:"https://rdbroker.wvd.microsoft.com"
$AlyaAvdShareServer = "PleaseSpecify"
$AlyaAvdShareRoot = "PleaseSpecify"
$AlyaAvdDomainAdminUPN = "PleaseSpecify" #Example:@("konrad.brunner@$($AlyaDomainName)")
$AlyaAvdOuProd = "PleaseSpecify" #Example:"OU=PROD,OU=Avd,OU=COMPUTERS,OU=CLOUD,DC=ALYACONSULTING,DC=LOCAL"
$AlyaAvdOuTest = "PleaseSpecify" #Example:"OU=TEST,OU=Avd,OU=COMPUTERS,OU=CLOUD,DC=ALYACONSULTING,DC=LOCAL"
$AlyaAvdAdmins = "PleaseSpecify" #Example:@("konrad.brunner@$($AlyaDomainName)")
$AlyaAvdStartTime = "PleaseSpecify" #Example:"06:00"
$AlyaAvdStopTime = "PleaseSpecify" #Example:"23:00"
$AlyaAvdHypervisorVersion = "PleaseSpecify" #Example:"V2"
$AlyaAvdSessionHostCount = "PleaseSpecify" #Example:4
$AlyaAvdSessionHostCountTest = "PleaseSpecify" #Example:1
$AlyaAvdMaxSessions = "PleaseSpecify" #Example:8
$AlyaAvdVmSize = "PleaseSpecify" #Example:"Standard_D8s_v4"
$AlyaAvdAcceleratedNetworking = "PleaseSpecify" #Example:$true
$AlyaAvdSessionHostLocation = "PleaseSpecify" #Example:$AlyaLocation
$AlyaAvdDesktopAccessGroup = "PleaseSpecify" #Example:"ALYASG-APP-DSKTP-P"
$AlyaAvdDesktopAccessGroupTest = "PleaseSpecify" #Example:"ALYASG-APP-DSKTP-T"
#>

<# SHAREPOINT ONPREM SETTINGS #>
$AlyaSharePointOnPremMySiteUrl = "PleaseSpecify" #Example:"https://mysite.$($AlyaLocalDomainName)"
$AlyaSharePointOnPremClaimPrefix = "PleaseSpecify" #Example:"w:"
$AlyaSharePointOnPremVersion = "PleaseSpecify" #Example:"2019"

<# SHAREPOINT SETTINGS #>
$AlyaPnPAppId = "PleaseSpecify"
$AlyaSharePointUrl = "https://$($AlyaTenantNameId).sharepoint.com"
$AlyaSharePointAdminUrl = "https://$($AlyaTenantNameId)-admin.sharepoint.com"
$AlyaSharePointNewSiteOwner = $AlyaOfficeGroupsNewGroupOwner
$AlyaSharePointNewSiteAdditionalOwner = $AlyaOfficeGroupsNewGroupAdditionalOwner
$AlyaSharePointNewSiteCollectionAdmins = @( $AlyaSharePointNewSiteOwner, $AlyaSharePointNewSiteAdditionalOwner )
#https://fabricweb.z5.web.core.windows.net/pr-deploy-site/refs/heads/7.0/theming-designer/index.html
$AlyaSpThemeDef = @{ 
    "themePrimary" = "#000000"
    "themeLighterAlt" = "#898989"
    "themeLighter" = "#737373"
    "themeLight" = "#595959"
    "themeTertiary" = "#373737"
    "themeSecondary" = "#2f2f2f"
    "themeDarkAlt" = "#252525"
    "themeDark" = "#151515"
    "themeDarker" = "#0b0b0b"
    "neutralLighterAlt" = "#faf9f8"
    "neutralLighter" = "#f3f2f1"
    "neutralLight" = "#edebe9"
    "neutralQuaternaryAlt" = "#e1dfdd"
    "neutralQuaternary" = "#d0d0d0"
    "neutralTertiaryAlt" = "#c8c6c4"
    "neutralTertiary" = "#595959"
    "neutralSecondary" = "#373737"
    "neutralPrimaryAlt" = "#2f2f2f"
    "neutralPrimary" = "#000000"
    "neutralDark" = "#151515"
    "black" = "#0b0b0b"
    "white" = "#ffffff"
}

<# TEAMS SETTINGS #>
$AlyaTeamsNewTeamOwner = $AlyaSharePointNewSiteOwner
$AlyaTeamsNewTeamAdditionalOwner = $AlyaSharePointNewSiteAdditionalOwner
$AlyaTeamsNewAdmins = $AlyaSharePointNewSiteCollectionAdmins

<# POWERPLATTFORM SETTINGS #>
$AlyaDataGatewayAppId = "PleaseSpecify"
$AlyaDataGatewayAppKeyVault = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"
$AlyaDataGatewayAppKeySecretName = "AlyaDataGatewayAppKeySecret"
$AlyaDataGatewayAppCertificateSecretName = "PleaseSpecify"

<# AIP SETTINGS #>
$AlyaAipAppId = "PleaseSpecify"
$AlyaAipApiServiceLocation = "PleaseSpecify"
$AlyaAipOnboardingPolicy = 0 # 0=norestriction 1=onlyLicenseUser else group name to use
$AlyaAipCustomPageUrl = "PleaseSpecify"

<# INTUNE SETTINGS #>
$AlyaDeviceCategories = @("Standard")
$AlyaDeviceAdminsGroupName = "PleaseSpecify" # Only these members can manage devices #Example:"$($AlyaCompanyNameShortM365)SG-DEV-ADMINS"
$AlyaDeviceAdminsGroupNameOnPrem = "PleaseSpecify"
$AlyaAllowDeviceRegistration = "PleaseSpecify" # All, None or a group name or an array of groups @()
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
$AlyaWormReportLocalsWebHookUrl = "PleaseSpecify"
$AlyaWormReportLocalsMissingWebHookUrl = "PleaseSpecify"

<# ORDER CATALOG SETTINGS #>
$AlyaOrderEmailCustomer = "PleaseSpecify"
$AlyaOrderEmailAlya = "PleaseSpecify"

<# PSTN SETTINGS #>
$AlyaPstnGateway = "PleaseSpecify" #Example:"pstn.provider.ch"
$AlyaPstnPort = "PleaseSpecify" #Example:"5080"
$AlyaPstnPolicyName = "PleaseSpecify" #Example:"ProviderName"
$AlyaPstnVoiceRouteName = $AlyaPstnPolicyName
$AlyaPstnUsageRecordsName = $AlyaPstnPolicyName
$AlyaPstnVoiceRoutePolicyName = $AlyaPstnPolicyName

<# COLORS #>
$CommandInfo = "Cyan"
$CommandSuccess = "Green"
$CommandError = "Red"
$CommandWarning = "Yellow"
$AlyaColor = "White"
$TitleColor = "Green"
$MenuColor = "Magenta"
$QuestionColor = "Magenta"

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCChNQj4sUi8Cqyg
# G08wOvCy0uY4SiW04l4KkAUYGy/LgqCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
# Qc9vAbjutKlUMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24g
# Um9vdCBDQSAtIFIzMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9i
# YWxTaWduMB4XDTIwMDcyODAwMDAwMFoXDTI5MDMxODAwMDAwMFowUzELMAkGA1UE
# BhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2Jh
# bFNpZ24gQ29kZSBTaWduaW5nIFJvb3QgUjQ1MIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAti3FMN166KuQPQNysDpLmRZhsuX/pWcdNxzlfuyTg6qE9aND
# m5hFirhjV12bAIgEJen4aJJLgthLyUoD86h/ao+KYSe9oUTQ/fU/IsKjT5GNswWy
# KIKRXftZiAULlwbCmPgspzMk7lA6QczwoLB7HU3SqFg4lunf+RuRu4sQLNLHQx2i
# CXShgK975jMKDFlrjrz0q1qXe3+uVfuE8ID+hEzX4rq9xHWhb71hEHREspgH4nSr
# /2jcbCY+6R/l4ASHrTDTDI0DfFW4FnBcJHggJetnZ4iruk40mGtwEd44ytS+ocCc
# 4d8eAgHYO+FnQ4S2z/x0ty+Eo7+6CTc9Z2yxRVwZYatBg/WsHet3DUZHc86/vZWV
# 7Z0riBD++ljop1fhs8+oWukHJZsSxJ6Acj2T3IyU3ztE5iaA/NLDA/CMDNJF1i7n
# j5ie5gTuQm5nfkIWcWLnBPlgxmShtpyBIU4rxm1olIbGmXRzZzF6kfLUjHlufKa7
# fkZvTcWFEivPmiJECKiFN84HYVcGFxIkwMQxc6GYNVdHfhA6RdktpFGQmKmgBzfE
# ZRqqHGsWd/enl+w/GTCZbzH76kCy59LE+snQ8FB2dFn6jW0XMr746X4D9OeHdZrU
# SpEshQMTAitCgPKJajbPyEygzp74y42tFqfT3tWbGKfGkjrxgmPxLg4kZN8CAwEA
# AaOCAXcwggFzMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzAP
# BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQfAL9GgAr8eDm3pbRD2VZQu86WOzAf
# BgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpjmove4t0bvDB6BggrBgEFBQcBAQRuMGww
# LQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL3Jvb3RyMzA7
# BggrBgEFBQcwAoYvaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# cm9vdC1yMy5jcnQwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxz
# aWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggrBgEF
# BQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJ
# KoZIhvcNAQEMBQADggEBAKz3zBWLMHmoHQsoiBkJ1xx//oa9e1ozbg1nDnti2eEY
# XLC9E10dI645UHY3qkT9XwEjWYZWTMytvGQTFDCkIKjgP+icctx+89gMI7qoLao8
# 9uyfhzEHZfU5p1GCdeHyL5f20eFlloNk/qEdUfu1JJv10ndpvIUsXPpYd9Gup7EL
# 4tZ3u6m0NEqpbz308w2VXeb5ekWwJRcxLtv3D2jmgx+p9+XUnZiM02FLL8Mofnre
# kw60faAKbZLEtGY/fadY7qz37MMIAas4/AocqcWXsojICQIZ9lyaGvFNbDDUswar
# AGBIDXirzxetkpNiIHd1bL3IMrTcTevZ38GQlim9wX8wggboMIIE0KADAgECAhB3
# vQ4Ft1kLth1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENv
# ZGUgU2lnbmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAw
# MDBaMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIw
# MAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAy
# MDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj
# /SBerjgSi8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlM
# g7BKRFAEeIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRV
# X5YLEeWatSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV
# 0xHK5s2zBZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEz
# IHXMsdXtHQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMk
# oog28vmfvpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq
# 7rfYrWGlr3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult
# 5a/dm2tjIF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNu
# twFsDeCXpxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYy
# AjIwfLWTyCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofn
# GrhO7izB36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
# FgQUJZ3Q/FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0
# Q9lWULvOljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8v
# b2NzcC5nbG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUH
# MAKGOmh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWdu
# aW5ncm9vdHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJ
# KwYBBAGgMgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24u
# Y29tL3JlcG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJ
# yTm6t6E5iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbV
# YQLFY4/UovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQt
# pFg6bBNJ+KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSX
# hndGKj0jfShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6
# bs+XYXvfcXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nO
# ZNm9/Lws80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOH
# X5OKSBoRHeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dq
# cYC/lt5yA9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0i
# xxnJpsoOqHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7
# qWPLd0jV+mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g6
# 04YfM/tV5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD
# 4ED6gVYDU/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S
# /gJXhZrh0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp
# 8nKmrVa46Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqt
# f2phU7+yR2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJ
# QWTEE/bP0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKX
# vYkPbEdx+QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4
# yMYgcMKb9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmY
# F8T4xO2k6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2
# mMIVpqWCZ1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7
# spNY6rQb3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd
# 2jANBgkqhkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy
# /fAHsVv1RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW
# 2H3Bh6zNXULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0
# MP6pBPKOL6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/
# pFL9zlcctWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcex
# U0bcV0hLQ4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf
# 6AMOGaM56A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzEC
# p9LnR+34c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9m
# UF5qE6YwQqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+Ku
# aJRsz+cnZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/Jl
# N6m6GM1jEhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutof
# dgNBzMUxgiEGMIIhAgIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIL0YcRHi
# BZVJpmCpSbjtlx+L1ty1tzFMzo1Tm9jB8h57MA0GCSqGSIb3DQEBAQUABIICABZ+
# GEUpLxsyrPP9QAt98nyyUnPI/9sD4JzRQBpjAscuji/q4hQa/wX92N9ZRewz/tzS
# DrIREsWoruLZ+o0Z3EYnLTX/uME1DJ5tSFX/xuEFuSxoM8iPwH8KvoUpR71kpI6D
# NCcbz0BvU9y8eZ+MAlUJ9ESt8QgEIdXDXZ3+jEyLS5ZqUd28XR4lT+fr9n7EZhRi
# fNk0yr2rKdrgk3ElKm8Id9as7IfeFyqBQdpWePsYjbiEyIV2A4pydvCiY0ErjKa3
# Gmo37cT2D7SQER6yYhG836Gk5yRmcsfsT/WFTRe17mKHN0637k1j61yBz1/YpIbE
# cOtrp6JlqHQ930uvJ45hrfdHEpBUPomRXb5kkkvZLu0YdIbwk2Gju0aeq+UsB6oy
# O8f6zgbz2BggA2jbKuT/6OGFQ8gJyUE49a5AgGQrV8Rj8dx4lXU5Rx4AQ5CF9l2R
# Dyx/X5NRiHtit8V7kSQw18ZUuUhZDhxz/j/Mg961ZIOfKzmIN7ygkucW1nYD7B+a
# 4UA3UuiQ/qSxnl42+CnPFn2M+MC7T5IiLQBnwXblEWJtLqWYC8RsuvtkKEKgIZbw
# LW4GnVtUwVkxW6yILIVUieXsBP3Rnk2qYt5v8Nu387n0ZZu+sclk3CaALg+YIHfM
# LOu34VgUT9KFbuYF7FQkZLvTX30Y+RjZ91KZFJCHoYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCCJAK2ZacZYY7g8zguJCRT3kE5q5qmzTvk8mtXrJd0FRQIUUr3M
# xGosF9utCE0E+Jod6dNguRIYDzIwMjYwODI5MTU0MzEzWjADAgEBoF2kWzBZMQsw
# CQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMm
# R2xvYmFsc2lnbiBSNDUgVFNBIGZvciBDb2RlU2lnbiAyMDI1MTCgghlgMIIGijCC
# BHKgAwIBAgIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcNAQEMBQAwXjELMAkG
# A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0ds
# b2JhbFNpZ24gT2ZmbGluZSBSNDUgVGltZXN0YW1waW5nIENBIDIwMjUwHhcNMjUx
# MDE1MDcyNTA0WhcNMzcwMTEwMDAwMDAwWjBZMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFsc2lnbiBSNDUgVFNB
# IGZvciBDb2RlU2lnbiAyMDI1MTAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQDRSo2hjYZASCijCQSc2RMQPPKojE/xf4Uija2JnsJ7Snl2gDoxKjQ9HcU6
# rVD8pgy1sBKdVxtLLFhY3gzY/PA2iwIs6ZzCnxshtjShsN1RyzRrzc4Fq+0xQx6q
# ADUMn96mqHE/0ok53DPbmpBkkUDytGM79nQfw9WVymYgA+TkbA0/QOmPNNJIZ6Cj
# X0t3wJfhL0caiXthBBMEWKxT5v2U7ZRbCq/DVDXA9oX1iFVBVaBpx57MLL00nyHu
# x0InYS7Rr54M3tNhm7+0maxpyTFa51uY1PHtTJMup/l3RGooQ5YweCH2hDoUNwKO
# C7QkFbklhPdq27EXkueg8qLOnRDmVO1r+B1yMAbl6QuV0L+OPB1SKBAPpmIFklmJ
# 0SoibbUqxsTzejjdI+ywQLUcXilogwKWsJ46h6wjlU5AVqT7FEBYzWCTt6hf7SLQ
# bPGs02Ba8oaaNfo0SL+aApN94luEB/wuE1lgptrckLzbQlCp56OgkAJYpqYuui+T
# fueCIU0CAwEAAaOCAcYwggHCMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAK
# BggrBgEFBQcDCDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQy+tPhB2gnkGsI0j8d
# PIxlNigGGTAfBgNVHSMEGDAWgBR3AjsBMQ8edHfDSMjDB2NViKU7ojCBpQYIKwYB
# BQUHAQEEgZgwgZUwQgYIKwYBBQUHMAGGNmh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24u
# Y29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNTBPBggrBgEFBQcwAoZDaHR0
# cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NvZmZsaW5lcjQ1dGlt
# ZXN0YW1wY2EyMDI1LmNydDBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLmds
# b2JhbHNpZ24uY29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNS5jcmwwVgYD
# VR0gBE8wTTAIBgZngQwBBAIwQQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0
# dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEB
# DAUAA4ICAQCOrnCmj0eGkYpuniz6/WFm91s6KjnhkMKYlbcftgpMBtlhysVniEOf
# BvhcvoFQw4AOHG9NRVvZpkBnag5Dt1HM3Jg21gRVCBwFyP1ET8IDxoflYx5OD4SC
# NLHs6vCg6rFkNT81v9Zy8u0xXy3WboN5iK/SbTmLGqCrAGJihLLrfIhvddwVrdBy
# iHteLxgjugT6JQogCSoBF2JqmH0ZBCl515btbTuWZLrQUs5vvl2o98Mdju9yyJRW
# LzPVcUkRk9d8xBBi638FBOAuo3fcyThGcne7wUOa+TghhwIHbZ3pxTYpgo5cCxEZ
# sH8EXwiTUTwHf0qesssg/2XdcGH7s0AR4TyOJ2QnAayYOAM/XOBxNzURQg4mhMdP
# L/F8VCMKj3koJaVcx2akh0B82le/aBU8q2Oa++OwOwiHF5e+f9m+yhyYbwGSogWI
# V3hgRl+VyKrch8gv35FHr/cVz8n0/CPGRXGiYJZ7P1wOOgYdkMD2iDKVYQby5Ix/
# xCB0/lSKLnqEoFezfmnCJbGgACVswMsxhJEUjtxEcQc9afalne+IOts0v/yCRikJ
# snmVbS0x50Dk2OH+VCiU9s/XyzgfC7WzrtQ5diIdc2Ksi3JMTJm4a0LiEIZWitD5
# +6PokOkQ8+35TsHOwUhs87I/yyJjlIZpAV4Of1/JN8bWVB3Edm4WzjCCBqAwggSI
# oAMCAQICEQCD2oY3t58MhAyUe4QKUngfMA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNV
# BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9i
# YWxTaWduIFRpbWVzdGFtcGluZyBSb290IFI0NTAeFw0yNTA3MTYwMzA1MDRaFw00
# MTA3MTYwMDAwMDBaMF4xCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTQwMgYDVQQDEytHbG9iYWxTaWduIE9mZmxpbmUgUjQ1IFRpbWVzdGFt
# cGluZyBDQSAyMDI1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApHcW
# +O19i+LdAoZFYzS+5X+WYvnWoFqXAfir1hynhUTdH4RW1Db+yOmrQ275jlsQ6bzo
# Z3nN0CMncZX4E0Qhpp6Qvx27+flpfzeMQacD7VciWUiF3TLiu7wT2bBCSENUn3hf
# GMG4PJvYFvO5o4DA1iNvHhG4oSzctodoJfb4c8EjVahCw/NLizB3ra+NWe2gZBSa
# ZKraMxFt676yqx7RcQnjbF4R0OLGovsZt23vU69A5BdoPxdA9zu9rM+qTBsPDVUJ
# exYwEVU0GY7BJ5mUWWniyAPHW0Wv4Azk5t7I0XUIjA3+2OGkr0dVBXVBDyEeGBVr
# YXEdhfVLwuh6HBGJFdIrEY5KoGlpoT+4BBQe4XCH5sv15Uo+M72VKWjPA5Ex3nfF
# JC4P5FW1SR6olCSaIrtnZzc+zgmpSyiD+GcE2udQRQHbDi74enXgazk0+ktpHZ1Z
# 8oTvSaSIREovXSLbH3KC8uFIkXucl7XPH7ZGIrmF9eF4zuoo5FIUnsvV60kLqFDz
# Pk+UbLmgZDUCPlFFBBehaaNvixEymx9ON2KXev+MfK6OZChqGbrOC2wvvAFHyKlT
# ZbVHdqNiu0u5a2T1C9dSTRny1/hxLwcxL9BWPzQLwhsiyXqUzM7uD0lD9+PYMaxU
# YgoVSxqb4xvPCiVqLNabI+WtjEzYfQ0P+6tBTFsCAwEAAaOCAWIwggFeMA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDASBgNVHRMBAf8ECDAGAQH/
# AgEAMB0GA1UdDgQWBBR3AjsBMQ8edHfDSMjDB2NViKU7ojAfBgNVHSMEGDAWgBRG
# shx34XsV8KU5oXDe0cQu6m2y3jCBjgYIKwYBBQUHAQEEgYEwfzA3BggrBgEFBQcw
# AYYraHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vdGltZXN0YW1wcm9vdHI0NTBE
# BggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# dGltZXN0YW1wcm9vdHI0NS5jcnQwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2Ny
# bC5nbG9iYWxzaWduLmNvbS90aW1lc3RhbXByb290cjQ1LmNybDARBgNVHSAECjAI
# MAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggIBADKj7n7RbuRmMZZYXqlMPRJoR6X1
# n//quXGLVfOpFoR9Ya05L94w0ywBjelyGGf+nAB+CZFQ7gUOd2a2bpfpW8Xw5ArM
# +YjPEf8AtC4E6Yr105U1YNjlTSERoWJKc1hkSN5m4dpsYteFykzFQVwX50hYKH3y
# Z6Vcu6Ha0EA5ofzLpi2jK2jbRDCXbFNLi5mO1xKRdB2AzAF0f5C00b4H3d5sCOB8
# njTvAwaTMGEMeTkLWM4Z9Y+3UOtOpo1QuxXbDpXVkLXraG25iL1VtvjxEAy4534n
# UINB9whORicJJSTLba6fOK2f/1QGWEdewWLHAzE+N5oH0QoNRALpJ5JjIfeInvO+
# sQdBidnPuLKJ95HTj7XyMvJhFZjtbHJGlEWx4UgKcuNKLDLXWALfwQDN2Dey3kTf
# d4yw4nQdk1PctLLK3F4L2nnLv94BMkpY+Rfl53oOEN4yTvtwCYP+VDuZrktc7Nac
# oTVxZnKGkv8a1akckdOwQZC+i8Ay1VyzMAX/Tb4+r3c65B7cpAtq3OoUijXUJgvZ
# xci6TX78smL2TYy2tWn+8G4krnXvy2ELR2XYnKEOS4MVmrSCsjM5nxSrghE10VDX
# QbEfa93lhikfFoIuINKzWDLqvu8ZucmxEufxpHjNnnRVXX/Zv5KQq8pu/MQoOz6D
# C74n5+O5bSwvT5sgMIIGozCCBIugAwIBAgIQeEqqgXNmnJAJVOQhyUfrwDANBgkq
# hkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjET
# MBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMDEy
# MDkwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIFRpbWVzdGFt
# cGluZyBSb290IFI0NTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALp0
# M+wn3BI4IRvF02Eo1lq8T9+LzJGEQyRXvGQhvDscHz1PjK0Ht/PF1wLpERSCmqq0
# lHI7cQ0a72hrhXmOr2bqWJgNusF8edL/zbNvMUXQBXQEAHJqJ364Nz86iO2Xg/Wr
# NU0Pn1k79S/fWcV8pTJ2YJbI7e74BH4ZUXKov0RBerx7HjsAm7y64Ja/kP6Nm8Ny
# iwAS+CA6YDj3wcyFivuHeS6hKyDmy6CFkSO2xCgHVCje7BAxT4ryzRQfHt1VHOoo
# MUz5IWqozfOWZ/oBQZvNDwtof7ve8UPqF+Ww3HAis2k2WXRrxuWJKnzlC4Fdqz+P
# uNF2cvN8oqnil0G/zIxF/mHJ9mwHCwAE6BUjT4IqLfbvw/oRNkih0f16OTo0XaMs
# Dpt3UCA0QN2xAzGtX+lih3OWA2H3lLDZXGxP5xTF4fF7DSOczXCMHWreSi2LKrvb
# QhQFB6r7FNwx0/YfbMu+aGZEcE1tF/lx6wVzjpGSdetoXB72RGEYKWLdF2aI7Ci6
# SW/bPnf+uTEfdRwYoqZHvdjuSIU7/bPiDz8qmMaa+oJvsaWlhh1aOvqkbHQPd1Jh
# an+HKd45m4vus0VgMCSXFRIqhTCTJqyWpi3ocG0LqTKtLJsoCnZC8lVhUZiU3u32
# xRdvPBUQsA6tsN7FFvRl0cwvWlYIz5nE8FWRwix5AgMBAAGjggF4MIIBdDAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDwYDVR0TAQH/BAUwAwEB
# /zAdBgNVHQ4EFgQURrIcd+F7FfClOaFw3tHELuptst4wHwYDVR0jBBgwFoAUrmwF
# o5MT4qLn4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEEbzBtMC4GCCsGAQUFBzABhiJo
# dHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsGAQUFBzAChi9o
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAi0i6Nlc8csXadfnvMvWGvdwSKOOILk82XyaZ7A8BIRCWkjjGcGtt867UDr0l
# 74Z/4omNlaV+KUQDTaqYqPG33OopYyHc7c2ICssQaWF5KUIMI7zpxe9SHi8zN9VP
# ZnpmqUdUM7HdFvLYZHGjMZTlb/ZNS+KEbNDJJWdPyEvQzksF1j37fUH6irHAIeB+
# CLDZZCv56vLHCvTPLgw0YO5su5LwP/F7UhJod1mB9RwupDqMOQMN7eXMr2ZIeWPV
# Sbj/S9IlT0hOkzuTd7CaSGy2oB2zdJ5fvSIEO3w3DYW1w5q73ZxaA420DZ9MdjTV
# ha1Fe7Wfuy6Ju6zIv5JjSMY/yheqDbwAEV+L6ONDhIpDNM39O8Cie9sfuGfIjBXe
# P6Z/xyjvoW9vskHPAiLrAfhLyNJ2byXfXtpoaD17RATCQW5JO6eYVgTt0SYrBJTb
# 5O1mjj2AnaSkVXlQXuP4Gh/AFm+QFTyKpkihDHu6KuCxqYcFRpvtJVU9N2mY7UaZ
# mIVHCh5i2/2c5cFDQo69z2/2jJH9guSf7K3jlVUF80kvbTT3/2fumUC705qAQkDa
# I4lgH4NxkrXp5soK+d3HbLJYQZxmjZsqbx9vVwRDXINdO2mc3jn6hE0183sbbYvx
# bwPBKVLilL97VIvfQHoLcAJ3Py+IBwIAddKvxtYiMhmjO+gwggWDMIIDa6ADAgEC
# Ag5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9i
# YWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
# AxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwx
# IDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9i
# YWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRv
# f+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJ
# f094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcx
# BsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQ
# Bzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5d
# RC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWq
# RfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX8
# 5mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjpl
# llnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R
# /98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFl
# tr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEA
# AaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE
# FK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tyt
# ok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7
# jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh
# 4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR
# 3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6
# fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgb
# KCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglI
# WYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Q
# v4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98
# i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU
# 4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzW
# AtcKZ4MFWsmkEDGCA2EwggNdAgEBMHMwXjELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNpZ24gT2ZmbGluZSBS
# NDUgVGltZXN0YW1waW5nIENBIDIwMjUCEQCEcj/BlcwW8dsrovZg3yvkMAsGCWCG
# SAFlAwQCAqCCAUEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMCsGCSqGSIb3
# DQEJNDEeMBwwCwYJYIZIAWUDBAICoQ0GCSqGSIb3DQEBDAUAMD8GCSqGSIb3DQEJ
# BDEyBDDLYLKh0rw1XZq2wzUHS3NPzFaGbQPKTRXZY8Z7quN4fs7hn93QAEyMbFQa
# d3nEDH0wgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGAeVsp16wuVESGZ+/lfc5VPyatCWji1HJpfGpCsxUATdR6
# t15R/zV2O3/BjERSnWJckkgBb/2sXG92dFpi59NU4H+u6axxHC9OPKakigN4FOZf
# E6YQJP3e2MyUmHF/0rzaK57UX4CvfKS0CNtBA1oIzxXZmvgq2tfumenNhTxs30uD
# O5C+3OxRPw+Gt2yAnDPvvSIZU+yJp+JvOuNhp3jrCzh9NWUqRc8pF8h/UZtiOU5K
# /FSRUddRavdpR+kaZudECLmGv2TujwUwNPD2Co3K4GQUCsBkmSEglYWZGFkvcA9C
# KepLlmUyOJBbXAzSYiFWuXkF62uiGmECwNQ2MeimFAv1AojN4xkUnmLWVwoxp/z1
# uSu78kzkERv3K/MQJQ0hAJLLhliBaTNqGDE8m99sUnLuX8V9oi8LKw6ZE6dwNg46
# Tywf8o4KfMe6mHubpQs9ZX0+U+SMbmNyZirrNXdPrm7FjuYAUFKZDZPKRMG/U5VJ
# J6y9wB85uc6vybo0dFHt
# SIG # End signature block
