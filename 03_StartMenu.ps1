#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2024

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
    06.11.2019 Konrad Brunner       Initial Version
    25.02.2020 Konrad Brunner       Added tenant configurations
    06.03.2020 Konrad Brunner       Added sharepoint configurations
    13.09.2020 Konrad Brunner       Added AAD configurations

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [switch]$unattended = $false,
    [Parameter(Mandatory=$false)]
    [string]$m1 = $null,
    [Parameter(Mandatory=$false)]
    [string]$m2 = $null,
    [Parameter(Mandatory=$false)]
    [string]$m3 = $null,
    [Parameter(Mandatory=$false)]
    [string]$m4 = $null,
    [Parameter(Mandatory=$false)]
    [string]$m5 = $null,
    [Parameter(Mandatory=$false)]
    [string]$o1 = $null,
    [Parameter(Mandatory=$false)]
    [string]$o2 = $null,
    [Parameter(Mandatory=$false)]
    [string]$o3 = $null
)

#Reading configuration
. $PSScriptRoot\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\03_StartMenu-$($AlyaTimeString).log" | Out-Null

#Menu definition
$menuDef = @(
    @("ed", "Edit Configuration", "Edit-Configuration"),
    @("co", "Concepts", "", @(
        @("n", "Naming", "", @(
            @("na", "NamingConventionAzure", "Start-NamingConventionAzure"),
            @("no", "NamingConventionOffice365", "Start-NamingConventionOffice365"),
            @("b", "Back", "back"),
            @("q", "Quit", "return")
        )),
        @("b", "Back", "back"),
        @("q", "Quit", "return"))),
    @("te", "Tenant", "", @(
        @("cp", "CreateAndUpdate-PublicStorageAccount", "CreateAndUpdate-PublicStorageAccount"),
        @("cd", "Create-AzureDiagnosticLoggingStorage", "Create-AzureDiagnosticLoggingStorage"),
        @("cr", "Create-AzureRecoveryVault", "Create-AzureRecoveryVault"),
        @("lo", "Set-O365AuditLogging", "Set-O365AuditLogging"),
        @("la", "Set-AzureAadAuditLogging", "Set-AzureAadAuditLogging"),
        @("ls", "Set-AzureSubAuditLogging", "Set-AzureSubAuditLogging"),
        @("da", "Set-AdHocSubscriptionsDisabled", "Set-AdHocSubscriptionsDisabled"),
        @("du", "Set-DefaultUsageLocation", "Set-DefaultUsageLocation"),
        @("pr", "Set-PasswordReset", "Set-PasswordReset"),
        @("gm", "Set-OfficeGroupManagers", "Set-OfficeGroupManagers"),
        @("ap", "Set-ConditionalAccessPolicies", "Set-ConditionalAccessPolicies"),
        @("es", "Set-AzureExternalSharingSettings", "Set-AzureExternalSharingSettings"),
        @("ev", "Set-EmailVerifiedUsers", "Set-EmailVerifiedUsers"),
        @("lp", "Set-LobAppsPermission", "Set-LobAppsPermission"),
        @("re", "Set-ReadOthersEnabled", "Set-ReadOthersEnabled"),
        @("uc", "Set-UserConsentEnabled", "Set-UserConsentEnabled"),
        @("b", "Back", "back"),
        @("q", "Quit", "return"))),
    @("ad", "Azure Active Directory", "", @(
        @("ca", "Configure-Admins", "Configure-Admins"),
        @("cg", "Configure-Groups", "Configure-Groups"),
        @("cl", "Configure-Licenses", "Configure-Licenses"),
        @("cr", "Configure-Roles", "Configure-Roles"),
        @("cv", "Create-AdVms", "Create-AdVms"),
        @("pg", "Prepare-GuestUsers", "Prepare-GuestUsers"),
        @("sa", "Sync-Aad", "Sync-Aad"),
        @("op", "On Premises AD", "", @(
            @("ac", "Allow-ConsitencyGuidInAd", "OnPremAllow-ConsitencyGuidInAd"),
            @("cu", "Compair-Users", "OnPremCompair-Users"),
            @("cl", "Configure-Licenses", "OnPremConfigure-Licenses"),
            @("eg", "Export-Groups", "OnPremExport-Groups"),
            @("eg", "Export-UsersAndContacts", "OnPremExport-UsersAndContacts"),
            @("eg", "Import-ProfilePictures", "OnPremImport-ProfilePictures"),
            @("iu", "Import-AndSyncAadUser", "OnPremImport-AndSyncAadUser"),
            @("rs", "Remove-LoginScripts", "OnPremRemove-LoginScripts"),
            @("eg", "Set-AdfsScpSetting", "OnPremSet-AdfsScpSetting"),
            @("b", "Back", "back"),
            @("q", "Quit", "return")
        )),
        @("up", "UPN Change", "", @(
            @("cc", "Change-UpnInAdFromCsv", "Change-UpnInAdFromCsv"),
            @("cu", "Change-UpnInAdSingleUser", "Change-UpnInAdSingleUser"),
            @("cd", "Change-UpnInDevOps", "Change-UpnInDevOps"),
            @("cs", "Change-UpnInSharePoint", "Change-UpnInSharePoint"),
            @("eu", "Export-UsersAndContacts", "Export-UsersAndContacts"),
            @("b", "Back", "back"),
            @("q", "Quit", "return")
        )),
        @("b", "Back", "back"),
        @("q", "Quit", "return"))),
    @("az", "Azure", "", @(
        @("cp", "CreateAndUpdate-PublicStorageAccount", "CreateAndUpdate-PublicStorageAccount"),
        @("cd", "Create-AzureDiagnosticLoggingStorage", "Create-AzureDiagnosticLoggingStorage"),
        @("cr", "Create-AzureRecoveryVault", "Create-AzureRecoveryVault"),
        @("et", "Extract-Templates", "Extract-Templates"),
        @("cj", "Create-JumpHost", "Create-JumpHost"),
        @("rl", "Remove-AllResourceGroupsDeleteLock", "Remove-AllResourceGroupsDeleteLock"),
        @("sl", "Set-AllResourceGroupsDeleteLock", "Set-AllResourceGroupsDeleteLock"),
        @("nt", "Network", "", @(
            @("cp", "Configure-VirtualNetworks", "Configure-VirtualNetworks"),
            @("ct", "Configure-VirtualNetworksTest", "Configure-VirtualNetworksTest"),
            @("ai", "Add-MyIpToSecGroups", "Add-MyIpToSecGroups"),
            @("gi", "Get-MSIPRangesAndUrls", "Get-MSIPRangesAndUrls"),
            @("gv", "Get-VpnGatewayDetails", "Get-VpnGatewayDetails"),
            @("cg", "Calculate-GatewaySubnet", "Calculate-GatewaySubnet"),
            #TODO Create VPN Gateway
            @("b", "Back", "back"),
            @("q", "Quit", "return")
        )),
        @("co", "Compute", "", @(
            @("ga", "Get-VmAgentState", "Get-VmAgentState"),
            @("b", "Back", "back"),
            @("q", "Quit", "return")
        )),
        @("b", "Back", "back"),
        @("q", "Quit", "return"))),
    @("at", "Azure Automation", "", @(
        @("ca", "Create-AutomationAccount", "Create-AutomationAccount"),
        @("aa", "Allow-AutomationAccountOnNewSubscription", "Allow-AutomationAccountOnNewSubscription"),
        @("er", "Extract-Runbooks", "Extract-Runbooks"),
        @("b", "Back", "back"),
        @("q", "Quit", "return"))),
    @("ad", "Azure Information Protection", "", @(
        @("cs", "Configure-AIPService", "Configure-AIPService"),
        @("cl", "Configure-LabelsAndPolicies", "Configure-LabelsAndPolicies"),
        @("gc", "Get-AIPConfiguration", "Get-AIPConfiguration"),
        @("gd", "Get-AIPDocumentLogs", "Get-AIPDocumentLogs"),
        @("gl", "Get-AIPServiceLocation", "Get-AIPServiceLocation"),
        @("gt", "Get-AIPTrackingLogs", "Get-AIPTrackingLogs"),
        @("ic", "Install-AIPClient", "Install-AIPClient"),
        @("sp", "Set-AIPOnboardingPolicy", "Set-AIPOnboardingPolicy"),
        @("b", "Back", "back"),
        @("q", "Quit", "return"))),
    @("cl", "Client", "", @(
        @("w", "OS", "", @(
            @("gs", "Get-DeviceRegStatus", "Get-DeviceRegStatus"),
            @("sr", "Set-ClientRegionalSettings", "Set-ClientRegionalSettings"),
            @("se", "Set-ExecutionPolicyUnrestricted", "Set-ExecutionPolicyUnrestricted"),
            @("st", "Set-O365AndAzureTrustedSites", "Set-O365AndAzureTrustedSites"),
            @("b", "Back", "back"),
            @("q", "Quit", "return")
        )),
        @("o", "Office", "", @(
            @("pd", "Prepare-DeployTool", "Prepare-DeployTool"),
            @("if", "Install Office365 Full", "Install-Office365-Full"),
            @("uf", "Uninstall Office365 Full", "Uninstall-Office365-Full"),
            @("io", "Install Office365 Only", "Install-Office365-Only"),
            @("uo", "Uninstall Office365 Only", "Uninstall-Office365-Only"),
            @("iw", "Install Office365 WVD", "Install-Office365-WVD"),
            @("uw", "Uninstall Office365 WVD", "Uninstall-Office365-WVD"),
            @("ss", "O365 Client Configuration Service", "Start-ClientConfigService"),
            @("uo", "Update-Office365", "Update-Office365"),
            @("b", "Back", "back"),
            @("q", "Quit", "return")
        )),
        @("b", "Back", "back"),
        @("q", "Quit", "return"))),
    @("sp", "SharePoint", "", @(
        @("at", "Add-SharePointDefaultTheme", "Add-SharePointDefaultTheme"),
        @("ad", "Add-SharePointDefaultDesign", "Add-SharePointDefaultDesign"),
        @("bs", "Backup-AllSites", "Backup-AllSites"),
        @("cd", "Clean-DeletedSites", "Clean-DeletedSites"),
        @("ca", "Configure-AzureB2BIntegration", "Configure-AzureB2BIntegration"),
        @("ch", "Configure-HubSites", "Configure-HubSites"),
        @("dc", "Disable-AllUsersClaims", "Disable-AllUsersClaims"),
        @("ds", "Disable-SiteCreation", "Disable-SiteCreation"),
        @("ea", "Enable-AIPIntegration", "Enable-AIPIntegration"),
        @("ec", "Enable-AllUsersClaims", "Enable-AllUsersClaims"),
        @("ee", "Enable-EmailAccountMatch", "Enable-EmailAccountMatch"),
        @("ev", "Enable-ExplorerViewCookie", "Enable-ExplorerViewCookie"),
        @("ep", "Enable-PeoplePickerForGuests", "Enable-PeoplePickerForGuests"),
        @("ew", "Enable-PublicCdn", "Enable-PublicCdn"),
        @("hd", "Hide-DefaultThemes", "Hide-DefaultThemes"),
        @("rp", "Run-OnlinePerformanceTest", "Run-OnlinePerformanceTest"),
        @("ss", "Set-SharingCapability", "Set-SharingCapability"),
        @("sl", "Set-SiteLogo", "Set-SiteLogo"),
        @("st", "Set-SiteTheme", "Set-SiteTheme"),
        @("op", "On Premises", "", @(
            @("ep", "Export-ProfilePictures", "OnPremExport-ProfilePictures"),
            @("et", "Export-TermGroup", "OnPremExport-TermGroup"),
            @("ip", "Import-ProfilePictures", "OnPremImport-ProfilePictures"),
            @("rl", "Record-SharePointLogs", "OnPremRecord-SharePointLogs"),
            @("rs", "ReInstall-Solution", "OnPremReInstall-Solution"),
            @("b", "Back", "back"),
            @("q", "Quit", "return")
        )),
        @("b", "Back", "back"),
        @("q", "Quit", "return"))),
    @("ex", "Exchange", "", @(
        @("cs", "Configure-ServiceUser", "Configure-ServiceUser"),
        @("sr", "Set-AllMailboxes30DayRetention", "Set-AllMailboxes30DayRetention"),
        @("us", "Update-Signature", "Update-Signature"),
        @("rh", "RemoveHybrid", "RemoveHybrid"),
        @("uc", "UsefullExchangeCommands", "UsefullExchangeCommands"),
        @("pe", "pstexport", "pstexport"),
        @("b", "Back", "back"),
        @("q", "Quit", "return"))),
    @("fs", "File Sync", "", @(
        @("sf", "SyncFrom-AzureFileStorageShare", "SyncFrom-AzureFileStorageShare"),
        @("st", "SyncTo-AzureFileStorageShare", "SyncTo-AzureFileStorageShare"),
        @("su", "Set-UserHomeAccess", "Set-UserHomeAccess"),
        @("bs", "BackupLocalFilesToShare", "BackupLocalFilesToShare"),
        @("sd", "SyncShareDirs", "SyncShareDirs"),
        @("ss", "SyncTo-SharePoint", "SyncTo-SharePoint"),
        @("b", "Back", "back"),
        @("q", "Quit", "return"))),
    @("it", "Intune", "", @(
        @("sa", "Set-IntuneAsMdmAuthority", "Set-IntuneAsMdmAuthority"),
        @("sb", "Set-IntuneBranding", "Set-IntuneBranding"),
        @("cr", "Create-IntuneWin32Packages", "Create-IntuneWin32Packages"),
        @("up", "Upload-IntuneWin32Packages", "Upload-IntuneWin32Packages"),
        @("co", "Configure-IntuneWin32Packages", "Configure-IntuneWin32Packages"),
        @("uw", "Upload-IntuneWebApps", "Upload-IntuneWebApps"),
        @("cw", "Configure-IntuneWebApps", "Configure-IntuneWebApps"),
        @("cp", "Configure-IntuneDeviceCompliancePolicies", "Configure-IntuneDeviceCompliancePolicies"),
        @("dt", "Download-Win32AppPrepTool", "Download-Win32AppPrepTool"),
        @("er", "Enable-PINReset", "Enable-PINReset"),
        @("ec", "Export-IntuneConfiguration", "Export-IntuneConfiguration"),
        @("ea", "Export-ApplicationConfiguration", "Export-ApplicationConfiguration"),
        @("gc", "Get-ProductCodeFromMsi", "Get-ProductCodeFromMsi"),
        @("gs", "Get-IntunePowershellSamples", "Get-IntunePowershellSamples"),
        @("rs", "Restart-IntuneWin32PackagesInstallation", "Restart-IntuneWin32PackagesInstallation"),
        @("ep", "extractPackages", "extractPackages"),
        @("b", "Back", "back"),
        @("q", "Quit", "return"))),
    @("tc", "Phone", "", @(
        @("ag", "Add-PSTNGateway", "Add-PSTNGateway"),
        @("sf", "Set-PSTNForwarding", "Set-PSTNForwarding"),
        @("sr", "Set-VoiceRouting", "Set-VoiceRouting"),
        @("au", "Activate-User", "Activate-User"),
        @("lu", "List-User", "List-User"),
        @("b", "Back", "back"),
        @("q", "Quit", "return"))),
    @("wv", "Windows Virtual Desktop", "", @(
        @("ad", "Admin", "", @(
            @("19", "Fall2019", "", @(
                @("pr", "Prod", "", @(
                    @("00", "00_prepareWvd", "Fall2019Prod_00_prepareWvd"),
                    @("01", "01_createWvdTenant", "Fall2019Prod_01_createWvdTenant"),
                    @("02", "02_createServicePrincipal", "Fall2019Prod_02_createServicePrincipal"),
                    @("04", "04_assignRoleToUsers", "Fall2019Prod_04_assignRoleToUsers"),
                    @("05", "05_prepareShare", "Fall2019Prod_05_prepareShare"),
                    @("06", "06_createAppHostPool_hpol001", "Fall2019Prod_06_createAppHostPool_hpol001"),
                    @("07", "07_createRdpHostPool_hpol002", "Fall2019Prod_07_createRdpHostPool_hpol002"),
                    @("08", "08_updateAppHostPool_hpol001", "Fall2019Prod_08_updateAppHostPool_hpol001"),
                    @("09", "09_updateRdpHostPool_hpol002", "Fall2019Prod_09_updateRdpHostPool_hpol002"),
                    @("10", "10_removeAppHostPool_hpol001", "Fall2019Prod_10_removeAppHostPool_hpol001"),
                    @("11", "11_removeRdpHostPool_hpol002", "Fall2019Prod_11_removeRdpHostPool_hpol002"),
                    @("121", "12_AddLoadBalancer_hpol001", "Fall2019Prod_12_AddLoadBalancer_hpol001"),
                    @("122", "12_AddLoadBalancer_hpol002", "Fall2019Prod_12_AddLoadBalancer_hpol002"),
                    @("13", "13_updateLocalFiles_hpol001", "Fall2019Prod_13_updateLocalFiles_hpol001"),
                    @("15", "15_createOrUpdateAppGroups_hpol001", "Fall2019Prod_15_createOrUpdateAppGroups_hpol001"),
                    @("16", "16_createOrUpdateAppGroups_hpol002", "Fall2019Prod_16_createOrUpdateAppGroups_hpol002"),
                    @("18", "18_setAppGroupIcons", "Fall2019Prod_18_setAppGroupIcons"),
                    @("19", "19_setHostPoolToValidation", "Fall2019Prod_19_setHostPoolToValidation"),
                    @("20", "20_assignUsersToGroups", "Fall2019Prod_20_assignUsersToGroups"),
                    @("21", "21_addUserToGroup", "Fall2019Prod_21_addUserToGroup"),
                    @("22", "22_setHostPoolCustomProerties", "Fall2019Prod_22_setHostPoolCustomProerties"),
                    @("30", "30_removeAppGroups", "Fall2019Prod_30_removeAppGroups"),
                    @("31", "31_removeSessionHosts", "Fall2019Prod_31_removeSessionHosts"),
                    @("32", "32_removeUserSessions", "Fall2019Prod_32_removeUserSessions"),
                    @("33", "33_removeAllSessions", "Fall2019Prod_33_removeAllSessions"),
                    @("34", "34_killOldDisconnectedSessions", "Fall2019Prod_34_killOldDisconnectedSessions"),
                    @("35", "35_listAllSessions", "Fall2019Prod_35_listAllSessions"),
                    @("36", "36_removeUserFromAllPools", "Fall2019Prod_36_removeUserFromAllPools"),
                    @("37", "37_allowNewSessionsOnAllHosts", "Fall2019Prod_37_allowNewSessionsOnAllHosts"),
                    @("40", "40_listRds", "Fall2019Prod_40_listRds"),
                    @("41", "41_getDiagnostics", "Fall2019Prod_41_getDiagnostics"),
                    @("43", "43_sendMessageToUsers", "Fall2019Prod_43_sendMessageToUsers"),
                    @("48", "48_logoutUserDirect", "Fall2019Prod_48_logoutUserDirect"),
                    @("50", "50_resizeVhdFiles", "Fall2019Prod_50_resizeVhdFiles"),
                    @("51", "51_resizeHostpoolVmSku", "Fall2019Prod_51_resizeHostpoolVmSku"),
                    @("b", "Back", "back"),
                    @("q", "Quit", "return")
                )),
                @("te", "Test", "", @(
                    @("00", "00_prepareWvd", "Fall2019Test_00_prepareWvd"),
                    @("01", "01_createWvdTenant", "Fall2019Test_01_createWvdTenant"),
                    @("02", "02_createServicePrincipal", "Fall2019Test_02_createServicePrincipal"),
                    @("04", "04_assignRoleToUsers", "Fall2019Test_04_assignRoleToUsers"),
                    @("05", "05_prepareShare", "Fall2019Test_05_prepareShare"),
                    @("06", "06_createAppHostPool_hpol001", "Fall2019Test_06_createAppHostPool_hpol001"),
                    @("07", "07_createRdpHostPool_hpol002", "Fall2019Test_07_createRdpHostPool_hpol002"),
                    @("08", "08_updateAppHostPool_hpol001", "Fall2019Test_08_updateAppHostPool_hpol001"),
                    @("09", "09_updateRdpHostPool_hpol002", "Fall2019Test_09_updateRdpHostPool_hpol002"),
                    @("10", "10_removeAppHostPool_hpol001", "Fall2019Test_10_removeAppHostPool_hpol001"),
                    @("11", "11_removeRdpHostPool_hpol002", "Fall2019Test_11_removeRdpHostPool_hpol002"),
                    @("121", "12_AddLoadBalancer_hpol001", "Fall2019Test_12_AddLoadBalancer_hpol001"),
                    @("122", "12_AddLoadBalancer_hpol002", "Fall2019Test_12_AddLoadBalancer_hpol002"),
                    @("13", "13_updateLocalFiles_hpol001", "Fall2019Test_13_updateLocalFiles_hpol001"),
                    @("15", "15_createOrUpdateAppGroups_hpol001", "Fall2019Test_15_createOrUpdateAppGroups_hpol001"),
                    @("16", "16_createOrUpdateAppGroups_hpol002", "Fall2019Test_16_createOrUpdateAppGroups_hpol002"),
                    @("18", "18_setAppGroupIcons", "Fall2019Test_18_setAppGroupIcons"),
                    @("19", "19_setHostPoolToValidation", "Fall2019Test_19_setHostPoolToValidation"),
                    @("20", "20_assignUsersToGroups", "Fall2019Test_20_assignUsersToGroups"),
                    @("21", "21_addUserToGroup", "Fall2019Test_21_addUserToGroup"),
                    @("22", "22_setHostPoolCustomProerties", "Fall2019Test_22_setHostPoolCustomProerties"),
                    @("30", "30_removeAppGroups", "Fall2019Test_30_removeAppGroups"),
                    @("31", "31_removeSessionHosts", "Fall2019Test_31_removeSessionHosts"),
                    @("32", "32_removeUserSessions", "Fall2019Test_32_removeUserSessions"),
                    @("33", "33_removeAllSessions", "Fall2019Test_33_removeAllSessions"),
                    @("34", "34_killOldDisconnectedSessions", "Fall2019Test_34_killOldDisconnectedSessions"),
                    @("35", "35_listAllSessions", "Fall2019Test_35_listAllSessions"),
                    @("36", "36_removeUserFromAllPools", "Fall2019Test_36_removeUserFromAllPools"),
                    @("37", "37_allowNewSessionsOnAllHosts", "Fall2019Test_37_allowNewSessionsOnAllHosts"),
                    @("40", "40_listRds", "Fall2019Test_40_listRds"),
                    @("41", "41_getDiagnostics", "Fall2019Test_41_getDiagnostics"),
                    @("43", "43_sendMessageToUsers", "Fall2019Test_43_sendMessageToUsers"),
                    @("48", "48_logoutUserDirect", "Fall2019Test_48_logoutUserDirect"),
                    @("50", "50_resizeVhdFiles", "Fall2019Test_50_resizeVhdFiles"),
                    @("51", "51_resizeHostpoolVmSku", "Fall2019Test_51_resizeHostpoolVmSku"),
                    @("b", "Back", "back"),
                    @("q", "Quit", "return")
                ))
            )),
            @("20", "Spring2020", "", @(
                @("pr", "Prod", "", @(
                    #TODO
                    @("b", "Back", "back"),
                    @("q", "Quit", "return")
                )),
                @("te", "Test", "", @(
                    #TODO
                    @("b", "Back", "back"),
                    @("q", "Quit", "return")
                ))
            )),
            @("b", "Back", "back"),
            @("q", "Quit", "return")
        )),
        @("as", "Autoscaling", "", @(
            @("cp", "Create-AutoscalingServicePrincipal", "Create-AutoscalingServicePrincipal"),
            @("sc", "Save-AutoscalingCredentials", "Save-AutoscalingCredentials"),
            @("sa", "ScaleHostPool_Alya", "ScaleHostPool_Alya"),
            @("sm", "ScaleHostPool_MS", "ScaleHostPool_MS"),
            #TODO Install scheduled task
            @("b", "Back", "back"),
            @("q", "Quit", "return")
        )),
        @("cl", "Client", "", @(
            @("rp", "Get-RegistrationToken-Prod", "Get-RegistrationToken-Prod"),
            @("rt", "Get-RegistrationToken-Test", "Get-RegistrationToken-Test"),
            @("ra", "Reinstall-Agent", "Reinstall-Agent"),
            @("b", "Back", "back"),
            @("q", "Quit", "return")
        )),
        @("im", "Image", "", @(
            @("ci", "Clean-Image", "Clean-Image"),
            @("cc", "Create-ImageHostClient", "Create-ImageHostClient"),
            @("cs", "Create-ImageHostServer", "Create-ImageHostServer"),
            @("pc", "Prepare-ImageClient", "Prepare-ImageClient"),
            @("ps", "Prepare-ImageServer", "Prepare-ImageServer"),
            @("it", "Image Install Tools", "ImageInstallTools"),
            @("b", "Back", "back"),
            @("q", "Quit", "return")
        )),
        @("gp", "Group Policies", "", @(
            @("at", "Administrativ Templates", "admTemplates"),
            @("it", "Group Policies", "groupPolicies"),
            @("b", "Back", "back"),
            @("q", "Quit", "return")
        )),
        @("ic", "wvdIcons", "wvdIcons"),
        @("sa", "wvdStartApps", "wvdStartApps"),
        @("th", "wvdTheme", "wvdTheme"),
        @("b", "Back", "back"),
        @("q", "Quit", "return"))),
    @("so", "Solutions", "", @(
        @("b", "Back", "back"),
        @("q", "Quit", "return"))),
    @("do", "DevOps", "", @(
        @("cr", "Connect-GitRepository", "Connect-GitRepository"),
        @("gc", "Git-CheckIn", "Git-CheckIn"),
        @("gs", "Git-Sync", "Git-Sync"),
        @("gb", "Git-Bash", "Git-Bash"),
        @("gd", "Git-Cmd", "Git-Cmd"),
        @("md", "Move-DevOpsTasks", "Move-DevOpsTasks"),
        @("b", "Back", "back"),
        @("q", "Quit", "return"))),
    @("cl", "Clean-Logs", "Clean-Logs"),
    @("q", "Quit", "return")
)

#Menu functions
function Clean-Logs
{
    & "$($AlyaScripts)\Clean-Logs.ps1"
}
function Set-O365AuditLogging
{
    & "$($AlyaScripts)\tenant\Set-O365AuditLogging.ps1"
}
function Set-AzureAadAuditLogging
{
    & "$($AlyaScripts)\tenant\Set-AzureAadAuditLogging.ps1"
}
function Set-AzureSubAuditLogging
{
    & "$($AlyaScripts)\tenant\Set-AzureSubAuditLogging.ps1"
}
function Set-PasswordReset
{
    & "$($AlyaScripts)\tenant\Set-PasswordReset.ps1"
}
function Set-EmailVerifiedUsers
{
    & "$($AlyaScripts)\tenant\Set-EmailVerifiedUsers.ps1"
}
function Set-AdHocSubscriptionsDisabled
{
    & "$($AlyaScripts)\tenant\Set-AdHocSubscriptionsDisabled.ps1"
}
function Set-AzureExternalSharingSettings
{
    & "$($AlyaScripts)\tenant\Set-AzureExternalSharingSettings.ps1"
}
function Set-ConditionalAccessPolicies
{
    & "$($AlyaScripts)\tenant\Set-ConditionalAccessPolicies.ps1"
}
function Set-LobAppsPermission
{
    & "$($AlyaScripts)\tenant\Set-LobAppsPermission.ps1"
}
function Set-ReadOthersEnabled
{
    & "$($AlyaScripts)\tenant\Set-ReadOthersEnabled.ps1"
}
function Set-UserConsentEnabled
{
    & "$($AlyaScripts)\tenant\Set-UserConsentEnabled.ps1"
}
function CreateAndUpdate-PublicStorageAccount
{
    & "$($AlyaScripts)\tenant\CreateAndUpdate-PublicStorageAccount.ps1"
}
function Set-DefaultUsageLocation
{
    & "$($AlyaScripts)\tenant\Set-DefaultUsageLocation.ps1"
}
function Create-AzureDiagnosticLoggingStorage
{
    & "$($AlyaScripts)\tenant\Create-AzureDiagnosticLoggingStorage.ps1"
}
function Create-AzureRecoveryVault
{
    & "$($AlyaScripts)\tenant\Create-AzureRecoveryVault.ps1"
}
function Set-OfficeGroupManagers
{
    & "$($AlyaScripts)\tenant\Set-OfficeGroupManagers.ps1"
}
function Create-AutomationAccount
{
    & "$($AlyaScripts)\automation\Create-AutomationAccount.ps1"
}
function Allow-AutomationAccountOnNewSubscription
{
    & "$($AlyaScripts)\automation\Allow-AutomationAccountOnNewSubscription.ps1"
}
function Extract-Runbooks
{
    & "$($AlyaScripts)\automation\Extract-Runbooks.ps1"
}
function Configure-AIPService
{
    & "$($AlyaScripts)\aip\Configure-AIPService.ps1"
}
function Configure-LabelsAndPolicies
{
    & "$($AlyaScripts)\aip\Configure-LabelsAndPolicies.ps1"
}
function Get-AIPConfiguration
{
    & "$($AlyaScripts)\aip\Get-AIPConfiguration.ps1"
}
function Get-AIPDocumentLogs
{
    & "$($AlyaScripts)\aip\Get-AIPDocumentLogs.ps1"
}
function Get-AIPServiceLocation
{
    & "$($AlyaScripts)\aip\Get-AIPServiceLocation.ps1"
}
function Get-AIPTrackingLogs
{
    & "$($AlyaScripts)\aip\Get-AIPTrackingLogs.ps1"
}
function Install-AIPClient
{
    & "$($AlyaScripts)\aip\Install-AIPClient.ps1"
}
function Set-AIPOnboardingPolicy
{
    & "$($AlyaScripts)\aip\Set-AIPOnboardingPolicy.ps1"
}
function CreateAndUpdate-PublicStorageAccount
{
    & "$($AlyaScripts)\azure\CreateAndUpdate-PublicStorageAccount.ps1"
}
function Extract-Templates
{
    & "$($AlyaScripts)\azure\Extract-Templates.ps1"
}
function Create-JumpHost
{
    & "$($AlyaScripts)\azure\Create-JumpHost.ps1"
}
function Remove-AllResourceGroupsDeleteLock
{
    & "$($AlyaScripts)\azure\Remove-AllResourceGroupsDeleteLock.ps1"
}
function Set-AllResourceGroupsDeleteLock
{
    & "$($AlyaScripts)\azure\Set-AllResourceGroupsDeleteLock.ps1"
}
function Configure-VirtualNetworks
{
    & "$($AlyaScripts)\network\Configure-VirtualNetworks.ps1"
}
function Configure-VirtualNetworksTest
{
    & "$($AlyaScripts)\network\Configure-VirtualNetworksTest.ps1"
}
function Add-MyIpToSecGroups
{
    & "$($AlyaScripts)\network\Add-MyIpToSecGroups.ps1"
}
function Get-MSIPRangesAndUrls
{
    & "$($AlyaScripts)\network\Get-MSIPRangesAndUrls.ps1"
}
function Calculate-GatewaySubnet
{
    & "$($AlyaScripts)\network\Calculate-GatewaySubnet.ps1"
}
function Get-VpnGatewayDetails
{
    & "$($AlyaScripts)\network\Get-VpnGatewayDetails.ps1"
}
function Get-VmAgentState
{
    & "$($AlyaScripts)\compute\Get-VmAgentState.ps1"
}
function Add-SharePointDefaultTheme
{
    & "$($AlyaScripts)\sharepoint\Add-SharePointDefaultTheme"
}
function Configure-AzureB2BIntegration
{
    & "$($AlyaScripts)\sharepoint\Configure-AzureB2BIntegration"
}
function Configure-HubSites
{
    & "$($AlyaScripts)\sharepoint\Configure-HubSites"
}
function Disable-AllUsersClaims
{
    & "$($AlyaScripts)\sharepoint\Disable-AllUsersClaims"
}
function Disable-SiteCreation
{
    & "$($AlyaScripts)\sharepoint\Disable-SiteCreation"
}
function Enable-AIPIntegration
{
    & "$($AlyaScripts)\sharepoint\Enable-AIPIntegration"
}
function Enable-AllUsersClaims
{
    & "$($AlyaScripts)\sharepoint\Enable-AllUsersClaims"
}
function Enable-EmailAccountMatch
{
    & "$($AlyaScripts)\sharepoint\Enable-EmailAccountMatch"
}
function Enable-ExplorerViewCookie
{
    & "$($AlyaScripts)\sharepoint\Enable-ExplorerViewCookie"
}
function Enable-PeoplePickerForGuests
{
    & "$($AlyaScripts)\sharepoint\Enable-PeoplePickerForGuests"
}
function Enable-PublicCdn
{
    & "$($AlyaScripts)\sharepoint\Enable-PublicCdn"
}
function Hide-DefaultThemes
{
    & "$($AlyaScripts)\sharepoint\Hide-DefaultThemes"
}
function Run-OnlinePerformanceTest
{
    & "$($AlyaScripts)\sharepoint\Run-OnlinePerformanceTest"
}
function Set-SharingCapability
{
    & "$($AlyaScripts)\sharepoint\Set-SharingCapability"
}
function Add-SharePointDefaultDesign
{
    & "$($AlyaScripts)\sharepoint\Add-SharePointDefaultDesign"
}
function Clean-DeletedSites
{
    & "$($AlyaScripts)\sharepoint\Clean-DeletedSites"
}
function Backup-AllSites
{
    & "$($AlyaScripts)\sharepoint\Backup-AllSites"
}
function Set-SiteLogo
{
    & "$($AlyaScripts)\sharepoint\Set-SiteLogo"
}
function Set-SiteTheme
{
    & "$($AlyaScripts)\sharepoint\Set-SiteTheme"
}
function OnPremExport-ProfilePictures
{
    & "$($AlyaScripts)\sharepoint\OnPremises\Export-ProfilePictures"
}
function OnPremExport-TermGroup
{
    & "$($AlyaScripts)\sharepoint\OnPremises\Export-TermGroup"
}
function OnPremImport-ProfilePictures
{
    & "$($AlyaScripts)\sharepoint\OnPremises\Import-ProfilePictures"
}
function OnPremRecord-SharePointLogs
{
    & "$($AlyaScripts)\sharepoint\OnPremises\Record-SharePointLogs"
}
function OnPremReInstall-Solution
{
    & "$($AlyaScripts)\sharepoint\OnPremises\ReInstall-Solution"
}
function OnPremAllow-ConsitencyGuidInAd
{
    & "$($AlyaScripts)\aad\OnPremises\Allow-ConsitencyGuidInAd.ps1"
}
function OnPremCompair-Users
{
    & "$($AlyaScripts)\aad\OnPremises\Compair-Users.ps1"
}
function Configure-Groups
{
    & "$($AlyaScripts)\aad\Configure-Groups.ps1"
}
function Configure-Admins
{
    & "$($AlyaScripts)\aad\Configure-Admins.ps1"
}
function Configure-Licenses
{
    & "$($AlyaScripts)\aad\Configure-Licenses.ps1"
}
function Configure-Roles
{
    & "$($AlyaScripts)\aad\Configure-Roles.ps1"
}
function OnPremConfigure-Licenses
{
    & "$($AlyaScripts)\aad\OnPremises\Configure-Licenses.ps1"
}
function Create-AdVms
{
    & "$($AlyaScripts)\aad\Create-AdVms.ps1"
}
function OnPremExport-Groups
{
    & "$($AlyaScripts)\aad\OnPremises\Export-Groups.ps1"
}
function OnPremExport-UsersAndContacts
{
    & "$($AlyaScripts)\aad\OnPremises\Export-UsersAndContacts.ps1"
}
function OnPremImport-ProfilePictures
{
    & "$($AlyaScripts)\aad\OnPremises\Import-ProfilePictures.ps1"
}
function OnPremSet-AdfsScpSetting
{
    & "$($AlyaScripts)\aad\OnPremises\Set-AdfsScpSetting.ps1"
}
function OnPremImport-AndSyncAadUser
{
    & "$($AlyaScripts)\aad\OnPremises\Import-AndSyncAadUser.ps1"
}
function OnPremRemove-LoginScripts
{
    & "$($AlyaScripts)\aad\OnPremises\Remove-LoginScripts.ps1"
}
function Prepare-GuestUsers
{
    & "$($AlyaScripts)\aad\Prepare-GuestUsers.ps1"
}
function Sync-Aad
{
    & "$($AlyaScripts)\aad\Sync-Aad.ps1"
}
function Change-UpnInAdFromCsv
{
    & "$($AlyaScripts)\aad\upnchange\Change-UpnInAdFromCsv.ps1"
}
function Change-UpnInAdSingleUser
{
    & "$($AlyaScripts)\aad\upnchange\Change-UpnInAdSingleUser.ps1"
}
function Change-UpnInDevOps
{
    & "$($AlyaScripts)\aad\upnchange\Change-UpnInDevOps.ps1"
}
function Change-UpnInSharePoint
{
    & "$($AlyaScripts)\aad\upnchange\Change-UpnInSharePoint.ps1"
}
function Export-UsersAndContacts
{
    & "$($AlyaScripts)\aad\upnchange\Export-UsersAndContacts.ps1"
}
function Start-ClientConfigService
{
    &("start") "https://config.office.com/"
}
function Set-ClientRegionalSettings
{
    & "$($AlyaScripts)\client\os\Set-ClientRegionalSettings.ps1"
}
function Set-ExecutionPolicyUnrestricted
{
    & "$($AlyaScripts)\client\os\Set-ExecutionPolicyUnrestricted.ps1"
}
function Set-O365AndAzureTrustedSites
{
    & "$($AlyaScripts)\client\os\Set-O365AndAzureTrustedSites.ps1"
}
function Get-DeviceRegStatus
{
    & "$($AlyaScripts)\client\os\Get-DeviceRegStatus.ps1"
}
function Prepare-DeployTool
{
    & "$($AlyaScripts)\client\office\Prepare-DeployTool.ps1"
}
function Update-Office365
{
    & "$($AlyaScripts)\client\office\Update-Office365.cmd"
}
function Install-Office365-WVD
{
    & "$($AlyaScripts)\client\office\Install-Office365-WVD.ps1"
}
function Uninstall-Office365-WVD
{
    & "$($AlyaScripts)\client\office\Uninstall-Office365-WVD.ps1"
}
function Install-Office365-Full
{
    & "$($AlyaScripts)\client\office\Install-Office365-Full.ps1"
}
function Uninstall-Office365-Full
{
    & "$($AlyaScripts)\client\office\Uninstall-Office365-Full.ps1"
}
function Install-Office365-Only
{
    & "$($AlyaScripts)\client\office\Install-Office365-Only.ps1"
}
function Uninstall-Office365-Only
{
    & "$($AlyaScripts)\client\office\Uninstall-Office365-Only.ps1"
}
function Configure-ServiceUser
{
    & "$($AlyaScripts)\exchange\Configure-ServiceUser.ps1"
}
function Set-AllMailboxes30DayRetention
{
    & "$($AlyaScripts)\exchange\Set-AllMailboxes30DayRetention.ps1"
}
function Update-Signature
{
    & "$($AlyaScripts)\exchange\Update-Signature.cmd"
}
function RemoveHybrid
{
    Start-Process "$($AlyaScripts)\exchange\RemoveHybrid.txt"
}
function UsefullExchangeCommands
{
    Start-Process "$($AlyaScripts)\exchange\UsefullExchangeCommands.txt"
}
function pstexport
{
    Start-Process "$($AlyaScripts)\exchange\pstexport"
}
function SyncFrom-AzureFileStorageShare
{
    & "$($AlyaScripts)\filesync\SyncFrom-AzureFileStorageShare.ps1"
}
function SyncTo-AzureFileStorageShare
{
    & "$($AlyaScripts)\filesync\SyncTo-AzureFileStorageShare.ps1"
}
function Set-UserHomeAccess
{
    & "$($AlyaScripts)\filesync\Set-UserHomeAccess.ps1"
}
function BackupLocalFilesToShare
{
    & "$($AlyaScripts)\filesync\BackupLocalFilesToShare.cmd"
}
function SyncShareDirs
{
    & "$($AlyaScripts)\filesync\SyncShareDirs.cmd"
}
function SyncTo-SharePoint
{
    & "$($AlyaScripts)\filesync\SyncTo-SharePoint.cmd"
}
function Enable-PINReset
{
    Start-Process "$($AlyaScripts)\intune\Enable-PINReset.txt"
}
function Create-IntuneWin32Packages
{
    & "$($AlyaScripts)\intune\Create-IntuneWin32Packages.ps1"
}

function Set-IntuneAsMdmAuthority
{
    & "$($AlyaScripts)\intune\Set-IntuneAsMdmAuthority.ps1"
}
function Set-IntuneBranding
{
    & "$($AlyaScripts)\intune\Set-IntuneBranding.ps1"
}
function Configure-IntuneDeviceCompliancePolicies
{
    & "$($AlyaScripts)\intune\Configure-IntuneDeviceCompliancePolicies.ps1"
}
function Upload-IntuneWin32Packages
{
    & "$($AlyaScripts)\intune\Upload-IntuneWin32Packages.ps1"
}
function Configure-IntuneWin32Packages
{
    & "$($AlyaScripts)\intune\Configure-IntuneWin32Packages.ps1"
}
function Upload-IntuneWebApps
{
    & "$($AlyaScripts)\intune\Upload-IntuneWebApps.ps1"
}
function Configure-IntuneWebApps
{
    & "$($AlyaScripts)\intune\Configure-IntuneWebApps.ps1"
}
function Export-ApplicationConfiguration
{
    & "$($AlyaScripts)\intune\Export-ApplicationConfiguration.ps1"
}
function Restart-IntuneWin32PackagesInstallation
{
    & "$($AlyaScripts)\intune\Restart-IntuneWin32PackagesInstallation.ps1"
}
function Download-Win32AppPrepTool
{
    & "$($AlyaScripts)\intune\Download-Win32AppPrepTool.ps1"
}
function Get-ProductCodeFromMsi
{
    & "$($AlyaScripts)\intune\Get-ProductCodeFromMsi.ps1"
}
function Export-IntuneConfiguration
{
    & "$($AlyaScripts)\intune\Export-IntuneConfiguration.ps1"
}
function Get-IntunePowershellSamples
{
    & "$($AlyaScripts)\intune\Get-IntunePowershellSamples.ps1"
}
function extractPackages
{
    Start-Process "$($AlyaScripts)\intune\extractPackages"
}
function Add-PSTNGateway
{
    & "$($AlyaScripts)\pstn\Add-PSTNGateway.ps1"
}
function Set-PSTNForwarding
{
    & "$($AlyaScripts)\pstn\Set-PSTNForwarding.ps1"
}
function Set-VoiceRouting
{
    & "$($AlyaScripts)\pstn\Set-VoiceRouting.ps1"
}
function Activate-User
{
    & "$($AlyaScripts)\pstn\Activate-User.ps1"
}
function List-User
{
    & "$($AlyaScripts)\pstn\List-User.ps1"
}
function Start-NamingConventionAzure
{
    & "$($AlyaData)\naming\NamingConventionAzure.xlsx"
}
function Start-NamingConventionOffice365
{
    & "$($AlyaData)\naming\NamingConventionOffice365.xlsx"
}
function Move-DevOpsTasks
{
    & "$($AlyaScripts)\source\Move-DevOpsTasks.ps1"
}
function Connect-GitRepository
{
    & "$($AlyaRoot)\02_GitClone.ps1"
}
function Git-Bash
{
    Set-Location "$($AlyaRoot)"
    & "$($AlyaGitRoot)\git-bash.exe"
}
function Git-Cmd
{
    Set-Location "$($AlyaRoot)"
    & "$($AlyaGitRoot)\git-cmd.exe"
}
function Git-CheckIn
{
    & "$($AlyaScripts)\source\Git-CheckIn.ps1"
}
function Git-Sync
{
    & "$($AlyaScripts)\source\Git-Sync.ps1"
}
function Fall2019Prod_00_prepareWvd
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\00_prepareWvd.ps1"
}
function Fall2019Prod_01_createWvdTenant
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\01_createWvdTenant.ps1"
}
function Fall2019Prod_02_createServicePrincipal
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\02_createServicePrincipal.ps1"
}
function Fall2019Prod_04_assignRoleToUsers
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\04_assignRoleToUsers.ps1"
}
function Fall2019Prod_05_prepareShare
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\05_prepareShare.ps1"
}
function Fall2019Prod_06_createAppHostPool_hpol001
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\06_createAppHostPool_hpol001.ps1"
}
function Fall2019Prod_07_createRdpHostPool_hpol002
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\07_createRdpHostPool_hpol002.ps1"
}
function Fall2019Prod_08_updateAppHostPool_hpol001
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\08_updateAppHostPool_hpol001.ps1"
}
function Fall2019Prod_09_updateRdpHostPool_hpol002
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\09_updateRdpHostPool_hpol002.ps1"
}
function Fall2019Prod_10_removeAppHostPool_hpol001
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\10_removeAppHostPool_hpol001.ps1"
}
function Fall2019Prod_11_removeRdpHostPool_hpol002
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\11_removeRdpHostPool_hpol002.ps1"
}
function Fall2019Prod_12_AddLoadBalancer_hpol001
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\12_AddLoadBalancer_hpol001.ps1"
}
function Fall2019Prod_12_AddLoadBalancer_hpol002
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\12_AddLoadBalancer_hpol002.ps1"
}
function Fall2019Prod_13_updateLocalFiles_hpol001
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\13_updateLocalFiles_hpol001.ps1"
}
function Fall2019Prod_15_createOrUpdateAppGroups_hpol001
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\15_createOrUpdateAppGroups_hpol001.ps1"
}
function Fall2019Prod_16_createOrUpdateAppGroups_hpol002
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\16_createOrUpdateAppGroups_hpol002.ps1"
}
function Fall2019Prod_18_setAppGroupIcons
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\18_setAppGroupIcons.ps1"
}
function Fall2019Prod_19_setHostPoolToValidation
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\19_setHostPoolToValidation.ps1"
}
function Fall2019Prod_20_assignUsersToGroups
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\20_assignUsersToGroups.ps1"
}
function Fall2019Prod_21_addUserToGroup
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\21_addUserToGroup.ps1"
}
function Fall2019Prod_22_setHostPoolCustomProerties
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\22_setHostPoolCustomProerties.ps1"
}
function Fall2019Prod_30_removeAppGroups
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\30_removeAppGroups.ps1"
}
function Fall2019Prod_31_removeSessionHosts
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\31_removeSessionHosts.ps1"
}
function Fall2019Prod_32_removeUserSessions
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\32_removeUserSessions.ps1"
}
function Fall2019Prod_33_removeAllSessions
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\33_removeAllSessions.ps1"
}
function Fall2019Prod_34_killOldDisconnectedSessions
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\34_killOldDisconnectedSessions.ps1"
}
function Fall2019Prod_35_listAllSessions
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\35_listAllSessions.ps1"
}
function Fall2019Prod_36_removeUserFromAllPools
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\36_removeUserFromAllPools.ps1"
}
function Fall2019Prod_37_allowNewSessionsOnAllHosts
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\37_allowNewSessionsOnAllHosts.ps1"
}
function Fall2019Prod_40_listRds
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\40_listRds.ps1"
}
function Fall2019Prod_41_getDiagnostics
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\41_getDiagnostics.ps1"
}
function Fall2019Prod_43_sendMessageToUsers
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\43_sendMessageToUsers.ps1"
}
function Fall2019Prod_48_logoutUserDirect
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\48_logoutUserDirect.ps1"
}
function Fall2019Prod_50_resizeVhdFiles
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\50_resizeVhdFiles.ps1"
}
function Fall2019Prod_51_resizeHostpoolVmSku
{
	& "$($AlyaScripts)\wvd\admin\fall2019prod\51_resizeHostpoolVmSku.ps1"
}
function Fall2019Test_00_prepareWvd
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\00_prepareWvd.ps1"
}
function Fall2019Test_01_createWvdTenant
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\01_createWvdTenant.ps1"
}
function Fall2019Test_02_createServicePrincipal
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\02_createServicePrincipal.ps1"
}
function Fall2019Test_04_assignRoleToUsers
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\04_assignRoleToUsers.ps1"
}
function Fall2019Test_05_prepareShare
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\05_prepareShare.ps1"
}
function Fall2019Test_06_createAppHostPool_hpol001
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\06_createAppHostPool_hpol001.ps1"
}
function Fall2019Test_07_createRdpHostPool_hpol002
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\07_createRdpHostPool_hpol002.ps1"
}
function Fall2019Test_08_updateAppHostPool_hpol001
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\08_updateAppHostPool_hpol001.ps1"
}
function Fall2019Test_09_updateRdpHostPool_hpol002
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\09_updateRdpHostPool_hpol002.ps1"
}
function Fall2019Test_10_removeAppHostPool_hpol001
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\10_removeAppHostPool_hpol001.ps1"
}
function Fall2019Test_11_removeRdpHostPool_hpol002
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\11_removeRdpHostPool_hpol002.ps1"
}
function Fall2019Test_12_AddLoadBalancer_hpol001
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\12_AddLoadBalancer_hpol001.ps1"
}
function Fall2019Test_12_AddLoadBalancer_hpol002
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\12_AddLoadBalancer_hpol002.ps1"
}
function Fall2019Test_13_updateLocalFiles_hpol001
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\13_updateLocalFiles_hpol001.ps1"
}
function Fall2019Test_15_createOrUpdateAppGroups_hpol001
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\15_createOrUpdateAppGroups_hpol001.ps1"
}
function Fall2019Test_16_createOrUpdateAppGroups_hpol002
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\16_createOrUpdateAppGroups_hpol002.ps1"
}
function Fall2019Test_18_setAppGroupIcons
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\18_setAppGroupIcons.ps1"
}
function Fall2019Test_19_setHostPoolToValidation
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\19_setHostPoolToValidation.ps1"
}
function Fall2019Test_20_assignUsersToGroups
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\20_assignUsersToGroups.ps1"
}
function Fall2019Test_21_addUserToGroup
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\21_addUserToGroup.ps1"
}
function Fall2019Test_22_setHostPoolCustomProerties
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\22_setHostPoolCustomProerties.ps1"
}
function Fall2019Test_30_removeAppGroups
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\30_removeAppGroups.ps1"
}
function Fall2019Test_31_removeSessionHosts
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\31_removeSessionHosts.ps1"
}
function Fall2019Test_32_removeUserSessions
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\32_removeUserSessions.ps1"
}
function Fall2019Test_33_removeAllSessions
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\33_removeAllSessions.ps1"
}
function Fall2019Test_34_killOldDisconnectedSessions
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\34_killOldDisconnectedSessions.ps1"
}
function Fall2019Test_35_listAllSessions
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\35_listAllSessions.ps1"
}
function Fall2019Test_36_removeUserFromAllPools
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\36_removeUserFromAllPools.ps1"
}
function Fall2019Test_37_allowNewSessionsOnAllHosts
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\37_allowNewSessionsOnAllHosts.ps1"
}
function Fall2019Test_40_listRds
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\40_listRds.ps1"
}
function Fall2019Test_41_getDiagnostics
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\41_getDiagnostics.ps1"
}
function Fall2019Test_43_sendMessageToUsers
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\43_sendMessageToUsers.ps1"
}
function Fall2019Test_48_logoutUserDirect
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\48_logoutUserDirect.ps1"
}
function Fall2019Test_50_resizeVhdFiles
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\50_resizeVhdFiles.ps1"
}
function Fall2019Test_51_resizeHostpoolVmSku
{
	& "$($AlyaScripts)\wvd\admin\fall2019test\51_resizeHostpoolVmSku.ps1"
}
function Create-AutoscalingServicePrincipal
{
    & "$($AlyaScripts)\wvd\autoscale\Create-AutoscalingServicePrincipal.ps1"
}
function Save-AutoscalingCredentials
{
    & "$($AlyaScripts)\wvd\autoscale\Save-AutoscalingCredentials.ps1"
}
function ScaleHostPool_Alya
{
    & "$($AlyaScripts)\wvd\autoscale\ScaleHostPool_Alya.ps1"
}
function ScaleHostPool_MS
{
    & "$($AlyaScripts)\wvd\autoscale\ScaleHostPool_MS.ps1"
}
function Get-RegistrationToken-Prod
{
    & "$($AlyaScripts)\wvd\client\Get-RegistrationToken-Prod.ps1"
}
function Get-RegistrationToken-Test
{
    & "$($AlyaScripts)\wvd\client\Get-RegistrationToken-Test.ps1"
}
function Reinstall-Agent
{
    & "$($AlyaScripts)\wvd\client\Reinstall-Agent.ps1"
}
function Create-ImageHostClient
{
    & "$($AlyaScripts)\wvd\image\Create-ImageHostClient.ps1"
}
function Create-ImageHostServer
{
    & "$($AlyaScripts)\wvd\image\Create-ImageHostServer.ps1"
}
function Prepare-ImageClient
{
    & "$($AlyaScripts)\wvd\image\Prepare-ImageClient.ps1"
}
function Prepare-ImageServer
{
    & "$($AlyaScripts)\wvd\image\Prepare-ImageServer.ps1"
}
function ImageInstallTools
{
    Start-Process "$($AlyaScripts)\wvd\image\install"
}
function admTemplates
{
    Start-Process "$($AlyaScripts)\wvd\wvdGpo\admTemplates"
}
function groupPolicies
{
    Start-Process "$($AlyaScripts)\wvd\wvdGpo\groupPolicies"
}
function wvdIcons
{
    Start-Process "$($AlyaScripts)\wvd\wvdIcons"
}
function wvdStartApps
{
    Start-Process "$($AlyaScripts)\wvd\wvdStartApps"
}
function wvdTheme
{
    Start-Process "$($AlyaScripts)\wvd\wvdTheme"
}
function Clean-Image
{
    & "$($AlyaScripts)\wvd\image\Clean-Image.ps1"
}
function Edit-Configuration
{
    if (-Not (Test-Path "$($AlyaData)\ConfigureEnv.ps1"))
    {
        Copy-Item -Path "$($AlyaScripts)\ConfigureEnvTemplate.ps1" -Destination "$($AlyaData)\ConfigureEnv.ps1"
		Write-Warning "Your custom variables were not present!"
		Write-Warning "  $PSScriptRoot\data\ConfigureEnv.ps1"
		Write-Warning "We have copied a template from"
		Write-Warning "  $PSScriptRoot\scripts\ConfigureEnvTemplate.ps1"
    }
    & "$($env:windir)\System32\WindowsPowerShell\v1.0\powershell_ise.exe" "$($AlyaData)\ConfigureEnv.ps1"
}

#Menu show function
function Show-Menu
{
    Param($menu, $level)
    do
    {
        Write-Host "Alya Consulting " -ForegroundColor $AlyaColor -NoNewline
        Write-Host "Cloud Configuration Menu" -ForegroundColor $TitleColor
        $switch = $true
        foreach($menuEntry in $menu)
        {
            $color = $MenuColor
            if ($menuEntry[0] -eq "b")
            {
                $color = $CommandWarning
            }
            if ($menuEntry[0] -eq "q")
            {
                $color = $CommandError
            }
            if ($switch)
            {
                Write-Host ("$([string]$menuEntry[0]): $([string]$menuEntry[1])".PadRight(50, " ") + "   ") -ForegroundColor $color -NoNewline
                $switch = $false
            }
            else
            {
                Write-Host "$([string]$menuEntry[0]): $([string]$menuEntry[1])".PadRight(50, " ") -ForegroundColor $color
                $switch = $true
            }
        }
        if (-Not $switch) { Write-Host "" }
        Write-Host "Please make a selection" -ForegroundColor $CommandInfo
        Switch ($level)
        {
            1 { if (-Not $m1) { $input = Read-Host } else { $input = $m1 } }
            2 { if (-Not $m2) { $input = Read-Host } else { $input = $m2 } }
            3 { if (-Not $m3) { $input = Read-Host } else { $input = $m3 } }
            4 { if (-Not $m4) { $input = Read-Host } else { $input = $m4 } }
            5 { if (-Not $m5) { $input = Read-Host } else { $input = $m5 } }
        }
        foreach($menuEntry in $menu)
        {
            if ($input -eq $menuEntry[0])
            {
                switch ($menuEntry[2])
                {
                    "return" { 
                        Stop-Transcript
                        exit
                    }
                    "back" { 
                        if ($level -gt 1) {
                            $menu = $global:lastMenu[$global:lastMenu.Count-1]
                            $global:lastMenu.RemoveAt($global:lastMenu.Count-1)
                            Show-Menu -menu $menu -level ($level-1) 
                        }
                        else {
                            Show-Menu -menu $menuDef -level 1
                        }
                    }
                    "" {
                        $null = $global:lastMenu.Add($menu)
                        Show-Menu -menu $menuEntry[3] -level ($level+1)
                    }
                    default {
                        (Get-Item "function:$($menuEntry[2])").ScriptBlock.Invoke()
                        if (-Not $unattended)
                        {
                            pause
                        }
                        Clear-Host
                        #Show-Menu -menu $menuDef -level 1
                        Stop-Transcript
                        exit
                    }
                }
            }
        }
    }
    until ($false)
}

#Running menu
$global:lastMenu = New-Object System.Collections.ArrayList
Show-Menu -menu $menuDef -level 1
