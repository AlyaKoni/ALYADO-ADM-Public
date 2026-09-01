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
    06.11.2019 Konrad Brunner       Initial Version
    25.02.2020 Konrad Brunner       Added tenant configurations
    06.03.2020 Konrad Brunner       Added sharepoint configurations
    13.09.2020 Konrad Brunner       Added AAD configurations
    06.02.2026 Konrad Brunner       Added powershell documentation

#>

<#
.SYNOPSIS
Provides an interactive PowerShell-based start menu for executing various Alya Consulting administrative and configuration scripts.

.DESCRIPTION
The 03_StartMenu.ps1 script serves as the central command interface for the Alya Base Configuration environment. It loads a predefined configuration, starts a PowerShell transcript for logging, and displays a hierarchical interactive menu. The menu allows the user to execute a broad range of management scripts for Azure, Office 365, Intune, SharePoint, Exchange, Windows Virtual Desktop, and other related administration tasks. The menu can be navigated interactively, or preconfigured selections can be automated through optional parameters.

.PARAMETER unattended
Runs the script in unattended mode, bypassing pause prompts.

.PARAMETER m1
Specifies the first-level menu choice when running in unattended mode.

.PARAMETER m2
Specifies the second-level menu choice when running in unattended mode.

.PARAMETER m3
Specifies the third-level menu choice when running in unattended mode.

.PARAMETER m4
Specifies the fourth-level menu choice when running in unattended mode.

.PARAMETER m5
Specifies the fifth-level menu choice when running in unattended mode.

.PARAMETER o1
Optional parameter 1 that can be passed to scripts for additional customization.

.PARAMETER o2
Optional parameter 2 that can be passed to scripts for additional customization.

.PARAMETER o3
Optional parameter 3 that can be passed to scripts for additional customization.

.INPUTS
None. The script accepts input through parameters or user interaction via menu selection.

.OUTPUTS
None directly. The script executes other PowerShell scripts and may produce log files in the AlyaLogs directory.

.EXAMPLE
PS> .\03_StartMenu.ps1
Launches the Alya Base Configuration start menu interactively.

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
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

# Reading configuration
. $PSScriptRoot\01_ConfigureEnv.ps1

# Starting Transcript
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

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBf2CPGvD49bvOz
# UFE6oHJPu0Kf4mC/IYJJEOXFrPvT7qCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFKBuWce
# ROplnOaRF5G2HPI+ybTrSSj9VVlpIz41MAONMA0GCSqGSIb3DQEBAQUABIICAMPw
# iKc2WH8uSBi9ncLx91nF0cKD/BeFXDmIKSJ+54HAaM1rbE+SbLBd3e8pjNjzdBYQ
# taiNu+Gq5hEKXEuePnUGxT8uIIDbP0EFLngCp+RBJCRc6pn7FPr7/8nM8fZy6xfm
# c0sXx7ljUh1xAg0LyNRszx+wbgQjGuvuVCbF3G1D0ZLmak5i+FdBzrlDTd+w3gnz
# iUbf9XLdXB4w1tvUULd06mBQbeCbDOBspqxmMS5HnCXkfdiy4SO+b7gEKrrspBDw
# L5IPcpzC/T45ylN150qFEe7B3xDjeG/MvVSUFCHXu+EaHy4U7Uy2k09NK6J5G+wG
# XApJP8kqwtwv8fd1sYwS5dMWtYGSlg+yhesQd7aEiiKQtL02POAhJgDxNtNcZYpv
# B1uh0I/1ri+5PF6hn/1nYyzugXWYA3p13bai+IxKkg9V5EMRW0s6okv+Hy5f5pYC
# 96XaNstrLCaJDcyU5CRZh8CLJN/Ke9JOu1aOzWxejlGfJx65u60wRf5VqBxXjcqQ
# F9t33tNE3vMz+Uz7DnB4UB30sQKaO+fOgv2qOwEd5EURq9qsNMgwVluenBjp1SS1
# YmWloIAgXSFuiRzGBWu3f8Q1MbfIkAPkgwPCKYQp3VVAt4lqWi4akyu/EIxUoz/A
# ItDD9MFF+V1QQ8C+BvdeCm9+iN7hYHXOZ8tNFNJjoYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCDXSkLt8sG8OUGWlmD2U9G9ql2ABZhZ2uwNxo58E884CwIUQRzD
# bYX/PSQdpep95rVRJEWgCzQYDzIwMjYwODI5MTU0NTAwWjADAgEBoF2kWzBZMQsw
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
# BDEyBDArDQKqWzjvONAkgvJljJWU2DhPlwm29HnO7jKz3Oq6MiftlmOVj+GS3d/Q
# NKOu7U4wgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGAfv/UJrIZ9o/QITgj8NffEwyIYMisSnv9DmBUj8TAcJpl
# gFt7qXvslVct4hxLOMNApnqPwVTbH8+9pnp19UcOBCX3WGvYWfc7PV3XvWxQtmMm
# EQz6OaRAIZ4QTaTl4DLIesMxAnW3/bBL0x/QPqLvnNm+CHNpwghN2XD7hiaaYtYU
# OfBrMcgGLNFxZGli4FNYTX+wNE7EXGYunaXFLs/k9g1ksu2exeagEcsBlyT0DAGz
# mmwXcRoi+EX+5rDJPfOIEJsTtduxyWa7K3kOFTrNQsxqB0nMyG+W6mgnA3bJWoYY
# IORPuqlk2YzqLF75KCufq5BK+UiiTg2zVhCcGR8dIyJurnwuGnDlFWgw4m6R4Vnh
# d2qAIT4jmu/9OnA8yuddrWyE9kfn11s7sj3DaFX0FsVVsBM+BIyWdeLF+ibwxfwB
# J2RzEbfI56jq+NX5qCDT5iOsJTqdrolXGgEC1e7E1fYYtxjG9uCNdu7IUrsSOtBK
# TXPQ4hJZz2/GKT+r97Lw
# SIG # End signature block
