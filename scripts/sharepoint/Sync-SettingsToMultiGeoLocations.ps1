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
    22.09.2025 Konrad Brunner       Initial Version

    This script is used to sync settings to all Multi-Geo locations. It requires following previous scripts to be run:
    - Configure-ServiceApplication
    - Install-ServiceApplicationCertificate
    06.02.2026 Konrad Brunner       Added powershell documentation

#>

<#
.SYNOPSIS
Synchronizes SharePoint Online tenant settings from the default Multi-Geo location to all other geographic locations within the organization.

.DESCRIPTION
The Sync-SettingsToMultiGeoLocations.ps1 script connects to the main SharePoint Online tenant using PnP PowerShell and retrieves tenant configuration settings. It then iterates through all non-default Multi-Geo locations and applies the same configuration settings to each, ensuring consistent tenant-level configuration across all geographic regions. The script can perform a dry run (simulation) without applying any changes and generates logs for all operations.

.PARAMETER SharePointServiceAppClientId
Specifies the Azure AD Client ID used for authentication with SharePoint Online.

.PARAMETER SharePointServiceAppThumbprint
Specifies the certificate thumbprint for the registered Azure AD application used to authenticate with SharePoint Online.

.PARAMETER DryRun
Indicates whether the script should perform a simulation without actually updating tenant settings. Default is $false.

.INPUTS
None. The script does not take piped input.

.OUTPUTS
JSON files containing tenant configuration data per Multi-Geo location and a transcript log file detailing execution results.

.EXAMPLE
PS> .\Sync-SettingsToMultiGeoLocations.ps1 -SharePointServiceAppClientId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -SharePointServiceAppThumbprint "abcdef123456abcdef123456abcdef123456abcdef" -DryRun $true

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$SharePointServiceAppClientId,
    [Parameter(Mandatory=$true)]
    [string]$SharePointServiceAppThumbprint,
    [bool]$DryRun = $false
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Sync-SettingsToMultiGeoLocations-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "PnP.PowerShell"

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "sharepoint | Sync-SettingsToMultiGeoLocations | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Login to main site
Write-Host "Login to main site" -ForegroundColor $CommandInfo
$conPnPAdmin = Connect-PnPOnline -Url $AlyaSharePointAdminUrl -Tenant $AlyaTenantName -ClientId $SharePointServiceAppClientId -Thumbprint $SharePointServiceAppThumbprint -ReturnConnection

# Getting configurations
Write-Host "Getting configurations" -ForegroundColor $CommandInfo
# $siteScriptsAdmin = Get-PnPSiteScript -Connection $conPnPAdmin
# $siteDesignsAdmin = Get-PnPSiteDesign -Connection $conPnPAdmin
$tenantInstances = Get-PnPTenantInstance -Connection $conPnPAdmin
$tenant = Get-PnPTenant -Connection $conPnPAdmin
$tenant | ConvertTo-Json -Depth 10 | Out-File "$($AlyaData)\sharepoint\TenantConfig-DEU.json" -Force

# Processing locations
Write-Host "Processing locations" -ForegroundColor $CommandInfo
foreach($location in $tenantInstances)
{
    if ($location.IsDefaultDataLocation -eq $true)
    {
        continue
    }
    Write-Host "Location: $($location.DataLocation) $($location.TenantAdminUrl)" -ForegroundColor $CommandInfo
    $adminUrl = $location.TenantAdminUrl
    $conPnP = Connect-PnPOnline -Url $adminUrl -Tenant $AlyaTenantName -ClientId $SharePointServiceAppClientId -Thumbprint $SharePointServiceAppThumbprint -ReturnConnection

    Write-Host "Tenant settings" -ForegroundColor $CommandInfo
    $tenantPnP = Get-PnPTenant -Connection $conPnP
    $tenantPnP | ConvertTo-Json -Depth 10 | Out-File "$($AlyaData)\sharepoint\TenantConfig-$($location.DataLocation).json" -Force
    if ($DryRun -eq $false)
    {
        $retries = 5
        do {
            try {
                $parms = @{}
                if ($tenantPnP.SpecialCharactersStateInFileFolderNames -ne $tenant.SpecialCharactersStateInFileFolderNames) { $parms["SpecialCharactersStateInFileFolderNames"] = $tenant.SpecialCharactersStateInFileFolderNames }
                if ($tenantPnP.ExternalServicesEnabled -ne $tenant.ExternalServicesEnabled) { $parms["ExternalServicesEnabled"] = $tenant.ExternalServicesEnabled }
                if ($tenantPnP.NoAccessRedirectUrl -ne $tenant.NoAccessRedirectUrl) { $parms["NoAccessRedirectUrl"] = $tenant.NoAccessRedirectUrl }
                if ($tenantPnP.SharingCapability -ne $tenant.SharingCapability) { $parms["SharingCapability"] = $tenant.SharingCapability }
                if ($tenantPnP.DisplayStartASiteOption -ne $tenant.DisplayStartASiteOption) { $parms["DisplayStartASiteOption"] = $tenant.DisplayStartASiteOption }
                if ($tenantPnP.StartASiteFormUrl -ne $tenant.StartASiteFormUrl) { $parms["StartASiteFormUrl"] = $tenant.StartASiteFormUrl }
                if ($tenantPnP.ShowAllUsersClaim -ne $tenant.ShowAllUsersClaim) { $parms["ShowAllUsersClaim"] = $tenant.ShowAllUsersClaim }
                if ($tenantPnP.ShowEveryoneExceptExternalUsersClaim -ne $tenant.ShowEveryoneExceptExternalUsersClaim) { $parms["ShowEveryoneExceptExternalUsersClaim"] = $tenant.ShowEveryoneExceptExternalUsersClaim }
                if ($tenantPnP.SearchResolveExactEmailOrUPN -ne $tenant.SearchResolveExactEmailOrUPN) { $parms["SearchResolveExactEmailOrUPN"] = $tenant.SearchResolveExactEmailOrUPN }
                if ($tenantPnP.OfficeClientADALDisabled -ne $tenant.OfficeClientADALDisabled) { $parms["OfficeClientADALDisabled"] = $tenant.OfficeClientADALDisabled }
                if ($tenantPnP.LegacyAuthProtocolsEnabled -ne $tenant.LegacyAuthProtocolsEnabled) { $parms["LegacyAuthProtocolsEnabled"] = $tenant.LegacyAuthProtocolsEnabled }
                if ($tenantPnP.RequireAcceptingAccountMatchInvitedAccount -ne $tenant.RequireAcceptingAccountMatchInvitedAccount) { $parms["RequireAcceptingAccountMatchInvitedAccount"] = $tenant.RequireAcceptingAccountMatchInvitedAccount }
                if ($tenantPnP.ProvisionSharedWithEveryoneFolder -ne $tenant.ProvisionSharedWithEveryoneFolder) { $parms["ProvisionSharedWithEveryoneFolder"] = $tenant.ProvisionSharedWithEveryoneFolder }
                if ($tenantPnP.SignInAccelerationDomain -ne $tenant.SignInAccelerationDomain) { $parms["SignInAccelerationDomain"] = $tenant.SignInAccelerationDomain }
                if ($tenantPnP.EnableGuestSignInAcceleration -ne $tenant.EnableGuestSignInAcceleration) { $parms["EnableGuestSignInAcceleration"] = $tenant.EnableGuestSignInAcceleration }
                if ($tenantPnP.UsePersistentCookiesForExplorerView -ne $tenant.UsePersistentCookiesForExplorerView) { $parms["UsePersistentCookiesForExplorerView"] = $tenant.UsePersistentCookiesForExplorerView }
                if ($tenantPnP.BccExternalSharingInvitations -ne $tenant.BccExternalSharingInvitations) { $parms["BccExternalSharingInvitations"] = $tenant.BccExternalSharingInvitations }
                if ($tenantPnP.BccExternalSharingInvitationsList -ne $tenant.BccExternalSharingInvitationsList) { $parms["BccExternalSharingInvitationsList"] = $tenant.BccExternalSharingInvitationsList }
                if ($tenantPnP.PublicCdnEnabled -ne $tenant.PublicCdnEnabled) { $parms["PublicCdnEnabled"] = $tenant.PublicCdnEnabled }
                if ($tenantPnP.PublicCdnAllowedFileTypes -ne $tenant.PublicCdnAllowedFileTypes) { $parms["PublicCdnAllowedFileTypes"] = $tenant.PublicCdnAllowedFileTypes }
                if ($tenantPnP.RequireAnonymousLinksExpireInDays -ne $tenant.RequireAnonymousLinksExpireInDays) { $parms["RequireAnonymousLinksExpireInDays"] = $tenant.RequireAnonymousLinksExpireInDays }
                if ($tenantPnP.SharingAllowedDomainList -ne $tenant.SharingAllowedDomainList) { $parms["SharingAllowedDomainList"] = $tenant.SharingAllowedDomainList }
                if ($tenantPnP.SharingBlockedDomainList -ne $tenant.SharingBlockedDomainList) { $parms["SharingBlockedDomainList"] = $tenant.SharingBlockedDomainList }
                if ($tenantPnP.SharingDomainRestrictionMode -ne $tenant.SharingDomainRestrictionMode) { $parms["SharingDomainRestrictionMode"] = $tenant.SharingDomainRestrictionMode }
                if ($tenantPnP.OneDriveStorageQuota -ne $tenant.OneDriveStorageQuota) { $parms["OneDriveStorageQuota"] = $tenant.OneDriveStorageQuota }
                if ($tenantPnP.OneDriveForGuestsEnabled -ne $tenant.OneDriveForGuestsEnabled) { $parms["OneDriveForGuestsEnabled"] = $tenant.OneDriveForGuestsEnabled }
                if ($tenantPnP.IPAddressEnforcement -ne $tenant.IPAddressEnforcement) { $parms["IPAddressEnforcement"] = $tenant.IPAddressEnforcement }
                if ($tenantPnP.IPAddressAllowList -ne $tenant.IPAddressAllowList) { $parms["IPAddressAllowList"] = $tenant.IPAddressAllowList }
                if ($tenantPnP.IPAddressWACTokenLifetime -ne $tenant.IPAddressWACTokenLifetime) { $parms["IPAddressWACTokenLifetime"] = $tenant.IPAddressWACTokenLifetime }
                if ($tenantPnP.UseFindPeopleInPeoplePicker -ne $tenant.UseFindPeopleInPeoplePicker) { $parms["UseFindPeopleInPeoplePicker"] = $tenant.UseFindPeopleInPeoplePicker }
                if ($tenantPnP.DefaultSharingLinkType -ne $tenant.DefaultSharingLinkType) { $parms["DefaultSharingLinkType"] = $tenant.DefaultSharingLinkType }
                if ($tenantPnP.ODBMembersCanShare -ne $tenant.ODBMembersCanShare) { $parms["ODBMembersCanShare"] = $tenant.ODBMembersCanShare }
                if ($tenantPnP.ODBAccessRequests -ne $tenant.ODBAccessRequests) { $parms["ODBAccessRequests"] = $tenant.ODBAccessRequests }
                if ($tenantPnP.PreventExternalUsersFromReSharing -ne $tenant.PreventExternalUsersFromReSharing) { $parms["PreventExternalUsersFromReSharing"] = $tenant.PreventExternalUsersFromReSharing }
                if ($tenantPnP.ShowPeoplePickerSuggestionsForGuestUsers -ne $tenant.ShowPeoplePickerSuggestionsForGuestUsers) { $parms["ShowPeoplePickerSuggestionsForGuestUsers"] = $tenant.ShowPeoplePickerSuggestionsForGuestUsers }
                if ($tenantPnP.FileAnonymousLinkType -ne $tenant.FileAnonymousLinkType) { $parms["FileAnonymousLinkType"] = $tenant.FileAnonymousLinkType }
                if ($tenantPnP.FolderAnonymousLinkType -ne $tenant.FolderAnonymousLinkType) { $parms["FolderAnonymousLinkType"] = $tenant.FolderAnonymousLinkType }
                if ($tenantPnP.NotifyOwnersWhenItemsReShared -ne $tenant.NotifyOwnersWhenItemsReShared) { $parms["NotifyOwnersWhenItemsReShared"] = $tenant.NotifyOwnersWhenItemsReShared }
                if ($tenantPnP.NotifyOwnersWhenInvitationsAccepted -ne $tenant.NotifyOwnersWhenInvitationsAccepted) { $parms["NotifyOwnersWhenInvitationsAccepted"] = $tenant.NotifyOwnersWhenInvitationsAccepted }
                if ($tenantPnP.NotificationsInOneDriveForBusinessEnabled -ne $tenant.NotificationsInOneDriveForBusinessEnabled) { $parms["NotificationsInOneDriveForBusinessEnabled"] = $tenant.NotificationsInOneDriveForBusinessEnabled }
                if ($tenantPnP.NotificationsInSharePointEnabled -ne $tenant.NotificationsInSharePointEnabled) { $parms["NotificationsInSharePointEnabled"] = $tenant.NotificationsInSharePointEnabled }
                if ($tenantPnP.OwnerAnonymousNotification -ne $tenant.OwnerAnonymousNotification) { $parms["OwnerAnonymousNotification"] = $tenant.OwnerAnonymousNotification }
                if ($tenantPnP.CommentsOnSitePagesDisabled -ne $tenant.CommentsOnSitePagesDisabled) { $parms["CommentsOnSitePagesDisabled"] = $tenant.CommentsOnSitePagesDisabled }
                if ($tenantPnP.SocialBarOnSitePagesDisabled -ne $tenant.SocialBarOnSitePagesDisabled) { $parms["SocialBarOnSitePagesDisabled"] = $tenant.SocialBarOnSitePagesDisabled }
                if ($tenantPnP.OrphanedPersonalSitesRetentionPeriod -ne $tenant.OrphanedPersonalSitesRetentionPeriod) { $parms["OrphanedPersonalSitesRetentionPeriod"] = $tenant.OrphanedPersonalSitesRetentionPeriod }
                if ($tenantPnP.DisallowInfectedFileDownload -ne $tenant.DisallowInfectedFileDownload) { $parms["DisallowInfectedFileDownload"] = $tenant.DisallowInfectedFileDownload }
                if ($tenantPnP.DefaultLinkPermission -ne $tenant.DefaultLinkPermission) { $parms["DefaultLinkPermission"] = $tenant.DefaultLinkPermission }
                if ($tenantPnP.ConditionalAccessPolicy -ne $tenant.ConditionalAccessPolicy) { $parms["ConditionalAccessPolicy"] = $tenant.ConditionalAccessPolicy }
                if ($tenantPnP.AllowDownloadingNonWebViewableFiles -ne $tenant.AllowDownloadingNonWebViewableFiles) { $parms["AllowDownloadingNonWebViewableFiles"] = $tenant.AllowDownloadingNonWebViewableFiles }
                if ($tenantPnP.AllowEditing -ne $tenant.AllowEditing) { $parms["AllowEditing"] = $tenant.AllowEditing }
                if ($tenantPnP.ApplyAppEnforcedRestrictionsToAdHocRecipients -ne $tenant.ApplyAppEnforcedRestrictionsToAdHocRecipients) { $parms["ApplyAppEnforcedRestrictionsToAdHocRecipients"] = $tenant.ApplyAppEnforcedRestrictionsToAdHocRecipients }
                if ($tenantPnP.FilePickerExternalImageSearchEnabled -ne $tenant.FilePickerExternalImageSearchEnabled) { $parms["FilePickerExternalImageSearchEnabled"] = $tenant.FilePickerExternalImageSearchEnabled }
                if ($tenantPnP.EmailAttestationRequired -ne $tenant.EmailAttestationRequired) { $parms["EmailAttestationRequired"] = $tenant.EmailAttestationRequired }
                if ($tenantPnP.EmailAttestationReAuthDays -ne $tenant.EmailAttestationReAuthDays) { $parms["EmailAttestationReAuthDays"] = $tenant.EmailAttestationReAuthDays }
                if ($tenantPnP.HideDefaultThemes -ne $tenant.HideDefaultThemes) { $parms["HideDefaultThemes"] = $tenant.HideDefaultThemes }
                if ($tenantPnP.DisabledWebPartIds -ne $tenant.DisabledWebPartIds) { $parms["DisabledWebPartIds"] = $tenant.DisabledWebPartIds }
                if ($tenantPnP.EnableAIPIntegration -ne $tenant.EnableAIPIntegration) { $parms["EnableAIPIntegration"] = $tenant.EnableAIPIntegration }
                #if ($tenantPnP.DisableCustomAppAuthentication -ne $tenant.DisableCustomAppAuthentication) { $parms["DisableCustomAppAuthentication"] = $tenant.DisableCustomAppAuthentication }
                if ($tenantPnP.InformationBarriersSuspension -ne $tenant.InformationBarriersSuspension) { $parms["InformationBarriersSuspension"] = $tenant.InformationBarriersSuspension }
                if ($tenantPnP.AllowFilesWithKeepLabelToBeDeletedODB -ne $tenant.AllowFilesWithKeepLabelToBeDeletedODB) { $parms["AllowFilesWithKeepLabelToBeDeletedODB"] = $tenant.AllowFilesWithKeepLabelToBeDeletedODB }
                if ($tenantPnP.AllowFilesWithKeepLabelToBeDeletedSPO -ne $tenant.AllowFilesWithKeepLabelToBeDeletedSPO) { $parms["AllowFilesWithKeepLabelToBeDeletedSPO"] = $tenant.AllowFilesWithKeepLabelToBeDeletedSPO }
                if ($tenantPnP.ExternalUserExpirationRequired -ne $tenant.ExternalUserExpirationRequired) { $parms["ExternalUserExpirationRequired"] = $tenant.ExternalUserExpirationRequired }
                if ($tenantPnP.ExternalUserExpireInDays -ne $tenant.ExternalUserExpireInDays) { $parms["ExternalUserExpireInDays"] = $tenant.ExternalUserExpireInDays }
                if ($tenantPnP.OneDriveRequestFilesLinkEnabled -ne $tenant.OneDriveRequestFilesLinkEnabled) { $parms["OneDriveRequestFilesLinkEnabled"] = $tenant.OneDriveRequestFilesLinkEnabled }
                if ($tenantPnP.EnableRestrictedAccessControl -ne $tenant.EnableRestrictedAccessControl) { $parms["EnableRestrictedAccessControl"] = $tenant.EnableRestrictedAccessControl }
                if ($tenantPnP.EnableAzureADB2BIntegration -ne $tenant.EnableAzureADB2BIntegration) { $parms["EnableAzureADB2BIntegration"] = $tenant.EnableAzureADB2BIntegration }
                if ($tenantPnP.CoreRequestFilesLinkEnabled -ne $tenant.CoreRequestFilesLinkEnabled) { $parms["CoreRequestFilesLinkEnabled"] = $tenant.CoreRequestFilesLinkEnabled }
                if ($tenantPnP.CoreRequestFilesLinkExpirationInDays -ne $tenant.CoreRequestFilesLinkExpirationInDays) { $parms["CoreRequestFilesLinkExpirationInDays"] = $tenant.CoreRequestFilesLinkExpirationInDays }
                if ($tenantPnP.DisableDocumentLibraryDefaultLabeling -ne $tenant.DisableDocumentLibraryDefaultLabeling) { $parms["DisableDocumentLibraryDefaultLabeling"] = $tenant.DisableDocumentLibraryDefaultLabeling }
                if ($tenantPnP.IsEnableAppAuthPopUpEnabled -ne $tenant.IsEnableAppAuthPopUpEnabled) { $parms["IsEnableAppAuthPopUpEnabled"] = $tenant.IsEnableAppAuthPopUpEnabled }
                if ($tenantPnP.ExpireVersionsAfterDays -ne $tenant.ExpireVersionsAfterDays) { $parms["ExpireVersionsAfterDays"] = $tenant.ExpireVersionsAfterDays }
                if ($tenantPnP.MajorVersionLimit -ne $tenant.MajorVersionLimit) { $parms["MajorVersionLimit"] = $tenant.MajorVersionLimit }
                if ($tenantPnP.EnableAutoExpirationVersionTrim -ne $tenant.EnableAutoExpirationVersionTrim) { $parms["EnableAutoExpirationVersionTrim"] = $tenant.EnableAutoExpirationVersionTrim }
                if ($tenantPnP.OneDriveLoopSharingCapability -ne $tenant.OneDriveLoopSharingCapability) { $parms["OneDriveLoopSharingCapability"] = $tenant.OneDriveLoopSharingCapability }
                if ($tenantPnP.OneDriveLoopDefaultSharingLinkScope -ne $tenant.OneDriveLoopDefaultSharingLinkScope) { $parms["OneDriveLoopDefaultSharingLinkScope"] = $tenant.OneDriveLoopDefaultSharingLinkScope }
                if ($tenantPnP.OneDriveLoopDefaultSharingLinkRole -ne $tenant.OneDriveLoopDefaultSharingLinkRole) { $parms["OneDriveLoopDefaultSharingLinkRole"] = $tenant.OneDriveLoopDefaultSharingLinkRole }
                if ($tenantPnP.CoreLoopSharingCapability -ne $tenant.CoreLoopSharingCapability) { $parms["CoreLoopSharingCapability"] = $tenant.CoreLoopSharingCapability }
                if ($tenantPnP.CoreLoopDefaultSharingLinkScope -ne $tenant.CoreLoopDefaultSharingLinkScope) { $parms["CoreLoopDefaultSharingLinkScope"] = $tenant.CoreLoopDefaultSharingLinkScope }
                if ($tenantPnP.CoreLoopDefaultSharingLinkRole -ne $tenant.CoreLoopDefaultSharingLinkRole) { $parms["CoreLoopDefaultSharingLinkRole"] = $tenant.CoreLoopDefaultSharingLinkRole }
                if ($tenantPnP.DisableVivaConnectionsAnalytics -ne $tenant.DisableVivaConnectionsAnalytics) { $parms["DisableVivaConnectionsAnalytics"] = $tenant.DisableVivaConnectionsAnalytics }
                if ($tenantPnP.IsCollabMeetingNotesFluidEnabled -ne $tenant.IsCollabMeetingNotesFluidEnabled) { $parms["IsCollabMeetingNotesFluidEnabled"] = $tenant.IsCollabMeetingNotesFluidEnabled }
                if ($tenantPnP.AllowAnonymousMeetingParticipantsToAccessWhiteboards -ne $tenant.AllowAnonymousMeetingParticipantsToAccessWhiteboards) { $parms["AllowAnonymousMeetingParticipantsToAccessWhiteboards"] = $tenant.AllowAnonymousMeetingParticipantsToAccessWhiteboards }
                if ($tenantPnP.IBImplicitGroupBased -ne $tenant.IBImplicitGroupBased) { $parms["IBImplicitGroupBased"] = $tenant.IBImplicitGroupBased }
                if ($tenantPnP.ShowPeoplePickerGroupSuggestionsForIB -ne $tenant.ShowPeoplePickerGroupSuggestionsForIB) { $parms["ShowPeoplePickerGroupSuggestionsForIB"] = $tenant.ShowPeoplePickerGroupSuggestionsForIB }
                if ($tenantPnP.BlockDownloadFileTypeIds -ne $tenant.BlockDownloadFileTypeIds) { $parms["BlockDownloadFileTypeIds"] = $tenant.BlockDownloadFileTypeIds }
                if ($tenantPnP.ExcludedBlockDownloadGroupIds -ne $tenant.ExcludedBlockDownloadGroupIds) { $parms["ExcludedBlockDownloadGroupIds"] = $tenant.ExcludedBlockDownloadGroupIds }
                if ($tenantPnP.StopNew2013Workflows -ne $tenant.StopNew2013Workflows) { $parms["StopNew2013Workflows"] = $tenant.StopNew2013Workflows }
                if ($tenantPnP.SiteOwnerManageLegacyServicePrincipalEnabled -ne $tenant.SiteOwnerManageLegacyServicePrincipalEnabled) { $parms["SiteOwnerManageLegacyServicePrincipalEnabled"] = $tenant.SiteOwnerManageLegacyServicePrincipalEnabled }
                if ($tenantPnP.BusinessConnectivityServiceDisabled -ne $tenant.BusinessConnectivityServiceDisabled) { $parms["BusinessConnectivityServiceDisabled"] = $tenant.BusinessConnectivityServiceDisabled }
                if ($tenantPnP.EnableSensitivityLabelForPDF -ne $tenant.EnableSensitivityLabelForPDF) { $parms["EnableSensitivityLabelForPDF"] = $tenant.EnableSensitivityLabelForPDF }
                if ($tenantPnP.IsDataAccessInCardDesignerEnabled -ne $tenant.IsDataAccessInCardDesignerEnabled) { $parms["IsDataAccessInCardDesignerEnabled"] = $tenant.IsDataAccessInCardDesignerEnabled }
                if ($tenantPnP.CoreSharingCapability -ne $tenant.CoreSharingCapability) { $parms["CoreSharingCapability"] = $tenant.CoreSharingCapability }
                if ($tenantPnP.BlockUserInfoVisibilityInOneDrive -ne $tenant.BlockUserInfoVisibilityInOneDrive) { $parms["BlockUserInfoVisibilityInOneDrive"] = $tenant.BlockUserInfoVisibilityInOneDrive }
                if ($tenantPnP.AllowOverrideForBlockUserInfoVisibility -ne $tenant.AllowOverrideForBlockUserInfoVisibility) { $parms["AllowOverrideForBlockUserInfoVisibility"] = $tenant.AllowOverrideForBlockUserInfoVisibility }
                if ($tenantPnP.AllowEveryoneExceptExternalUsersClaimInPrivateSite -ne $tenant.AllowEveryoneExceptExternalUsersClaimInPrivateSite) { $parms["AllowEveryoneExceptExternalUsersClaimInPrivateSite"] = $tenant.AllowEveryoneExceptExternalUsersClaimInPrivateSite }
                if ($tenantPnP.AIBuilderEnabled -ne $tenant.AIBuilderEnabled) { $parms["AIBuilderEnabled"] = $tenant.AIBuilderEnabled }
                if ($tenantPnP.AllowSensitivityLabelOnRecords -ne $tenant.AllowSensitivityLabelOnRecords) { $parms["AllowSensitivityLabelOnRecords"] = $tenant.AllowSensitivityLabelOnRecords }
                if ($tenantPnP.AnyoneLinkTrackUsers -ne $tenant.AnyoneLinkTrackUsers) { $parms["AnyoneLinkTrackUsers"] = $tenant.AnyoneLinkTrackUsers }
                if ($tenantPnP.EnableSiteArchive -ne $tenant.EnableSiteArchive) { $parms["EnableSiteArchive"] = $tenant.EnableSiteArchive }
                if ($tenantPnP.ESignatureEnabled -ne $tenant.ESignatureEnabled) { $parms["ESignatureEnabled"] = $tenant.ESignatureEnabled }
                if ($tenantPnP.BlockUserInfoVisibilityInSharePoint -ne $tenant.BlockUserInfoVisibilityInSharePoint) { $parms["BlockUserInfoVisibilityInSharePoint"] = $tenant.BlockUserInfoVisibilityInSharePoint }
                if ($tenantPnP.MarkNewFilesSensitiveByDefault -ne $tenant.MarkNewFilesSensitiveByDefault) { $parms["MarkNewFilesSensitiveByDefault"] = $tenant.MarkNewFilesSensitiveByDefault }
                if ($tenantPnP.OneDriveDefaultShareLinkScope -ne $tenant.OneDriveDefaultShareLinkScope) { $parms["OneDriveDefaultShareLinkScope"] = $tenant.OneDriveDefaultShareLinkScope }
                if ($tenantPnP.OneDriveDefaultShareLinkRole -ne $tenant.OneDriveDefaultShareLinkRole) { $parms["OneDriveDefaultShareLinkRole"] = $tenant.OneDriveDefaultShareLinkRole }
                if ($tenantPnP.OneDriveDefaultLinkToExistingAccess -ne $tenant.OneDriveDefaultLinkToExistingAccess) { $parms["OneDriveDefaultLinkToExistingAccess"] = $tenant.OneDriveDefaultLinkToExistingAccess }
                if ($tenantPnP.OneDriveBlockGuestsAsSiteAdmin -ne $tenant.OneDriveBlockGuestsAsSiteAdmin) { $parms["OneDriveBlockGuestsAsSiteAdmin"] = $tenant.OneDriveBlockGuestsAsSiteAdmin }
                if ($tenantPnP.RecycleBinRetentionPeriod -ne $tenant.RecycleBinRetentionPeriod) { $parms["RecycleBinRetentionPeriod"] = $tenant.RecycleBinRetentionPeriod }
                if ($tenantPnP.CoreDefaultShareLinkScope -ne $tenant.CoreDefaultShareLinkScope) { $parms["CoreDefaultShareLinkScope"] = $tenant.CoreDefaultShareLinkScope }
                if ($tenantPnP.CoreDefaultShareLinkRole -ne $tenant.CoreDefaultShareLinkRole) { $parms["CoreDefaultShareLinkRole"] = $tenant.CoreDefaultShareLinkRole }
                if ($tenantPnP.GuestSharingGroupAllowListInTenantByPrincipalIdentity -ne $tenant.GuestSharingGroupAllowListInTenantByPrincipalIdentity) { $parms["GuestSharingGroupAllowListInTenantByPrincipalIdentity"] = $tenant.GuestSharingGroupAllowListInTenantByPrincipalIdentity }
                if ($tenantPnP.OneDriveSharingCapability -ne $tenant.OneDriveSharingCapability) { $parms["OneDriveSharingCapability"] = $tenant.OneDriveSharingCapability }
                if ($tenantPnP.AllowWebPropertyBagUpdateWhenDenyAddAndCustomizePagesIsEnabled -ne $tenant.AllowWebPropertyBagUpdateWhenDenyAddAndCustomizePagesIsEnabled) { $parms["AllowWebPropertyBagUpdateWhenDenyAddAndCustomizePagesIsEnabled"] = $tenant.AllowWebPropertyBagUpdateWhenDenyAddAndCustomizePagesIsEnabled }
                if ($tenantPnP.SelfServiceSiteCreationDisabled -ne $tenant.SelfServiceSiteCreationDisabled) { $parms["SelfServiceSiteCreationDisabled"] = $tenant.SelfServiceSiteCreationDisabled }
                if ($tenantPnP.ExtendPermissionsToUnprotectedFiles -ne $tenant.ExtendPermissionsToUnprotectedFiles) { $parms["ExtendPermissionsToUnprotectedFiles"] = $tenant.ExtendPermissionsToUnprotectedFiles }
                if ($tenantPnP.WhoCanShareAllowListInTenant -ne $tenant.WhoCanShareAllowListInTenant) { $parms["WhoCanShareAllowListInTenant"] = $tenant.WhoCanShareAllowListInTenant }
                if ($tenantPnP.LegacyBrowserAuthProtocolsEnabled -ne $tenant.LegacyBrowserAuthProtocolsEnabled) { $parms["LegacyBrowserAuthProtocolsEnabled"] = $tenant.LegacyBrowserAuthProtocolsEnabled }
                if ($tenantPnP.EnableDiscoverableByOrganizationForVideos -ne $tenant.EnableDiscoverableByOrganizationForVideos) { $parms["EnableDiscoverableByOrganizationForVideos"] = $tenant.EnableDiscoverableByOrganizationForVideos }
                if ($tenantPnP.RestrictedAccessControlforSitesErrorHelpLink -ne $tenant.RestrictedAccessControlforSitesErrorHelpLink) { $parms["RestrictedAccessControlforSitesErrorHelpLink"] = $tenant.RestrictedAccessControlforSitesErrorHelpLink }
                if ($tenantPnP.Workflow2010Disabled -ne $tenant.Workflow2010Disabled) { $parms["Workflow2010Disabled"] = $tenant.Workflow2010Disabled }
                if ($tenantPnP.AllowSharingOutsideRestrictedAccessControlGroups -ne $tenant.AllowSharingOutsideRestrictedAccessControlGroups) { $parms["AllowSharingOutsideRestrictedAccessControlGroups"] = $tenant.AllowSharingOutsideRestrictedAccessControlGroups }
                if ($tenantPnP.HideSyncButtonOnDocLib -ne $tenant.HideSyncButtonOnDocLib) { $parms["HideSyncButtonOnDocLib"] = $tenant.HideSyncButtonOnDocLib }
                if ($tenantPnP.HideSyncButtonOnODB -ne $tenant.HideSyncButtonOnODB) { $parms["HideSyncButtonOnODB"] = $tenant.HideSyncButtonOnODB }
                #if ($tenantPnP.StreamLaunchConfig -ne $tenant.StreamLaunchConfig) { $parms["StreamLaunchConfig"] = $tenant.StreamLaunchConfig }
                if ($tenantPnP.EnableMediaReactions -ne $tenant.EnableMediaReactions) { $parms["EnableMediaReactions"] = $tenant.EnableMediaReactions }
                if ($tenantPnP.ContentSecurityPolicyEnforcement -ne $tenant.ContentSecurityPolicyEnforcement) { $parms["ContentSecurityPolicyEnforcement"] = $tenant.ContentSecurityPolicyEnforcement }
                if ($tenantPnP.DisableSpacesActivation -ne $tenant.DisableSpacesActivation) { $parms["DisableSpacesActivation"] = $tenant.DisableSpacesActivation }
                if ($tenantPnP.DisableSpacesActivation -ne $tenant.DisableSpacesActivation) { $parms["DisableSpacesActivation"] = $tenant.DisableSpacesActivation }
                Set-PnPTenant -Connection $conPnP -Force @parms
                $retries = -1
            } catch {
                Write-Warning "Error setting tenant properties, retrying... $($_.Exception.Message)"
                $tenantPnP = Get-PnPTenant -Connection $conPnP
                if ($retries -eq 0)
                {
                    throw
                }
                $retries--
            }
        } while ($retries -gt 0)

    }

    # Write-Host "Site scripts" -ForegroundColor $CommandInfo
    # $siteScripts = Get-PnPSiteScript -Connection $conPnP
    # foreach($siteScriptsAdminItem in $siteScriptsAdmin)
    # {
    #     $siteScript = $siteScripts | Where-Object {$_.Title -eq $siteScriptsAdminItem.Title}
    #     if (-Not $siteScript)
    #     {
    #         Write-Host "Creating Site Script: $($siteScriptsAdminItem.Title)"
    #         if ($DryRun -eq $false)
    #         {
    #             $newSiteScript = Add-PnPSiteScript -Title $siteScriptsAdminItem.Title -Description $siteScriptsAdminItem.Description -Content $siteScriptsAdminItem.Content -Connection $conPnP
    #         }
    #     }
    #     else
    #     {
    #         Write-Host "Site Script already exists: $($siteScriptsAdminItem.Title)"
    #         # Update Site Script if changed
    #         if ($siteScript.Description -ne $siteScriptsAdminItem.Description -or $siteScript.Content -ne $siteScriptsAdminItem.Content)
    #         {
    #             Write-Host "Updating Site Script: $($siteScriptsAdminItem.Title)"
    #             if ($DryRun -eq $false)
    #             {
    #                 Set-PnPSiteScript -Identity $siteScript.Id -Title $siteScriptsAdminItem.Title -Description $siteScriptsAdminItem.Description -Content $siteScriptsAdminItem.Content -Connection $conPnP
    #             }
    #         }
    #     }
    # }

    # Write-Host "Site designs" -ForegroundColor $CommandInfo
    # $siteDesigns = Get-PnPSiteDesign -Connection $conPnP
    # foreach($siteDesignsAdminItem in $siteDesignsAdmin)
    # {
    #     $siteDesign = $siteDesigns | Where-Object {$_.Title -eq $siteDesignsAdminItem.Title}
    #     if (-Not $siteDesign)
    #     {
    #         Write-Host "Creating Site Design: $($siteDesignsAdminItem.Title)"
    #         if ($DryRun -eq $false)
    #         {
    #             $newSiteDesign = Add-PnPSiteDesign -Title $siteDesignsAdminItem.Title -Description $siteDesignsAdminItem.Description -WebTemplate $siteDesignsAdminItem.WebTemplate -SiteScripts $siteDesignsAdminItem.SiteScriptIds -Connection $conPnP
    #         }
    #     }
    #     else
    #     {
    #         Write-Host "Site Design already exists: $($siteDesignsAdminItem.Title)"
    #         # Update Site Design if changed
    #         if ($siteDesign.Description -ne $siteDesignsAdminItem.Description -or $siteDesign.WebTemplate -ne $siteDesignsAdminItem.WebTemplate -or ($siteDesign.SiteScriptIds | Sort-Object) -ne ($siteDesignsAdminItem.SiteScriptIds | Sort-Object))
    #         {
    #             Write-Host "Updating Site Design: $($siteDesignsAdminItem.Title)"
    #             if ($DryRun -eq $false)
    #             {
    #                 Set-PnPSiteDesign -Identity $siteDesign.Id -Title $siteDesignsAdminItem.Title -Description $siteDesignsAdminItem.Description -WebTemplate $siteDesignsAdminItem.WebTemplate -SiteScripts $siteDesignsAdminItem.SiteScriptIds -Connection $conPnP
    #             }
    #         }
    #     }
    # }

    $conPnP = $null
}

$conPnPAdmin = $null

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDvZmBJN043PEjQ
# DW7QgD7nlZP8K5sg7q5UMOA5wlARzaCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
# th1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAwMDBaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# EylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj/SBerjgS
# i8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlMg7BKRFAE
# eIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRVX5YLEeWa
# tSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV0xHK5s2z
# BZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEzIHXMsdXt
# HQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMkoog28vmf
# vpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq7rfYrWGl
# r3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult5a/dm2tj
# IF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNutwFsDeCX
# pxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYyAjIwfLWT
# yCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofnGrhO7izB
# 36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJZ3Q
# /FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lWULvO
# ljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5ncm9v
# dHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJKwYBBAGg
# MgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3Jl
# cG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJyTm6t6E5
# iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbVYQLFY4/U
# ovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQtpFg6bBNJ
# +KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSXhndGKj0j
# fShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6bs+XYXvf
# cXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nOZNm9/Lws
# 80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOHX5OKSBoR
# HeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dqcYC/lt5y
# A9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0ixxnJpsoO
# qHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7qWPLd0jV
# +mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72f1LiSY25
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g604YfM/tV
# 5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD4ED6gVYD
# U/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S/gJXhZrh
# 0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp8nKmrVa4
# 6Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqtf2phU7+y
# R2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJQWTEE/bP
# 0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKXvYkPbEdx
# +QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4yMYgcMKb
# 9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmYF8T4xO2k
# 6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2mMIVpqWC
# Z1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7spNY6rQb
# 3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd2jANBgkq
# hkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy/fAHsVv1
# RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW2H3Bh6zN
# XULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0MP6pBPKO
# L6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/pFL9zlcc
# tWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcexU0bcV0hL
# Q4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf6AMOGaM5
# 6A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzECp9LnR+34
# c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9mUF5qE6Yw
# QqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+KuaJRsz+cn
# ZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/JlN6m6GM1j
# EhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutofdgNBzMUx
# ghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIE55pQRmxB7wcSR2
# mGK9si6uOPz88ih/2h8QDbYK5RudMA0GCSqGSIb3DQEBAQUABIICABomO6mAf/oV
# kEY5hNoydVBE4MQFSo98hoRz4YE7FcHPJqN3LLe+eTznhb/jTJ12dyXDUiecjWOR
# /w89Xx5Jv4H9zaO4qehgRYmWZ9L0Th5YLbPzkCmlONov0aUhZ3zcdr74szJPjzqv
# /TPWAI+Eo5GpQzz+emyRyz7jztiAAjYFjT+FDl02/dRswViKyEBghRcf97o5hFkp
# ruImGeMmiyMvDjwSCtUexFZQDC3Xk4/ot+TTBsAk5XNUJ9u+x6sQjueZm/aPO9ZT
# 27wAE0dkyauXC2bs8wTr4XBrxUsuQeolyeZHhNS+BVP5vUq1LMnmV7YAK1ZGEb/6
# d882n5iqcx3rulRvahAiB9+nUle9vOL9W8nQ4/2mVnkYH9qWleC/2I327OYh8Oko
# 4EQZmsykAZ9XGrdEzCCt4Mfo7sSJepv78QDWJMtjNIWYkf2dm9kKB0Z/kuKbsCUx
# AvaAJ1XAg3sC+pf5I+OuexdjUTJwJKOkMYuoVC0UbwVL0qQXJHJI7BA8JzI7MMGa
# v4DBJDq+GSbJ2w5faGG/21c9+KrOFijikSLUJJXre+uSvbhw+ra4lm01kKTpPRNs
# hXz87wlk9CkjqEda9rfESuPgWhIwdVuVT1SyPacQDs/R7La5SFWbvolP8QPno4Fg
# Wvl2FHPAy2W8pbbFnqvwP8lLXv8gRlyEoYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCB59r2ld4FsWgIva8ygonCkdtRnqcPr7/jI8oE/5QFycAIUcs4FXNbIKOkU
# kIE4A/9M07VS7sEYDzIwMjYwMjA2MTIxNzU1WjADAgEBoFikVjBUMQswCQYDVQQG
# EwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFs
# c2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMCAQICEAEA
# CyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5WhcNMzQx
# MjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBu
# di1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2
# MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4PuCF6+aq
# Cj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb5gk0Xydy
# 3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJScRV1W6/6e
# fi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy5RJY+o1N
# WhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY0Lie04Du
# KbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2ZwbI6yiFH
# aS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYhKUlrMH9+
# 2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5sWtX1qvCz
# k6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGoMIIBpDAO
# BgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYE
# FIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQCMEEGCSsG
# AQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNv
# bS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5
# BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2Fj
# YXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24u
# Y29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn
# 48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xv
# YmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG9w0BAQwF
# AAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26IFq7fQMI
# rN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76TkvL+v2f4mH
# olGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftPttS+G/Mh
# NUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIlS3Ki74CU
# 15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt8DT4RQj9
# LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5lgJkgXEc
# 1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD9hQchjiG
# kyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71yzGKWnbA
# WQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGLZtJFJzGJ
# D7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVAGXCqHsh6
# 2QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZMIIEQaAD
# AgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0ds
# b2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYD
# VQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAwMDAwMFow
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOvdYNfqUdS
# x2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt0ShKwSy7
# uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrE
# iPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64
# VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16ZevRVqku
# vftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv
# +GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm19m1W/ood
# CT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIGbxsY1Tbq
# ZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMDAd6ZJflx
# bumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/MiyTdtk8EWf
# usE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9GbCX6oxQ
# kW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGGMBIGA1Ud
# EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDDvWWWMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAu
# BggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYWaxlASSUI
# HuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCyz+zCVmUd
# vX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W
# 8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWz
# Alcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59eodaZzul9
# S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8oMWsr1EG
# 8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1If5iEO0d
# MPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDU
# Y6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+
# PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+
# gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIIDa6ADAgEC
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
# AtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJYIZIAWUD
# BAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0
# MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcNAQkEMSIE
# IHHJ/LGuowqnqwdRagtkEBsZGO2PscPJqIYqiSvguVFKMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAgAvCQAzHbwv2
# 2n2CdzxGh6UZODOOFpgsvQyEatZUJ916vMEOCKgnPaM7lKxbCYfXHnZmqDzr7AkA
# hI5GcEKUuREmyjH4vPWGBGgL/sNKusqm4OVmqNKFnQREG4fIe2SMvyAnwkUbPSq5
# fSQfefJ3stnQc8O6Qz8eJ99VBOOF0Y5ZULhlGkH6sXh4UaO3qKER2f61blZ+diJp
# +xfSH+LnhGJ4LaA8oXs2zSuPOGwqUx6UZdzMF+3ddYLlQ6XOffmDY3hTl6R3EjFs
# ds9BREmxR8OPJMTySUmA0MiR5l35YCQNuJocV6lwmjrJZ68WBaw4W/umowg5KDDb
# QroUSpOGc0stHH0QGG94mPK/6AZcqFQXo5QfRU/2r+lzSkqLUsE4wDjCjdnAsE/b
# uUI2zDsYwhEoA9YJ9fvah3BLfg4yT9V95cL0ieqCBwtsQ6Tt+frentL2/y+CAhde
# ekktllj4bZe2Y6jsWgc2xyLqIQfAkICBzKDjGGXKXfXYOYw5qPzR
# SIG # End signature block
