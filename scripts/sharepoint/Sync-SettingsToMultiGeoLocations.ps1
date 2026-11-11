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
    06.02.2026 Konrad Brunner       Added powershell documentation
    05.08.2026 Konrad Brunner       Added new parameters for OneDrive and Core sharing link expiration settings

    This script is used to sync settings to all Multi-Geo locations. It requires following previous scripts to be run:
    - Configure-ServiceApplication
    - Install-ServiceApplicationCertificate

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

# Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transcript
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
            #Added 05.08.2026
            if ($tenantPnP.MinCompatibilityLevel -ne $tenant.MinCompatibilityLevel) { $parms["MinCompatibilityLevel"] = $tenant.MinCompatibilityLevel }
            if ($tenantPnP.MaxCompatibilityLevel -ne $tenant.MaxCompatibilityLevel) { $parms["MaxCompatibilityLevel"] = $tenant.MaxCompatibilityLevel }
            if ($tenantPnP.ShowEveryoneClaim -ne $tenant.ShowEveryoneClaim) { $parms["ShowEveryoneClaim"] = $tenant.ShowEveryoneClaim }
            if ($tenantPnP.UserVoiceForFeedbackEnabled -ne $tenant.UserVoiceForFeedbackEnabled) { $parms["UserVoiceForFeedbackEnabled"] = $tenant.UserVoiceForFeedbackEnabled }
            if ($tenantPnP.OneDriveOrganizationSharingLinkMaxExpirationInDays -ne $tenant.OneDriveOrganizationSharingLinkMaxExpirationInDays) { $parms["OneDriveOrganizationSharingLinkMaxExpirationInDays"] = $tenant.OneDriveOrganizationSharingLinkMaxExpirationInDays }
            if ($tenantPnP.OneDriveOrganizationSharingLinkRecommendedExpirationInDays -ne $tenant.OneDriveOrganizationSharingLinkRecommendedExpirationInDays) { $parms["OneDriveOrganizationSharingLinkRecommendedExpirationInDays"] = $tenant.OneDriveOrganizationSharingLinkRecommendedExpirationInDays }
            if ($tenantPnP.CoreOrganizationSharingLinkMaxExpirationInDays -ne $tenant.CoreOrganizationSharingLinkMaxExpirationInDays) { $parms["CoreOrganizationSharingLinkMaxExpirationInDays"] = $tenant.CoreOrganizationSharingLinkMaxExpirationInDays }
            if ($tenantPnP.CoreOrganizationSharingLinkRecommendedExpirationInDays -ne $tenant.CoreOrganizationSharingLinkRecommendedExpirationInDays) { $parms["CoreOrganizationSharingLinkRecommendedExpirationInDays"] = $tenant.CoreOrganizationSharingLinkRecommendedExpirationInDays }
            if ($tenantPnP.AllowAppsBypassOfUnmanagedDevicePolicy -ne $tenant.AllowAppsBypassOfUnmanagedDevicePolicy) { $parms["AllowAppsBypassOfUnmanagedDevicePolicy"] = $tenant.AllowAppsBypassOfUnmanagedDevicePolicy }
            if ($tenantPnP.DisabledAdaptiveCardExtensionIds -ne $tenant.DisabledAdaptiveCardExtensionIds) { $parms["DisabledAdaptiveCardExtensionIds"] = $tenant.DisabledAdaptiveCardExtensionIds }
            if ($tenantPnP.EnableAutoNewsDigest -ne $tenant.EnableAutoNewsDigest) { $parms["EnableAutoNewsDigest"] = $tenant.EnableAutoNewsDigest }
            if ($tenantPnP.CommentsOnListItemsDisabled -ne $tenant.CommentsOnListItemsDisabled) { $parms["CommentsOnListItemsDisabled"] = $tenant.CommentsOnListItemsDisabled }
            if ($tenantPnP.CommentsOnFilesDisabled -ne $tenant.CommentsOnFilesDisabled) { $parms["CommentsOnFilesDisabled"] = $tenant.CommentsOnFilesDisabled }
            if ($tenantPnP.AllowCommentsTextOnEmailEnabled -ne $tenant.AllowCommentsTextOnEmailEnabled) { $parms["AllowCommentsTextOnEmailEnabled"] = $tenant.AllowCommentsTextOnEmailEnabled }
            if ($tenantPnP.DisableBackToClassic -ne $tenant.DisableBackToClassic) { $parms["DisableBackToClassic"] = $tenant.DisableBackToClassic }
            if ($tenantPnP.LabelMismatchEmailHelpLink -ne $tenant.LabelMismatchEmailHelpLink) { $parms["LabelMismatchEmailHelpLink"] = $tenant.LabelMismatchEmailHelpLink }
            if ($tenantPnP.FileTypesForVersionExpiration -ne $tenant.FileTypesForVersionExpiration) { $parms["FileTypesForVersionExpiration"] = $tenant.FileTypesForVersionExpiration }
            if ($tenantPnP.CoreDefaultLinkToExistingAccess -ne $tenant.CoreDefaultLinkToExistingAccess) { $parms["CoreDefaultLinkToExistingAccess"] = $tenant.CoreDefaultLinkToExistingAccess }
            if ($tenantPnP.HideSyncButtonOnTeamSite -ne $tenant.HideSyncButtonOnTeamSite) { $parms["HideSyncButtonOnTeamSite"] = $tenant.HideSyncButtonOnTeamSite }
            if ($tenantPnP.CoreBlockGuestsAsSiteAdmin -ne $tenant.CoreBlockGuestsAsSiteAdmin) { $parms["CoreBlockGuestsAsSiteAdmin"] = $tenant.CoreBlockGuestsAsSiteAdmin }
            if ($tenantPnP.IsWBFluidEnabled -ne $tenant.IsWBFluidEnabled) { $parms["IsWBFluidEnabled"] = $tenant.IsWBFluidEnabled }
            if ($tenantPnP.ShowOpenInDesktopOptionForSyncedFiles -ne $tenant.ShowOpenInDesktopOptionForSyncedFiles) { $parms["ShowOpenInDesktopOptionForSyncedFiles"] = $tenant.ShowOpenInDesktopOptionForSyncedFiles }
            if ($tenantPnP.AuthContextResilienceMode -ne $tenant.AuthContextResilienceMode) { $parms["AuthContextResilienceMode"] = $tenant.AuthContextResilienceMode }
            if ($tenantPnP.BlockDownloadFileTypePolicy -ne $tenant.BlockDownloadFileTypePolicy) { $parms["BlockDownloadFileTypePolicy"] = $tenant.BlockDownloadFileTypePolicy }
            if ($tenantPnP.TlsTokenBindingPolicyValue -ne $tenant.TlsTokenBindingPolicyValue) { $parms["TlsTokenBindingPolicyValue"] = $tenant.TlsTokenBindingPolicyValue }
            if ($tenantPnP.ArchiveRedirectUrl -ne $tenant.ArchiveRedirectUrl) { $parms["ArchiveRedirectUrl"] = $tenant.ArchiveRedirectUrl }
            if ($tenantPnP.MediaTranscription -ne $tenant.MediaTranscription) { $parms["MediaTranscription"] = $tenant.MediaTranscription }
            if ($tenantPnP.MediaTranscriptionAutomaticFeatures -ne $tenant.MediaTranscriptionAutomaticFeatures) { $parms["MediaTranscriptionAutomaticFeatures"] = $tenant.MediaTranscriptionAutomaticFeatures }
            if ($tenantPnP.ReduceTempTokenLifetimeEnabled -ne $tenant.ReduceTempTokenLifetimeEnabled) { $parms["ReduceTempTokenLifetimeEnabled"] = $tenant.ReduceTempTokenLifetimeEnabled }
            if ($tenantPnP.ReduceTempTokenLifetimeValue -ne $tenant.ReduceTempTokenLifetimeValue) { $parms["ReduceTempTokenLifetimeValue"] = $tenant.ReduceTempTokenLifetimeValue }
            if ($tenantPnP.ViewersCanCommentOnMediaDisabled -ne $tenant.ViewersCanCommentOnMediaDisabled) { $parms["ViewersCanCommentOnMediaDisabled"] = $tenant.ViewersCanCommentOnMediaDisabled }
            if ($tenantPnP.AllOrganizationSecurityGroupId -ne $tenant.AllOrganizationSecurityGroupId) { $parms["AllOrganizationSecurityGroupId"] = $tenant.AllOrganizationSecurityGroupId }
            if ($tenantPnP.AllowGuestUserShareToUsersNotInSiteCollection -ne $tenant.AllowGuestUserShareToUsersNotInSiteCollection) { $parms["AllowGuestUserShareToUsersNotInSiteCollection"] = $tenant.AllowGuestUserShareToUsersNotInSiteCollection }
            if ($tenantPnP.ContentTypeSyncSiteTemplatesList -ne $tenant.ContentTypeSyncSiteTemplatesList) { $parms["ContentTypeSyncSiteTemplatesList"] = $tenant.ContentTypeSyncSiteTemplatesList }
            if ($tenantPnP.ConditionalAccessPolicyErrorHelpLink -ne $tenant.ConditionalAccessPolicyErrorHelpLink) { $parms["ConditionalAccessPolicyErrorHelpLink"] = $tenant.ConditionalAccessPolicyErrorHelpLink }
            if ($tenantPnP.CustomizedExternalSharingServiceUrl -ne $tenant.CustomizedExternalSharingServiceUrl) { $parms["CustomizedExternalSharingServiceUrl"] = $tenant.CustomizedExternalSharingServiceUrl }
            if ($tenantPnP.IncludeAtAGlanceInShareEmails -ne $tenant.IncludeAtAGlanceInShareEmails) { $parms["IncludeAtAGlanceInShareEmails"] = $tenant.IncludeAtAGlanceInShareEmails }
            if ($tenantPnP.MassDeleteNotificationDisabled -ne $tenant.MassDeleteNotificationDisabled) { $parms["MassDeleteNotificationDisabled"] = $tenant.MassDeleteNotificationDisabled }
            if ($tenantPnP.RestrictExternalSharing -ne $tenant.RestrictExternalSharing) { $parms["RestrictExternalSharing"] = $tenant.RestrictExternalSharing }
            if ($tenantPnP.AllowFileArchive -ne $tenant.AllowFileArchive) { $parms["AllowFileArchive"] = $tenant.AllowFileArchive }
            if ($tenantPnP.AllowFileArchiveOnNewSitesByDefault -ne $tenant.AllowFileArchiveOnNewSitesByDefault) { $parms["AllowFileArchiveOnNewSitesByDefault"] = $tenant.AllowFileArchiveOnNewSitesByDefault }
            if ($tenantPnP.IsSharePointAddInsDisabled -ne $tenant.IsSharePointAddInsDisabled) { $parms["IsSharePointAddInsDisabled"] = $tenant.IsSharePointAddInsDisabled }
            if ($tenantPnP.SyncAadB2BManagementPolicy -ne $tenant.SyncAadB2BManagementPolicy) { $parms["SyncAadB2BManagementPolicy"] = $tenant.SyncAadB2BManagementPolicy }
            if ($tenantPnP.ResyncContentSecurityPolicyConfigurationEntries -ne $tenant.ResyncContentSecurityPolicyConfigurationEntries) { $parms["ResyncContentSecurityPolicyConfigurationEntries"] = $tenant.ResyncContentSecurityPolicyConfigurationEntries }
            if ($tenantPnP.DelayContentSecurityPolicyEnforcement -ne $tenant.DelayContentSecurityPolicyEnforcement) { $parms["DelayContentSecurityPolicyEnforcement"] = $tenant.DelayContentSecurityPolicyEnforcement }
            if ($tenantPnP.RestrictResourceAccountAccess -ne $tenant.RestrictResourceAccountAccess) { $parms["RestrictResourceAccountAccess"] = $tenant.RestrictResourceAccountAccess }
            if ($tenantPnP.EnforceRequestDigest -ne $tenant.EnforceRequestDigest) { $parms["EnforceRequestDigest"] = $tenant.EnforceRequestDigest }
            if ($tenantPnP.RestrictExternalSharingForAgents -ne $tenant.RestrictExternalSharingForAgents) { $parms["RestrictExternalSharingForAgents"] = $tenant.RestrictExternalSharingForAgents }
            if ($tenantPnP.EnableNotificationsSubscriptions -ne $tenant.EnableNotificationsSubscriptions) { $parms["EnableNotificationsSubscriptions"] = $tenant.EnableNotificationsSubscriptions }
            if ($parms.Count -gt 0) {
                Write-Host "Syncing tenant properties: $($parms.Keys -join ', ')"
                if ($DryRun -eq $false) {
                    Set-PnPTenant -Connection $conPnP -Force @parms
                }
            }
            break
        } catch {
            Write-Warning "Error syncing tenant properties, retrying... $($_.Exception.Message)"
            $tenantPnP = Get-PnPTenant -Connection $conPnP
            if ($retries -eq 0)
            {
                throw
            }
            $retries--
        }
    } while ($retries -gt 0)

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

# Stopping Transcript
Stop-Transcript

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD3XU2yx0G7Vpcx
# rr/828GqCqg6/lvDgkjjnQFFgiayrqCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIF6PGPd8
# Nk7hHomtIhgorUcJe/C4qDWlAkT216S+LoosMA0GCSqGSIb3DQEBAQUABIICAG3n
# gpDAI3yG/M4SVhYHvm3WsE16QXTGz20pNXMAzPJYt1goW4gcG11BQE4UaV67osjx
# mRUxm/pf+OLiXu9tQtdgPjTKRc80ro6Tb3byvk5g1ZV81UsDYeZ64Ab73hnBvduQ
# sN9ewZC88p+qd34xkiGsNuhsupMSe+58ZKFmspALMWk5/fe2KNIROsJY14zwj39Y
# I5IpOvw5jLMoWv0xskep0sWLxgI7S5llJqR0fDpv08nhjdS29TubLmubYVF5CBz4
# mCLdFhQ41ZDGch04nXykcOnvqZeFmS6Rk1JEOG4vKi350YwhQIeBS/yTJ+YSFA4E
# sxAcHnNYZWCH3OhtoVqWtdjQpo5E+tLf+/87TCUxAv8ZN3DTg1++sNlEDcIPU1Y7
# jWPry0WPdsa2F5JqWGhiRU61TUXDMprYurRZoOD0TT24Ig+VYt5qHtWCKJPFkity
# 5bKRBvcoH4yEO+oH2/5i3dAS+EF26g/2JNc9sKtEcBK/M2GLgZ6xrSMIMUECLrmh
# GQC/AHczu1Cw4YsfJi66FPmKrIZwA7rP8SfIv2PT8db6qg02zk+/eugQrGWgFx0y
# kz6SbaHdpe9RMcacZ3+NbNebzIaxsl4XcgJ0ev1Bj/y+HH4//JUgzvGfzKzesG63
# /uBeVQrU/UarRDQicksF4sPCAJa0pCi5SPmEk7MsoYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCBgzepBlWL8TW3aA/uaQmfJZzFnSY1f1Ekf62UicRZu+gIUS5jB
# hvy9VodVjqd3RHEV28BRP88YDzIwMjYwODA2MDYzNzM1WjADAgEBoF2kWzBZMQsw
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
# BDEyBDDTk8ecahdbQPU/392pWRifDhw4S7hg9mLazyFfp48p3j4ZLlc4ZaUeo3CE
# cTBXmhEwgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGADHhbNE5GiCLlF7xiHOUPMQGcLtUSK57hMwhnzEeY1/rS
# 6cBiQCf1qZ5LAoDLhfwBzjOZvdXNQB4LZlvrj/K0Rf+gza4XBCajhlowfenmug/k
# YnRWQbQ8F+eU/f+fWGyBpYh5nwtTHJ1kWLSupMcNVVAvRPpVQMlw1zdNdMiZrisI
# 0d8NHA0DqAi+s7u7gkC1Ix1xvvClFERLwZxYMB/9SM2be30DtwUps2EOonwSM8pP
# vVOEb4orSYltMuIC8D5TD2gTJhqiLFbM2m4s9gDg2P5wda3bNMYRCNN8vVKjYCyQ
# wqRxEI6+ZqY4T6FVbcyArDltHCe4I5kzNTNWh+AFoTsi+ELY2OlyshqB1dqSn51+
# r/ptvO0KCJKa7is99sdMmH7AlbBJqUD7i+D1L9zvDI7vnPjbo9WykLJten5od7tL
# lFAnzPvLgnlpLkCqr+NjmKkN+rzptr0Arh08zaGFvNEimh9gdAsxpdXNRcXY9Uz/
# y5Oi4GaKFf4PQew1AtMM
# SIG # End signature block
