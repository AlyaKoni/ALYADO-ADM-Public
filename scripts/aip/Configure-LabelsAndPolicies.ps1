#Requires -Version 5.0

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
    24.09.2020 Konrad Brunner       Initial Version
    16.11.2022 Konrad Brunner       Added site and group definitions
    06.02.2026 Konrad Brunner       Added powershell documentation

#>

<#
.SYNOPSIS
Configures Microsoft Information Protection labels and label policies in Exchange Online based on provided Excel configuration files.

.DESCRIPTION
The Configure-LabelsAndPolicies.ps1 script automates the setup and management of sensitivity labels and publishing policies in Exchange Online. It reads label definitions and publishing configurations from provided Excel files, creates or updates corresponding labels and label policies, and adjusts encryption, site and group protection, and advanced policy settings accordingly. Optionally, it can disable unused labels. The script requires modules such as ExchangeOnlineManagement, AIPService, and ImportExcel, and maintains an execution transcript in the Alya logging directory.

.PARAMETER inputLabelFile
Specifies the path to the Excel file containing the label definitions. Defaults to "$AlyaData\aip\Labels.xlsx" if not provided.

.PARAMETER inputPublishFile
Specifies the path to the Excel file containing publishing profile definitions. Defaults to "$AlyaData\aip\PublishProfiles.xlsx" if not provided.

.PARAMETER DisablingUnusedLabels
If specified, disables any existing labels that are not defined in the input Excel file.

.INPUTS
None. The script does not accept piped input.

.OUTPUTS
Outputs log information about the configuration process. Creates or updates labels and label policies within Exchange Online.

.EXAMPLE
PS> .\Configure-LabelsAndPolicies.ps1 -inputLabelFile "C:\Data\AIP\Labels.xlsx" -inputPublishFile "C:\Data\AIP\PublishProfiles.xlsx" -DisablingUnusedLabels

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [string]$inputLabelFile = $null, #Defaults to "$AlyaData\aip\Labels.xlsx"
    [string]$inputPublishFile = $null, #Defaults to "$AlyaData\aip\PublishProfiles.xlsx"
    [switch]$DisablingUnusedLabels = $false
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\onprem\Configure-LabelsAndPolicies-$($AlyaTimeString).log" | Out-Null

#Members
if (-Not $inputLabelFile)
{
    $inputLabelFile = "$AlyaData\aip\Labels.xlsx"
}
if (-Not $inputPublishFile)
{
    $inputPublishFile = "$AlyaData\aip\PublishProfiles.xlsx"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"
Install-ModuleIfNotInstalled "AIPService"
Install-ModuleIfNotInstalled "ImportExcel"

# Reading inputLabelFile file
Write-Host "Reading label file from '$inputLabelFile'" -ForegroundColor $CommandInfo
if (-Not (Test-Path $inputLabelFile))
{
    throw "'$inputLabelFile' not found!"
}
$labelDefs = Import-Excel $inputLabelFile -ErrorAction Stop

# Reading inputPublishFile file
Write-Host "Reading publish file from '$inputPublishFile'" -ForegroundColor $CommandInfo
if (-Not (Test-Path $inputPublishFile))
{
    throw "'$inputPublishFile' not found!"
}
$publishDefs = Import-Excel $inputPublishFile

# Logins
LoginTo-IPPS

# =============================================================
# Exchange stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "UnifiedLabels | Configure-LabelsAndPolicies | EXCHANGE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Configuring labels
try
{
    #https://docs.microsoft.com/en-us/azure/information-protection/rms-client/clientv2-admin-guide-customizations
    #https://docs.microsoft.com/en-us/microsoft-365/compliance/create-sensitivity-labels?view=o365-worldwide#example-configuration-to-configure-a-sensitivity-label-for-different-languages

    Write-Warning "TODO Naming conflict with MS label public"
    Write-Warning "TODO Delete existing MS Policies"
    Write-Warning "TODO Delete existing MS Labels"
    pause

    Write-Host "Configuring labels in exchange" -ForegroundColor $CommandInfo
    $labelName = $null
    $priority = -1
    foreach($labelDef in $labelDefs)
    {
        #$labelDef = $labelDefs[0]
        $labelName = $labelDef.NameEN
        if (-Not [string]::IsNullOrEmpty($labelDef.Name)) { $labelName = $labelDef.Name }
        if (-Not [string]::IsNullOrEmpty($labelName))
        {
            Write-Host "  Label: $($labelName)" -ForegroundColor $CommandInfo
            $lastLabelName = $labelName
            $encryptionRightsDefinitions = $null
            $label = $null
            $priority += 1
            $contentType = @("File", "Email", "Site", "UnifiedGroup")
            $DisplayNameLocaleSettings = [PSCustomObject]@{LocaleKey='DisplayName';
                Settings=@(
                @{key="en-en";Value=$labelDef.NameEN;}
                @{key="it-it";Value=$labelDef.NameEN;}
                @{key="it-ch";Value=$labelDef.NameEN;}
                @{key="fr-fr";Value=$labelDef.NameEN;}
                @{key="fr-ch";Value=$labelDef.NameEN;}
                @{key="de-de";Value=$labelDef.NameDE;}
                @{key="de-ch";Value=$labelDef.NameDE;})}
            $TooltipLocaleSettings = [PSCustomObject]@{LocaleKey='Tooltip';
                Settings=@(
                @{key="en-en";Value=$labelDef.CommentEN;}
                @{key="it-it";Value=$labelDef.CommentEN;}
                @{key="it-ch";Value=$labelDef.CommentEN;}
                @{key="fr-fr";Value=$labelDef.CommentEN;}
                @{key="fr-ch";Value=$labelDef.CommentEN;}
                @{key="de-de";Value=$labelDef.CommentDE;}
                @{key="de-ch";Value=$labelDef.CommentDE;})}

            $label = Get-Label -Identity $labelName -ErrorAction SilentlyContinue
            if (-Not $label)
            {
                Write-Host "    - does not exist, creating"
                $label = New-Label -Name $labelName -DisplayName $labelDef.NameEN -Tooltip $labelDef.CommentEN -LocaleSettings (ConvertTo-Json $DisplayNameLocaleSettings -Depth 3 -Compress),(ConvertTo-Json $TooltipLocaleSettings -Depth 3 -Compress) -ContentType $contentType
            }
            else
            {
                Write-Host "    - exists, updating"
                Set-Label -Identity $labelName -LocaleSettings (ConvertTo-Json $DisplayNameLocaleSettings -Depth 3 -Compress),(ConvertTo-Json $TooltipLocaleSettings -Depth 3 -Compress) -ContentType $contentType
            }

            $AllowGuests = $labelDef.AllowGuests -eq "On"
            $Privacy = "Private"
            if ($labelName.Contains("Pub"))
            {
                $Privacy = "Public"
            }
            $SharingOption = "ExternalUserAndGuestSharing"
            if ($AlyaSharingPolicy -eq "KnownAccountsOnly")
            {
                $SharingOption = "ExternalUserSharingOnly"
            }
            if ($AlyaSharingPolicy -eq "AdminOnly")
            {
                $SharingOption = "ExistingExternalUserSharingOnly"
            }
            if ($AlyaSharingPolicy -eq "None")
            {
                $SharingOption = "Disabled"
            }

            if ($labelDef.Encryption -eq "On")
            {
                $encryptionProtectionType = "Template"
                $encryptionPromptUser = $false
                $encryptionContentExpiredOnDateInDaysOrNever = "Never"
                [int]$encryptionOfflineAccessDays = 14
                if ($labelDef.EncryptionTarget -eq "User defined")
                {
                    Write-Host "    - setting user defined encryption"
                    $encryptionProtectionType = "UserDefined"
                    $encryptionPromptUser = $true
                }
                else
                {
                    Write-Host "    - setting encryption"
                    if ([string]::IsNullOrEmpty($labelDef.EncryptionPermissionEmail))
                    {
                        throw "Label '$($labelName)' does not have 'EncryptionPermissionEmail' specified"
                    }
                    Write-Host "        for $($labelDef.EncryptionPermissionEmail)"
                    $encryptionRightsDefinitions = $labelDef.EncryptionPermissionEmail
                    switch ($labelDef.EncryptionPermission)
                    {
                        "Co-Owner" {
                            $encryptionRightsDefinitions += ":VIEW,VIEWRIGHTSDATA,DOCEDIT,EDIT,PRINT,EXTRACT,REPLY,REPLYALL,FORWARD,EXPORT,EDITRIGHTSDATA,OBJMODEL,OWNER"
                        }
                        "Co-Author" {
                            $encryptionRightsDefinitions += ":VIEW,VIEWRIGHTSDATA,DOCEDIT,EDIT,PRINT,EXTRACT,REPLY,REPLYALL,FORWARD,OBJMODEL"
                        }
                        "Reviewer" {
                            $encryptionRightsDefinitions += ":VIEW,VIEWRIGHTSDATA,DOCEDIT,EDIT,REPLY,REPLYALL,FORWARD,OBJMODEL"
                        }
                        "Viewer" {
                            $encryptionRightsDefinitions += ":VIEW,VIEWRIGHTSDATA,OBJMODEL"
                        }
                        default {
                            $encryptionRightsDefinitions += $labelDef.EncryptionPermission
                        }
                    }
                }
                if ($labelDef.EncryptionOfflineAccessType -eq "Only for a number of days")
                {
                    $encryptionOfflineAccessDays = [int]$labelDef.EncryptionOfflineAccessDays
                }
                if (-Not [string]::IsNullOrEmpty($labelDef.EncryptionContentExpiration) -and $labelDef.EncryptionContentExpiration -ne "Never")
                {
                    throw "TODO" #TODO
                }
                Write-Host "    - setting site and group protection"
                if (-Not $labelDef.SiteAndGroupProtection -or $labelDef.SiteAndGroupProtection -eq "Off")
                {
                    if ($encryptionProtectionType -eq "UserDefined")
                    {
                        Set-Label -Identity $labelName -EncryptionEnabled $true -EncryptionProtectionType $encryptionProtectionType `
                        -EncryptionPromptUser $encryptionPromptUser -EncryptionEncryptOnly $false -EncryptionDoNotForward $true `
                        -EncryptionContentExpiredOnDateInDaysOrNever $encryptionContentExpiredOnDateInDaysOrNever `
                        -EncryptionOfflineAccessDays $encryptionOfflineAccessDays -EncryptionRightsDefinitions $encryptionRightsDefinitions `
                        -SiteAndGroupProtectionEnabled $false -TeamsChannelProtectionEnabled $false
                    }
                    else
                    {
                        Set-Label -Identity $labelName -EncryptionEnabled $true -EncryptionProtectionType $encryptionProtectionType `
                        -EncryptionPromptUser $encryptionPromptUser -EncryptionDoNotForward $false `
                        -EncryptionContentExpiredOnDateInDaysOrNever $encryptionContentExpiredOnDateInDaysOrNever `
                        -EncryptionOfflineAccessDays $encryptionOfflineAccessDays -EncryptionRightsDefinitions $encryptionRightsDefinitions `
                        -SiteAndGroupProtectionEnabled $false -TeamsChannelProtectionEnabled $false
                    }
                }
                else
                {
                    if ($encryptionProtectionType -eq "UserDefined")
                    {
                        Set-Label -Identity $labelName -EncryptionEnabled $true -EncryptionProtectionType $encryptionProtectionType `
                        -EncryptionPromptUser $encryptionPromptUser -EncryptionEncryptOnly $false -EncryptionDoNotForward $true `
                        -EncryptionContentExpiredOnDateInDaysOrNever $encryptionContentExpiredOnDateInDaysOrNever `
                        -EncryptionOfflineAccessDays $encryptionOfflineAccessDays -EncryptionRightsDefinitions $encryptionRightsDefinitions `
                        -SiteAndGroupProtectionEnabled $true -SiteAndGroupProtectionAllowAccessToGuestUsers $AllowGuests `
                        -SiteAndGroupProtectionAllowEmailFromGuestUsers $AllowGuests -SiteAndGroupProtectionAllowFullAccess $AllowGuests `
                        -SiteAndGroupProtectionAllowLimitedAccess $AllowGuests -SiteAndGroupProtectionBlockAccess $false `
                        -SiteAndGroupProtectionPrivacy $Privacy -SiteExternalSharingControlType $SharingOption -TeamsChannelProtectionEnabled $true
                    }
                    else
                    {
                        Set-Label -Identity $labelName -EncryptionEnabled $true -EncryptionProtectionType $encryptionProtectionType `
                        -EncryptionPromptUser $encryptionPromptUser -EncryptionDoNotForward $false `
                        -EncryptionContentExpiredOnDateInDaysOrNever $encryptionContentExpiredOnDateInDaysOrNever `
                        -EncryptionOfflineAccessDays $encryptionOfflineAccessDays -EncryptionRightsDefinitions $encryptionRightsDefinitions `
                        -SiteAndGroupProtectionEnabled $true -SiteAndGroupProtectionAllowAccessToGuestUsers $AllowGuests `
                        -SiteAndGroupProtectionAllowEmailFromGuestUsers $AllowGuests -SiteAndGroupProtectionAllowFullAccess $AllowGuests `
                        -SiteAndGroupProtectionAllowLimitedAccess $AllowGuests -SiteAndGroupProtectionBlockAccess $false `
                        -SiteAndGroupProtectionPrivacy $Privacy -SiteExternalSharingControlType $SharingOption -TeamsChannelProtectionEnabled $true
                    }
                }
            }
            else
            {
                Write-Host "    - setting site and group protection"
                if (-Not $labelDef.SiteAndGroupProtection -or $labelDef.SiteAndGroupProtection -eq "Off")
                {
                    Set-Label -Identity $labelName -EncryptionEnabled $false -SiteAndGroupProtectionEnabled $false -TeamsChannelProtectionEnabled $false
                }
                else
                {
                    Set-Label -Identity $labelName -EncryptionEnabled $false `
                        -SiteAndGroupProtectionEnabled $true -TeamsChannelProtectionEnabled $true -SiteAndGroupProtectionAllowAccessToGuestUsers $AllowGuests `
                        -SiteAndGroupProtectionAllowEmailFromGuestUsers $AllowGuests -SiteAndGroupProtectionAllowFullAccess $AllowGuests `
                        -SiteAndGroupProtectionAllowLimitedAccess $AllowGuests -SiteAndGroupProtectionBlockAccess $false `
                        -SiteAndGroupProtectionPrivacy $Privacy -SiteExternalSharingControlType $SharingOption
                }
            }

            #TODO advanced settings
            #Set-Label -Identity Confidential -AdvancedSettings @{labelByCustomProperties="Secure Islands label is Confidential,Classification,Confidential"}
            #Set-Label -Identity Confidential -AdvancedSettings @{customPropertiesByLabel="Classification,Confidential"}

            #Set-Label -Identity "Recipients Only" -AdvancedSettings @{SMimeSign=$false}
            #Set-Label -Identity "Recipients Only" -AdvancedSettings @{SMimeEncrypt=$false}

            #Set-Label -Identity Public -AdvancedSettings @{color="#40e0d0"}
        }
        else
        {
            Write-Host "    - setting encryption"
            if ($label -and -not [string]::IsNullOrEmpty($labelDef.EncryptionPermissionEmail))
            {
                Write-Host "        for $($labelDef.EncryptionPermissionEmail)"
                $encryptionRightsDefinitions += ";"+$labelDef.EncryptionPermissionEmail
                switch ($labelDef.EncryptionPermission)
                {
                    "Co-Owner" {
                        $encryptionRightsDefinitions += ":VIEW,VIEWRIGHTSDATA,DOCEDIT,EDIT,PRINT,EXTRACT,REPLY,REPLYALL,FORWARD,EXPORT,EDITRIGHTSDATA,OBJMODEL,OWNER"
                    }
                    "Co-Author" {
                        $encryptionRightsDefinitions += ":VIEW,VIEWRIGHTSDATA,DOCEDIT,EDIT,PRINT,EXTRACT,REPLY,REPLYALL,FORWARD,OBJMODEL"
                    }
                    "Reviewer" {
                        $encryptionRightsDefinitions += ":VIEW,VIEWRIGHTSDATA,DOCEDIT,EDIT,REPLY,REPLYALL,FORWARD,OBJMODEL"
                    }
                    "Viewer" {
                        $encryptionRightsDefinitions += ":VIEW,VIEWRIGHTSDATA,OBJMODEL"
                    }
                    default {
                        $encryptionRightsDefinitions += $labelDef.EncryptionPermission
                    }
                }
                Set-Label -Identity $lastLabelName -EncryptionRightsDefinitions $encryptionRightsDefinitions
            }
        }
    }

    Write-Host "Correcting label priority" -ForegroundColor $CommandInfo
    do
    {
        #TODO use before and after label
        $changedSomePrio = $false
        $priority = -1
        foreach($labelDef in $labelDefs)
        {
            $labelName = $labelDef.NameEN
            if (-Not [string]::IsNullOrEmpty($labelDef.Name)) { $labelName = $labelDef.Name }
            if (-Not [string]::IsNullOrEmpty($labelName))
            {
                $priority += 1
                $label = Get-Label -Identity $labelName
                if ($label.Priority -ne $priority)
                {
                    Set-Label -Identity $labelName -Priority $priority
                    $changedSomePrio = $true
                }
            }
        }
    } while ($changedSomePrio)

    if ($DisablingUnusedLabels)
    {
        Write-Host "Disabling unused labels" -ForegroundColor $CommandInfo
        $allLabels = Get-Label
        foreach($label in $allLabels)
        {
            $fnd = $false
            foreach($labelDef in $labelDefs)
            {
                $labelName = $labelDef.NameEN
                if (-Not [string]::IsNullOrEmpty($labelDef.Name)) { $labelName = $labelDef.Name }
                if (-Not [string]::IsNullOrEmpty($labelName))
                {
                    if ($label.Name -eq $labelName)
                    {
                        $fnd = $true
                        break
                    }
                }
            }
            if (-Not $fnd)
            {
                Write-Host "  - disabling $($label.Name)"
                throw "Not yet implemented" #TODO
            }
        }
    }

    Write-Host "Configuring Publish profiles in exchange" -ForegroundColor $CommandInfo
    #https://github.com/MicrosoftDocs/Azure-RMSDocs/blob/master/Azure-RMSDocs/rms-client/clientv2-admin-guide-customizations.md
    foreach($publishDef in $publishDefs)
    {
        #$publishDef = $publishDefs[0]
        if (-Not [string]::IsNullOrEmpty($publishDef.ProfileName))
        {
            Write-Host "  Publish profile: $($publishDef.ProfileName)"
            $configuredLables = $publishDef.Labels.Split(",")
            $policy = Get-LabelPolicy -Identity $publishDef.ProfileName -ErrorAction SilentlyContinue
            if (-Not $policy)
            {
                Write-Host "    - does not exist, creating"
                $policy = New-LabelPolicy -Name $publishDef.ProfileName -Labels $configuredLables -ModernGroupLocation $publishDef.ModernGrpLoc -ExchangeLocation $publishDef.ExchangeLoc -SharePointLocation $publishDef.SharePointLoc -OneDriveLocation $publishDef.OneDriveLoc -Comment $publishDef.Description
            }
            else
            {
                Write-Host "    - exists, updating"
            }
            $labelsToAdd = $null
            $labelsToRemove = $null
            foreach($lbl in $policy.Labels)
            {
                if ($configuredLables -notcontains $lbl)
                {
                    if (-Not $labelsToRemove) { $labelsToRemove = @() }
                    $labelsToRemove += $lbl
                }
            }
            foreach($lbl in $configuredLables)
            {
                if ($policy.Labels -notcontains $lbl)
                {
                    if (-Not $labelsToAdd) { $labelsToAdd = @() }
                    $labelsToAdd = $lbl
                }
            }
            Set-LabelPolicy -Identity $publishDef.ProfileName -AddLabels $labelsToAdd -RemoveLabels $labelsToRemove -Comment $publishDef.Description -AddExchangeLocation $publishDef.ExchangeLoc -AddSharePointLocation $publishDef.SharePointLoc -AddOneDriveLocation $publishDef.OneDriveLoc -AddModernGroupLocation $publishDef.ModernGrpLoc
            
            #Advanced settings
            Set-LabelPolicy -Identity $publishDef.ProfileName -AdvancedSettings @{
                RequireDowngradeJustification=$false
                EnablebarHiding=$true
                DisableDnf=$true
                Mandatory=$false
                SiteAndGroupMandatory=$false
                #https://docs.microsoft.com/en-us/azure/information-protection/rms-client/clientv2-admin-guide-customizations
                EnableCustomPermissions=$true
                HideBarByDefault=$true
                DisableMandatoryInOutlook=$true
                OutlookRecommendationEnabled=$false
                EnableContainerSupport=$true
                OutlookDefaultLabel="None"
                PFileSupportedExtensions="*"
                AdditionalPPrefixExtensions="*"
                PostponeMandatoryBeforeSave=$true
                EnableCustomPermissionsForCustomProtectedFiles=$true
                AttachmentAction="Automatic"
                ReportAnIssueLink="mailto:$AlyaSupportEmail"
                OutlookWarnUntrustedCollaborationLabel=$null
                OutlookJustifyUntrustedCollaborationLabel=$null
                OutlookBlockUntrustedCollaborationLabel=$null
                OutlookBlockTrustedDomains=$null
                OutlookJustifyTrustedDomains=$null
                OutlookUnlabeledCollaborationAction="Off"
                OutlookOverrideUnlabeledCollaborationExtensions=$null
                OutlookUnlabeledCollaborationActionOverrideMailBodyBehavior="Off"
                EnableOutlookDistributionListExpansion=$false
                OutlookGetEmailAddressesTimeOutMSProperty="3000"
                EnableAudit=$true
                LogMatchedContent=$true
                EnableLabelByMailHeader=$null
                EnableLabelBySharePointProperties=$true
                RunPolicyInBackground=$true
                JustificationTextForUserText=$null
                SharepointWebRequestTimeout="00:05:00"
                SharepointFileWebRequestTimeout="00:15:00"
                OutlookSkipSmimeOnReadingPaneEnabled=$true
                EnableTrackAndRevoke=$true
                EnableRevokeGuiSupport=$true
                OfficeContentExtractionTimeout="00:00:15"
            }
            if ($publishDef.DefaultLabel -and -Not [string]::IsNullOrEmpty($publishDef.DefaultLabel.Trim()))
            {
                $deflabel = Get-Label -Identity $publishDef.DefaultLabel -ErrorAction SilentlyContinue
                if ($deflabel)
                {
                    Set-LabelPolicy -Identity $publishDef.ProfileName -AdvancedSettings @{DefaultLabelId=$deflabel.ImmutableId}
                }
                else
                {
                    Write-Warning "Can't find default label named '$($publishDef.DefaultLabel)'"
                }
            }
            if ($AlyaAipCustomPageUrl -and $AlyaAipCustomPageUrl -ne "PleaseSpecify" -and -Not [string]::IsNullOrEmpty($AlyaAipCustomPageUrl))
            {
                Set-LabelPolicy -Identity $publishDef.ProfileName -AdvancedSettings @{CustomUrl=$AlyaAipCustomPageUrl}
            }
            Set-LabelPolicy -Identity $publishDef.ProfileName -RetryDistribution
        }
    }

    Write-Host "Actually configured labels"
    Get-Label | Format-Table -Property DisplayName, IsValid, Disabled

    Write-Host "Actually configured policies"
    Get-LabelPolicy | Format-Table -Property DisplayName, Name, DistributionStatus, Guid
}
catch
{
    try { Write-Error ($_.Exception | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}
	Write-Error ($_.Exception) -ErrorAction Continue
}

<#
# Logins
LoginTo-AIP -ServiceUserLogin

# =============================================================
# AIP stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "UnifiedLabels | Configure-LabelsAndPolicies | AIPSERVICE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

$actTemplates = Get-AipServiceTemplate
foreach ($actTemplate in $actTemplates)
{
    #$actTemplate = $actTemplates[1]
    $actTemplate = Get-AipServiceTemplate -TemplateId $actTemplate.TemplateId
    if (($actTemplate.Names | Where-Object { $_.Key -eq 1033 }).Value.StartsWith("Highly Confidential") -or `
        ($actTemplate.Names | Where-Object { $_.Key -eq 1033 }).Value.StartsWith("Confidential"))
    {
        Remove-AipServiceTemplate -TemplateId $actTemplate.TemplateId
    }
}
#>
#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC/YyniJT/vfkXr
# aQPpMYOYMBp38qdgdYIy4Wy/LVIHzKCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIHAmYSkNYmZOln7o
# x0if/fi0K/VvBhuLO0X4FWg1zyCXMA0GCSqGSIb3DQEBAQUABIICAGECE+cJr9PJ
# gqW/GAhgFiLrCjdgCgkG36RHTEl3hWU5ii2La+bG76KO3/U+UmzODOwSDKsYOT32
# 7pOYUsGQCLgDa37XbBorf6JM2CHtYX1X4TpuvNEg2DZkmJn9yrL3IPcTsARhq260
# VCf05RjF0hMooNJxVRWQoC7Nbyu8dm9yiS60RnEd8z9NVCcEn1WSZ+b/aR9BhPG+
# 5gcE/im4PheUCnzBlUFz5KBRnM4XPxLC9KZeoacZysnQHU970DJGaJEWOjeRMeZi
# C3FK28bacBh8kN1uk8b34ke8w4RpSRL/AZIMC4a3ZgShLl+isdZBGpbol/D2low6
# KLD6h0c/qlSxN0Cq3GOQ4fohGF9I/MsNs0lJTcGM2W8FLSE//JIMi4tyaxY9Fr1+
# LDlZkGDT8UN5thOcEga06+LG6OnmwNTQq8ZZWVM/cdZw/FM3f8GUs17A71wFF0hW
# SjwrpPAa/4ZNyMMsTnbi6k26c8qQC5eqYOGH/DJ9KexgHyV6E6Z10xyBceXoVJ9+
# p8hxH6PTyiPXHk1YFlX12+LAI2n8t4SoaNiiKvbXWAbhCYt324/0of5ocaTZogzx
# wUMhsoLEQsO5Vudg4TowCOo/suFY4Eyj3s5P35R8ioVRz3t65AiYJAT96NE6Iwc8
# wQaZClnR62wVoBKScRdS/XXSCZQ4ovDioYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCCSinXFwRCddDoSoGzZ/n2gEPM/mrcqgMzET9OEM1mdYwIUcpVYJm/1XY0p
# eGbaTH84HGJLSzYYDzIwMjYwMjA2MTE0MjIzWjADAgEBoFikVjBUMQswCQYDVQQG
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
# IEmzYdNe8GdQti6JkNhuTMDyMSurQ7sqmzQ17L7O/VphMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAhBmc1z/yvjYg
# vvfUrs8zEITErH8QmKBLgqxZfP5+Ea5qx4HirkNKtKanqbK8gIrcC+54T46nW9WH
# oefSvQElAcA5RiO0/qKqUhKxJjcEr9j7zRcKUhXoR317s7UFrjRqsQmKBbDHeMJZ
# Tyg+PZfdyROWn3tnHDzCdLnlGKyoZ6GDXLsPRpSCe0w06SbabkaDWQRlICfJRSNY
# SMKuVg1K80wMjDq1iXfzVsnEfvpzJ8AmvKnoaEFfe2RHh6M+Lrif4IWXVKYb0UZ6
# z52d8nFiysTChVPs9JGOTgrQ+2jAcTXgxQRbcsSPw02JbEIjgtorTVHOVFFurR+N
# p2QTePSIw4Rcbpn85nJ6/PlPZxPYSPftLq7FgjrzeealG2Q6TRFrvEmp1ejdrkDa
# VQm+1qJ17C1dRIaRl7fFrf1ERzm+vOmrhz2zqhhYLpuHMVaG0uUVIQANvJ1Xm+HF
# aFr4dA3ZqHKuGkHOmy3+CHI9XkAnwJbQ+Nd9xRq4Sb2cGrkxsE+8
# SIG # End signature block
