#Requires -Version 5.0

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
    24.09.2020 Konrad Brunner       Initial Version
    16.11.2022 Konrad Brunner       Added site and group definitions

#>

[CmdletBinding()]
Param(
    [string]$inputLabelFile = $null, #Defaults to "$AlyaData\aip\Labels.xlsx"
    [string]$inputPublishFile = $null #Defaults to "$AlyaData\aip\PublishProfiles.xlsx"
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

    Write-Host "Configuring labels in exchange"
    $encryptionRightsDefinitions = $null
    $labelName = $null
    $priority = -1
    foreach($labelDef in $labelDefs)
    {
        #$labelDef = $labelDefs[0]
        if (-Not [string]::IsNullOrEmpty($labelDef.NameEN))
        {
            Write-Host "  Label: $($labelDef.NameEN)"
            $labelName = $labelDef.NameEN
            $priority += 1
            $label = Get-Label -Identity $labelName -ErrorAction SilentlyContinue
            if (-Not $label)
            {
                Write-Host "    - does not exist, creating"
                $label = New-Label -Name $labelName -DisplayName $labelName -Tooltip $labelDef.CommentEN
            }
            else
            {
                Write-Host "    - exists, updating"
            }

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
            Set-Label -Identity $labelName -Priority $priority -LocaleSettings (ConvertTo-Json $DisplayNameLocaleSettings -Depth 3 -Compress),(ConvertTo-Json $TooltipLocaleSettings -Depth 3 -Compress)

            $AllowGuests = $labelDef.AllowGuests -eq "On"
            $Privacy = "Private"
            if ($labelDef.NameEN.Contains("Public"))
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
                    $encryptionProtectionType = "UserDefined"
                    $encryptionPromptUser = $true
                }
                else
                {
                    if ([string]::IsNullOrEmpty($labelDef.EncryptionPermissionEmail))
                    {
                        throw "Label '$($labelDef.NameEN)' does not have 'EncryptionPermissionEmail' specified"
                    }
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
                if (-Not $labelDef.SiteAndGroupProtection -or $labelDef.SiteAndGroupProtection -eq "Off")
                {
                    if ($encryptionProtectionType -eq "UserDefined")
                    {
                        Set-Label -Identity $labelName -EncryptionEnabled $true -EncryptionProtectionType $encryptionProtectionType `
                        -EncryptionPromptUser $encryptionPromptUser -EncryptionEncryptOnly $false -EncryptionDoNotForward $true `
                        -EncryptionContentExpiredOnDateInDaysOrNever $encryptionContentExpiredOnDateInDaysOrNever `
                        -EncryptionOfflineAccessDays $encryptionOfflineAccessDays -EncryptionRightsDefinitions $encryptionRightsDefinitions `
                        -SiteAndGroupProtectionEnabled $false
                    }
                    else
                    {
                        Set-Label -Identity $labelName -EncryptionEnabled $true -EncryptionProtectionType $encryptionProtectionType `
                        -EncryptionPromptUser $encryptionPromptUser -EncryptionDoNotForward $false `
                        -EncryptionContentExpiredOnDateInDaysOrNever $encryptionContentExpiredOnDateInDaysOrNever `
                        -EncryptionOfflineAccessDays $encryptionOfflineAccessDays -EncryptionRightsDefinitions $encryptionRightsDefinitions `
                        -SiteAndGroupProtectionEnabled $false
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
                        -SiteAndGroupProtectionPrivacy $Privacy -SiteExternalSharingControlType $SharingOption
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
                        -SiteAndGroupProtectionPrivacy $Privacy -SiteExternalSharingControlType $SharingOption
                    }
                }
            }
            else
            {
                if (-Not $labelDef.SiteAndGroupProtection -or $labelDef.SiteAndGroupProtection -eq "Off")
                {
                    Set-Label -Identity $labelName -EncryptionEnabled $false -SiteAndGroupProtectionEnabled $false
                }
                else
                {
                    Set-Label -Identity $labelName -EncryptionEnabled $false `
                        -SiteAndGroupProtectionEnabled $true -SiteAndGroupProtectionAllowAccessToGuestUsers $AllowGuests `
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
            #TODO check following code
            if ($label -and -not [string]::IsNullOrEmpty( $labelDef.EncryptionPermissionEmail))
            {
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
                Set-Label -Identity $labelName -EncryptionRightsDefinitions $encryptionRightsDefinitions
            }
        }
    }

    Write-Host "Correcting label priority"
    do
    {
        #TODO use before and after label
        $changedSomePrio = $false
        $priority = -1
        foreach($labelDef in $labelDefs)
        {
            if (-Not [string]::IsNullOrEmpty($labelDef.NameEN))
            {
                $priority += 1
                $label = Get-Label -Identity $labelDef.NameEN
                if ($label.Priority -ne $priority)
                {
                    Set-Label -Identity $labelDef.NameEN -Priority $priority
                    $changedSomePrio = $true
                }
            }
        }
    } while ($changedSomePrio)

    Write-Host "Disabling unused labels"
    $allLabels = Get-Label
    foreach($label in $allLabels)
    {
        $fnd = $false
        foreach($label in $allLabels)
        {
            if (-Not [string]::IsNullOrEmpty($labelDef.NameEN))
            {
                if ($label.Name -eq $labelDef.NameEN)
                {
                    $fnd = $true
                    break
                }
            }
        }
        if (-Not $fnd)
        {
            Write-Host "  - diabling $($label.Name)"
            $label.Disabled = $true
        }
    }

    Write-Host "Configuring Publish profiles in exchange"
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
                $policy = New-LabelPolicy -Name $publishDef.ProfileName -Labels $configuredLables
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
finally
{
    DisconnectFrom-EXOandIPPS
}
<#
# Logins
LoginTo-AIP

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
