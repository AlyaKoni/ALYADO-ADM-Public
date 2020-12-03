#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

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
    Alya Basis Konfiguration ist Freie Software: Sie koennen es unter den
	Bedingungen der GNU General Public License, wie von der Free Software
	Foundation, Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
    veroeffentlichten Version, weiter verteilen und/oder modifizieren.
    Alya Basis Konfiguration wird in der Hoffnung, dass es nuetzlich sein wird,
	aber OHNE JEDE GEWAEHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewaehrleistung der MARKTFAEHIGKEIT oder EIGNUNG FUER EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Public License fuer weitere Details:
	https://www.gnu.org/licenses/gpl-3.0.txt

    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    04.03.2020 Konrad Brunner       Initial Version
    25.10.2020 Konrad Brunner       Changed from service user to new ExchangeOnline module

#>

[CmdletBinding()]
Param(
    [string]$inputFile = $null #Defaults to "$AlyaData\aad\Gruppen.xlsx"
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Configure-Groups-$($AlyaTimeString).log" | Out-Null

#Members
if (-Not $inputFile)
{
    $inputFile = "$AlyaData\aad\Gruppen.xlsx"
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Uninstall-ModuleIfInstalled "AzureAd"
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"
Install-ModuleIfNotInstalled "AzureAdPreview"
Install-ModuleIfNotInstalled "ImportExcel"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
#LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad

# =============================================================
# AD stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Configure-Groups | LOCAL" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Reading input file
Write-Host "Reading input file from '$inputFile" -ForegroundColor $CommandInfo
if (-Not (Test-Path $inputFile))
{
    throw "Input file '$inputFile' not found!"
}
$groupDefs = Import-Excel $inputFile -WorksheetName "Gruppen" -ErrorAction Stop

Write-Host "Configured groups" -ForegroundColor $CommandInfo
$groupDefs | Select-Object -Property Type, Name, Description | Format-Table -AutoSize
$SecurityGroup = @()
$O365Group = @()
$GroupToDisable = @()
foreach ($groupDef in $groupDefs)
{
    if ($groupDef.Activ -eq "yes")
    {
        if ($groupDef.Type -eq "O365Group")
        {
            $O365Group += $groupDef
        }
        if ($groupDef.Type -eq "SecurityGroup")
        {
            $SecurityGroup += $groupDef
        }
    }
    else
    {
        $GroupToDisable += $groupDef
    }
}

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Configure-Groups | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Checking security groups" -ForegroundColor $CommandInfo
foreach ($secGroup in $SecurityGroup)
{
    Write-Host "  Group '$($secGroup.DisplayName)'"
    $exGrp = Get-AzureADMSGroup -SearchString $secGroup.DisplayName
    if ($exGrp.Count -gt 1)
    {
        foreach($grp in $exGrp)
        {
            if ($grp.DisplayName -eq $secGroup.DisplayName)
            {
                $exGrp = $grp
                break
            }
        }
    }
    if ($exGrp)
    {
        Write-Host "   - Group already exists! Updating."
        if ([string]::IsNullOrEmpty($secGroup.DanymicRule))
        {
            $tmp = Set-AzureADMSGroup -Id $exGrp.Id -Description $secGroup.Description -DisplayName $secGroup.DisplayName -MailNickname $secGroup.Alias -Visibility $secGroup.Visibility
        }
        else
        {
            $tmp = Set-AzureADMSGroup -Id $exGrp.Id -Description $secGroup.Description -DisplayName $secGroup.DisplayName -MailNickname $secGroup.Alias -GroupTypes "DynamicMembership" -MembershipRule $secGroup.DanymicRule -MembershipRuleProcessingState "On" -Visibility $secGroup.Visibility
        }
    }
    else
    {
        Write-Host "   - Group doesn't exists! Creating."
        if ([string]::IsNullOrEmpty($secGroup.DanymicRule))
        {
            $exGrp = New-AzureADMSGroup -DisplayName $secGroup.DisplayName -Description $secGroup.Description -MailEnabled $false -MailNickname $secGroup.Alias -SecurityEnabled $True -Visibility $secGroup.Visibility
        }
        else
        {
            $exGrp = New-AzureADMSGroup -DisplayName $secGroup.DisplayName -Description $secGroup.Description -MailEnabled $false -MailNickname $secGroup.Alias -SecurityEnabled $True -GroupTypes "DynamicMembership" -MembershipRule $secGroup.DanymicRule -MembershipRuleProcessingState "On" -Visibility $secGroup.Visibility
        }
    }

    if (-Not [string]::IsNullOrEmpty($secGroup.Licenses))
    {
        $apiToken = Get-AzAccessToken
        if (-Not $apiToken)
        {
            Write-Warning "Can't aquire an access token."
            exit
        }
        $Global:retryCount = 10
        do
        {
            try
            {
                $header = @{'Authorization'='Bearer '+$apiToken;'Content-Type'='application/json';'X-Requested-With'='XMLHttpRequest';'x-ms-client-request-id'=[guid]::NewGuid();'x-ms-correlation-id'=[guid]::NewGuid();}
                $url = "https://main.iam.ad.ext.azure.com/api/AccountSkus"
                $response = Invoke-WebRequest -Uri $url -Headers $header -Method GET -ErrorAction Stop
                $availableLics = $response | ConvertFrom-Json
                $url = "https://main.iam.ad.ext.azure.com/api/AccountSkus/Group/$($exGrp.Id)"
                #following call shows from time to time 404. Don't know why
                $response = Invoke-WebRequest -Uri $url -Headers $header -Method GET -ErrorAction Stop
                $actualLics = $response | ConvertFrom-Json
                $Global:retryCount = -1
            } catch {
                Write-Host "Exception catched: $($_.Exception.Message)"
                Write-Host "Retrying $Global:retryCount times"
                $Global:retryCount--
                Write-Host "Sleeping 60 seconds"
                Start-Sleep -Seconds 60
            }
        } while ($Global:retryCount -gt 0)
        foreach($license in $secGroup.Licenses.Split(","))
        {
            $licPresent = $false
            $licSku = $null
            foreach($exlic in $actualLics.licenses)
            {
                if ($exlic.accountSkuId -eq "$($AlyaTenantNameId):$($license)")
                {
                    $licPresent = $true
                    break
                }
            }
            foreach($exlic in $availableLics)
            {
                if ($exlic.accountSkuId -like "*:$($license)")
                {
                    $licSku = $exlic.accountSkuId
                    break
                }
            }
            if (-Not $licSku)
            {
                Write-Warning "Can't find license '$($license)' in your list of available licenses!"
                continue
            }
            if (-Not $licPresent)
            {
                Write-Host "       Configuring license '$($license)'"
                $licenceAssignmentConfig = @{
                    assignments = @(
                        @{
                            "objectId"       = $exGrp.Id
                            "isUser"         = $false
                            "addLicenses"    = @(
                                @{
                                "accountSkuId"         = $licSku
                                "disabledServicePlans" = @()
                                }
                            )
                            "removeLicenses" = @()
                            "updateLicenses" = @()
                        }
                    )
                }
                $requestBody = $licenceAssignmentConfig | ConvertTo-Json -Depth 5
                $url = "https://main.iam.ad.ext.azure.com/api/AccountSkus/assign"
                $response = Invoke-WebRequest -Uri $url -Headers $header -Method POST -Body $requestBody -ContentType "application/json; charset=UTF-8" -ErrorAction Stop
            }
        }
        $url = "https://main.iam.ad.ext.azure.com/api/AccountSkus/Group/$($exGrp.Id)/Reprocess"
        $response = Invoke-WebRequest -Uri $url -Headers $header -Method POST -Body $null -ErrorAction Stop
    }
}

Write-Host "Checking o365 groups" -ForegroundColor $CommandInfo
foreach ($secGroup in $O365Group)
{
    Write-Host "  Group '$($secGroup.DisplayName)'"
    $exGrp = Get-AzureADMSGroup -SearchString $secGroup.DisplayName
    if ($exGrp.Count -gt 1)
    {
        foreach($grp in $exGrp)
        {
            if ($grp.DisplayName -eq $secGroup.DisplayName)
            {
                $exGrp = $grp
                break
            }
        }
    }
    if ($exGrp)
    {
        Write-Host "   - Group already exists! Updating."
        if ([string]::IsNullOrEmpty($secGroup.DanymicRule))
        {
            $tmp = Set-AzureADMSGroup -Id $exGrp.Id -Description $secGroup.Description -DisplayName $secGroup.DisplayName -MailNickname $secGroup.Alias -Visibility $secGroup.Visibility
        }
        else
        {
            $tmp = Set-AzureADMSGroup -Id $exGrp.Id -Description $secGroup.Description -DisplayName $secGroup.DisplayName -MailNickname $secGroup.Alias -GroupTypes "DynamicMembership", "Unified" -MembershipRule $secGroup.DanymicRule -MembershipRuleProcessingState "On" -Visibility $secGroup.Visibility
        }
    }
    else
    {
        Write-Host "   - Group doesn't exists! Creating."
        if ([string]::IsNullOrEmpty($secGroup.DanymicRule))
        {
            $exGrp = New-AzureADMSGroup -DisplayName $secGroup.DisplayName -Description $secGroup.Description -MailEnabled $true -MailNickname $secGroup.Alias -SecurityEnabled $True -GroupTypes "Unified" -Visibility $secGroup.Visibility
        }
        else
        {
            $exGrp = New-AzureADMSGroup -DisplayName $secGroup.DisplayName -Description $secGroup.Description -MailEnabled $true -MailNickname $secGroup.Alias -SecurityEnabled $True -GroupTypes "DynamicMembership", "Unified" -MembershipRule $secGroup.DanymicRule -MembershipRuleProcessingState "Paused" -Visibility $secGroup.Visibility
        }
    }

    if (-Not [string]::IsNullOrEmpty($secGroup.Licenses))
    {
        $apiToken = Get-AzAccessToken
        if (-Not $apiToken)
        {
            Write-Warning "Can't aquire an access token."
            exit
        }
        $Global:retryCount = 10
        do
        {
            try
            {
                $header = @{'Authorization'='Bearer '+$apiToken;'Content-Type'='application/json';'X-Requested-With'='XMLHttpRequest';'x-ms-client-request-id'=[guid]::NewGuid();'x-ms-correlation-id'=[guid]::NewGuid();}
                $url = "https://main.iam.ad.ext.azure.com/api/AccountSkus"
                $response = Invoke-WebRequest -Uri $url -Headers $header -Method GET -ErrorAction Stop
                $availableLics = $response | ConvertFrom-Json
                $url = "https://main.iam.ad.ext.azure.com/api/AccountSkus/Group/$($exGrp.Id)"
                $response = Invoke-WebRequest -Uri $url -Headers $header -Method GET -ErrorAction Stop
                $actualLics = $response | ConvertFrom-Json
                $Global:retryCount = -1
            } catch {
                Write-Host "Exception catched: $($_.Exception.Message)"
                Write-Host "Retrying $Global:retryCount times"
                $Global:retryCount--
                if ($Global:retryCount -lt 0) { throw }
                Start-Sleep -Seconds 10
            }
        } while ($Global:retryCount -gt 0)
        foreach($license in $secGroup.Licenses.Split(","))
        {
            $licPresent = $false
            $licSku = $null
            foreach($exlic in $actualLics.licenses)
            {
                if ($exlic.accountSkuId -eq "$($AlyaTenantNameId):$($license)")
                {
                    $licPresent = $true
                    break
                }
            }
            foreach($exlic in $availableLics)
            {
                if ($exlic.accountSkuId -like "*:$($license)")
                {
                    $licSku = $exlic.accountSkuId
                    break
                }
            }
            if (-Not $licSku)
            {
                Write-Warning "       Can't find license '$($license)' in your list of available licenses!"
                continue
            }
            if (-Not $licPresent)
            {
                Write-Host "       Configuring license '$($license)'"
                $licenceAssignmentConfig = @{
                    assignments = @(
                        @{
                            "objectId"       = $exGrp.Id
                            "isUser"         = $false
                            "addLicenses"    = @(
                                @{
                                "accountSkuId"         = $licSku
                                "disabledServicePlans" = @()
                                }
                            )
                            "removeLicenses" = @()
                            "updateLicenses" = @()
                        }
                    )
                }
                $requestBody = $licenceAssignmentConfig | ConvertTo-Json -Depth 5
                $url = "https://main.iam.ad.ext.azure.com/api/AccountSkus/assign"
                $response = Invoke-WebRequest -Uri $url -Headers $header -Method POST -Body $requestBody -ContentType "application/json; charset=UTF-8" -ErrorAction Stop
            }
        }
        $url = "https://main.iam.ad.ext.azure.com/api/AccountSkus/Group/$($exGrp.Id)/Reprocess"
        $response = Invoke-WebRequest -Uri $url -Headers $header -Method POST -Body $null -ErrorAction Stop
    }
}

# =============================================================
# Exchange stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Configure-Groups | EXCHANGE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Configuring O365 group settings in exchange online" -ForegroundColor $CommandInfo
try
{
    Write-Host "  Connecting to Exchange Online" -ForegroundColor $CommandInfo
    LoginTo-EXO

    Write-Host "Checking O365 groups" -ForegroundColor $CommandInfo
    foreach ($grp in $O365Group)
    {
        Write-Host "  Group '$($grp.DisplayName)'"
        $Global:retryCount = 5
        do
        {
            $uGrp = Get-UnifiedGroup -Identity $grp.DisplayName -ErrorAction SilentlyContinue
            if ($uGrp)
            {
                Write-Host "   - Group found! Updating."
                $HiddenFromAddressListsEnabled = $true
                $CalendarMemberReadOnly = $true
                $RejectMessagesFromSendersOrMembers = $true
                $UnifiedGroupWelcomeMessageEnabled = $false
                $SubscriptionEnabled = $false
                $ModerationEnabled = $false
                $HiddenFromExchangeClientsEnabled = $true
                if ($grp.O365HiddenFromAddressListsEnabled -ne $null) { $HiddenFromAddressListsEnabled = $grp.O365HiddenFromAddressListsEnabled }
                if ($grp.O365CalendarMemberReadOnly -ne $null) { $CalendarMemberReadOnly = $grp.O365CalendarMemberReadOnly }
                if ($grp.O365RejectMessagesFromSendersOrMembers -ne $null) { $RejectMessagesFromSendersOrMembers = $grp.O365RejectMessagesFromSendersOrMembers }
                if ($grp.O365UnifiedGroupWelcomeMessageEnabled -ne $null) { $UnifiedGroupWelcomeMessageEnabled = $grp.O365UnifiedGroupWelcomeMessageEnabled }
                if ($grp.O365SubscriptionEnabled -ne $null) { $SubscriptionEnabled = $grp.O365SubscriptionEnabled }
                if ($grp.O365ModerationEnabled -ne $null) { $ModerationEnabled = $grp.O365ModerationEnabled }
                if ($grp.O365HiddenFromExchangeClientsEnabled -ne $null) { $HiddenFromExchangeClientsEnabled = $grp.O365HiddenFromExchangeClientsEnabled }
                Set-UnifiedGroup -Identity $grp.DisplayName -Alias $grp.Alias -HiddenFromAddressListsEnabled:$true -CalendarMemberReadOnly:$true -RejectMessagesFromSendersOrMembers:$true -UnifiedGroupWelcomeMessageEnabled:$false -SubscriptionEnabled:$false -ModerationEnabled:$false -HiddenFromExchangeClientsEnabled:$true
                $Global:retryCount = -1
            }
            else
            {
                Write-Host "Group $($grp.DisplayName) not found! Waiting 30 seconds and retrying"
                Start-Sleep -Seconds 30
                $Global:retryCount--
            }
        } while ($Global:retryCount -ge 0)
    }
}
catch
{
    try { Write-Error ($_.Exception | ConvertTo-Json -Depth 3) -ErrorAction Continue } catch {}
    Write-Error ($_.Exception) -ErrorAction Continue
    Write-Error "Please delete created groups by hand. Clean them from recycle bin. Start over again after fixing the issue." -ErrorAction Continue
}
finally
{
    DisconnectFrom-EXOandIPPS
}

Write-Host "Setting ProcessingState" -ForegroundColor $CommandInfo
foreach ($secGroup in $o365Group)
{
    $exGrp = Get-AzureADMSGroup -SearchString $secGroup.DisplayName
    if ($exGrp.Count -gt 1)
    {
        foreach($grp in $exGrp)
        {
            if ($grp.DisplayName -eq $secGroup.DisplayName)
            {
                $exGrp = $grp
                break
            }
        }
    }
    if ($exGrp)
    {
        if (-Not [string]::IsNullOrEmpty($secGroup.DanymicRule))
        {
            Write-Host "  Group '$($secGroup.DisplayName)'"
            Write-Host "   - Setting processing state to On"
            $tmp = Set-AzureADMSGroup -Id $exGrp.Id -MembershipRuleProcessingState "On"
        }
    }

}

Write-Host "Checking disabled groups" -ForegroundColor $CommandInfo
foreach ($secGroup in $GroupToDisable)
{
    Write-Host "  Group '$($secGroup.DisplayName)'"
    $exGrp = Get-AzureADMSGroup -SearchString $secGroup.DisplayName
    if ($exGrp.Count -gt 1)
    {
        foreach($grp in $exGrp)
        {
            if ($grp.DisplayName -eq $secGroup.DisplayName)
            {
                $exGrp = $grp
                break
            }
        }
    }
    if ($exGrp)
    {
        Write-Host "    disabling"
        Set-AzureADMSGroup -Id $exGrp.Id -MailEnabled $false -SecurityEnabled $false -Visibility $false
    }
}


#Stopping Transscript
Stop-Transcript