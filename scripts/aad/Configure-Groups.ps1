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
Install-ModuleIfNotInstalled AzureAdPreview
Install-ModuleIfNotInstalled "ImportExcel"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
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
$groupDefs = Import-Excel $inputFile -ErrorAction Stop

Write-Host "Configured groups" -ForegroundColor $CommandInfo
$groupDefs | Select-Object -Property Type, Name, Description | Format-Table -AutoSize
$SecurityGroup = @()
$O365Group = @()
$O365GroupToFinish = @()
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
        $header = @{'Authorization'='Bearer '+$apiToken;'X-Requested-With'='XMLHttpRequest';'x-ms-client-request-id'=[guid]::NewGuid();'x-ms-correlation-id'=[guid]::NewGuid();}
        $url = "https://main.iam.ad.ext.azure.com/api/AccountSkus"
        $response = Invoke-WebRequest -Uri $url -Headers $header -Method GET -ErrorAction Stop
        $availableLics = $response | ConvertFrom-Json
        $url = "https://main.iam.ad.ext.azure.com/api/AccountSkus/Group/$($exGrp.Id)"
        $response = Invoke-WebRequest -Uri $url -Headers $header -Method GET -ErrorAction Stop
        $actualLics = $response | ConvertFrom-Json
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
                $response = Invoke-WebRequest -Uri $url -Headers $header -Method POST -Body $requestBody -ContentType "application/json" -ErrorAction Stop
            }
        }
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
        $O365GroupToFinish += $secGroup
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
        $header = @{'Authorization'='Bearer '+$apiToken;'X-Requested-With'='XMLHttpRequest';'x-ms-client-request-id'=[guid]::NewGuid();'x-ms-correlation-id'=[guid]::NewGuid();}
        $url = "https://main.iam.ad.ext.azure.com/api/AccountSkus"
        $response = Invoke-WebRequest -Uri $url -Headers $header -Method GET -ErrorAction Stop
        $availableLics = $response | ConvertFrom-Json
        $url = "https://main.iam.ad.ext.azure.com/api/AccountSkus/Group/$($exGrp.Id)"
        $response = Invoke-WebRequest -Uri $url -Headers $header -Method GET -ErrorAction Stop
        $actualLics = $response | ConvertFrom-Json
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
                $response = Invoke-WebRequest -Uri $url -Headers $header -Method POST -Body $requestBody -ContentType "application/json" -ErrorAction Stop
            }
        }
    }
}

if ($O365GroupToFinish.Count -gt 0)
{
    Write-Host "Configuring O365 group settings in exchange online" -ForegroundColor $CommandInfo
    #Write-Host "Sleeping now 5 Minutes to let sync aad the groups to exchange"
    #Start-Sleep -Seconds 300

    # =============================================================
    # Checking exchange service user
    # =============================================================

    . "$($AlyaScripts)\exchange\Configure-ServiceUser.ps1"

    # =============================================================
    # Exchange stuff
    # =============================================================

    Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
    Write-Host "AAD | Configure-Groups | EXCHANGE" -ForegroundColor $CommandInfo
    Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

    Get-PSSession | Remove-PSSession
    try
    {
        Write-Host "  Connecting to Exchange Online" -ForegroundColor $CommandInfo
        $SecExchUserPasswordForRunAsAccount = ConvertTo-SecureString $ExchUserPasswordForRunAsAccount -AsPlainText -Force
        $ExchangeCredential = New-Object System.Management.Automation.PSCredential ($ExchUser.UserPrincipalName, $SecExchUserPasswordForRunAsAccount)
        $Commands = @("Get-Command","Get-UnifiedGroup","Set-UnifiedGroup")
        $Session = New-PSSession –ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $ExchangeCredential -Authentication Basic -AllowRedirection
        Import-PSSession -Session $Session -DisableNameChecking:$true -AllowClobber:$true -CommandName $Commands | Out-Null

        Write-Host "Checking O365 groups" -ForegroundColor $CommandInfo
        foreach ($o365Group in $O365GroupToFinish)
        {
            Write-Host "  Group '$($o365Group.DisplayName)'"
            $uGrp = Get-UnifiedGroup -Identity $o365Group.DisplayName -ErrorAction SilentlyContinue
            if ($uGrp)
            {
                Write-Host "   - Group already exists! Updating."
                Set-UnifiedGroup -Identity $o365Group.DisplayName -Alias $o365Group.Alias -HiddenFromAddressListsEnabled:$true -CalendarMemberReadOnly:$true -RejectMessagesFromSendersOrMembers:$true -UnifiedGroupWelcomeMessageEnabled:$false -SubscriptionEnabled:$false -ModerationEnabled:$false -HiddenFromExchangeClientsEnabled:$true
            }
            else
            {
                throw "Group $($o365Group.DisplayName) not found!"
            }
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
        Get-PSSession | Remove-PSSession
    }

    Write-Host "Setting ProcessingState" -ForegroundColor $CommandInfo
    foreach ($secGroup in $O365GroupToFinish)
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