#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2026

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
    10.03.2025 Konrad Brunner       Initial Creation

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$domainToRemove,
    [bool]$dryRun = $true
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\exchange\Remove-Domain-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"

# Members
$allChanges = @()

# Logging in
Write-Host "Logging in to graph" -ForegroundColor $CommandInfo
Connect-MGGraph -Scopes @("Directory.ReadWrite.All","Domain.ReadWrite.All") -TenantId $AlyaTenantId -NoWelcome

# Checking actual user
#TODO Migration admin user
# Remove global admins with domain to change in upn
$req = Invoke-MgGraphRequest -Method "Get" -Uri "https://graph.microsoft.com/beta/me"
if ($req.userPrincipalName.Contains($domainToRemove))
{
    Write-Error "Your actual logged in user is in same domain you like to remove. Thats not possible. Please use a different user!"
    exit
}

if (-Not (Test-Path "$($AlyaData)\exchange\RemoveDomain"))
{
    New-Item -ItemType Directory -Path "$($AlyaData)\exchange\RemoveDomain" -Force
}

try {

    # Suggestions
    #Write-Host "Only in: United States, Canada (English only), United Kingdom, Australia, New Zealand and South Africa" -ForegroundColor Magenta
    #Write-Host "Consider buying a Business Assist Subscription" -ForegroundColor Magenta
    #Write-Host "https://support.microsoft.com/de-de/office/business-assistent-f%C3%BCr-microsoft-365-37deb8fe-61cc-4cf9-9ad1-1c8d93475070" -ForegroundColor Magenta
    #Pause
    Write-Host "MX record already changed to unreachable.unknown.ch?" -ForegroundColor Magenta
    Pause
    Write-Host "Microsoft support advised for special support?" -ForegroundColor Magenta
    Pause

    # Getting domains
    Write-Host "Getting domains" -ForegroundColor $CommandInfo
    $req = Invoke-MgGraphRequest -Method "Get" -Uri "https://graph.microsoft.com/beta/domains"
    $domains = $req.value
    $domainToUse = ($domains | Where-Object { $_.Id -like "*.onmicrosoft.com" }).Id
    $domains | ConvertTo-Json -Depth 10 | Set-Content -Path "$($AlyaData)\exchange\RemoveDomain\$($domainToRemove)-domainsBeforeDefault.json"

    # Changing default domain
    Write-Host "Changing default domain" -ForegroundColor $CommandInfo
    $wasDefault = $false
    $fromDomain = $domains | Where-Object { $_.Id -eq $domainToRemove }
    if ($fromDomain.IsDefault) {
        $wasDefault = $true
        Write-Warning "Changing default domain from '$domainToRemove' to '$domainToUse'"
        $body = @{ IsDefault = $true } | ConvertTo-Json -Compress -Depth 99
        if (-Not $dryRun) {
            $req = Invoke-MgGraphRequest -Method "Patch" -Uri "https://graph.microsoft.com/beta/domains/$($domainToUse)" -Body $body
            $allChanges += @{
                Object = "Domain"
                Action = "SetDefault"
                Old = "$domainToRemove"
                New = "$domainToUse"
            }
        }
    }
    $req = Invoke-MgGraphRequest -Method "Get" -Uri "https://graph.microsoft.com/beta/domains"
    $domains = $req.value
    $fromDomain = $domains | Where-Object { $_.Id -eq $domainToRemove }
    if ($fromDomain.IsDefault) {
        Write-Host "Default domain changed from '$domainToRemove' to '$domainToUse'"
    }
    else
    {
        if (-Not $dryRun -and $wasDefault)
        {
            Write-Error "Was not able to change default domain"
        }
    }
    $domains | ConvertTo-Json -Depth 10 | Set-Content -Path "$($AlyaData)\exchange\RemoveDomain\$($domainToRemove)-domainsAfterDefault.json"

    # Getting users
    Write-Host "Getting users" -ForegroundColor $CommandInfo
    $nextUri = "https://graph.microsoft.com/beta/users"
    $users = @()
    do {
        $req = Invoke-MgGraphRequest -Method "Get" -Uri $nextUri
        $users += $req.value
        $nextUri = $req.'@odata.nextLink'
    } while ($nextUri)
    $users | ConvertTo-Json -Depth 10 | Set-Content -Path "$($AlyaData)\exchange\RemoveDomain\$($domainToRemove)-usersBeforeChange.json"

    # Getting groups
    Write-Host "Getting groups" -ForegroundColor $CommandInfo
    $nextUri = "https://graph.microsoft.com/beta/groups"
    $groups = @()
    do {
        $req = Invoke-MgGraphRequest -Method "Get" -Uri $nextUri
        $groups += $req.value
        $nextUri = $req.'@odata.nextLink'
    } while ($nextUri)
    $groups | ConvertTo-Json -Depth 10 | Set-Content -Path "$($AlyaData)\exchange\RemoveDomain\$($domainToRemove)-groupsBeforeChange.json"

    # Changing user upns
    Write-Host "Changing user upns" -ForegroundColor $CommandInfo
    foreach($user in $users) {
        Write-Host "User: $($user.userPrincipalName)"
        if ($user.userPrincipalName -like "*$domainToRemove") {
            $newUpn = $user.userPrincipalName.Replace($domainToRemove, $domainToUse)
            Write-Warning "Changing upn '$($user.userPrincipalName)' to '$newUpn'"
            $body = @{ userPrincipalName = $newUpn } | ConvertTo-Json -Compress -Depth 99
            if (-Not $dryRun) {
                try {
                    $req = Invoke-MgGraphRequest -Method "Patch" -Uri "https://graph.microsoft.com/beta/users/$($user.Id)" -Body $body
                    $allChanges += @{
                        Object = "UPN"
                        Action = "Changed"
                        Old = "$($user.userPrincipalName)"
                        New = "$newUpn"
                    }
                } catch {
                    Write-Error $_.Exception -ErrorAction SilentlyContinue
                    Write-Warning "You can't change your own upn!"
                    #TODO
                }
            }
        }
    }
    $allChanges | ConvertTo-Json -Depth 10 | Set-Content -Path "$($AlyaData)\exchange\RemoveDomain\$($domainToRemove)-changesUpnChange.json"
    $nextUri = "https://graph.microsoft.com/beta/users"
    $usersAfterUpnChange = @()
    do {
        $req = Invoke-MgGraphRequest -Method "Get" -Uri $nextUri
        $usersAfterUpnChange += $req.value
        $nextUri = $req.'@odata.nextLink'
    } while ($nextUri)
    $usersAfterUpnChange | ConvertTo-Json -Depth 10 | Set-Content -Path "$($AlyaData)\exchange\RemoveDomain\$($domainToRemove)-usersAfterUpnChange.json"

    Write-Host "Allow now changes to be synced across services" -ForegroundColor Magenta
    Pause

    # Logging in
    Write-Host "Logging in to exchange" -ForegroundColor $CommandInfo
    Connect-ExchangeOnline -ShowProgress $true

    # Changing user proxy addresses
    Write-Host "Changing user proxy addresses" -ForegroundColor $CommandInfo
    foreach($user in $users) {
        Write-Host "User: $($user.userPrincipalName)"
        $usr = Get-Mailbox -Identity $user.id -ErrorAction SilentlyContinue
        if ($usr) {
            foreach($mail in $usr.EmailAddresses) {
                #TODO check does not work, if addres only has to be removed
                if ($mail -like "smtp:*$domainToRemove" -and $mail -notlike "*$($user.userPrincipalName)" -and $mail -notlike "*$($usr.PrimarySmtpAddress)") {
                    $newMail = $mail.Replace($domainToRemove, $domainToUse)
                    Write-Warning "Changing user '$($user.userPrincipalName)' proxy mail '$mail' to '$newMail'"
                    if (-Not $dryRun) {
                        Set-Mailbox -Identity $user.id -EmailAddresses @{Add = $newMail} #-MicrosoftOnlineServicesID $newMail
                        Set-Mailbox -Identity $user.id -EmailAddresses @{Remove = $mail}
                        $allChanges += @{
                            Object = "UPN"
                            Action = "Changed"
                            Old = "$($user.userPrincipalName)"
                            New = "$newUpn"
                        }
                    }
                }
            }
        }
    }
    $allChanges | ConvertTo-Json -Depth 10 | Set-Content -Path "$($AlyaData)\exchange\RemoveDomain\$($domainToRemove)-changesProxyAddressChange.json"
    $nextUri = "https://graph.microsoft.com/beta/users"
    $usersAfterProxyAddressChange = @()
    do {
        $req = Invoke-MgGraphRequest -Method "Get" -Uri $nextUri
        $usersAfterProxyAddressChange += $req.value
        $nextUri = $req.'@odata.nextLink'
    } while ($nextUri)
    $usersAfterProxyAddressChange | ConvertTo-Json -Depth 10 | Set-Content -Path "$($AlyaData)\exchange\RemoveDomain\$($domainToRemove)-usersAfterProxyAddressChange.json"

    # Changing group domains
    Write-Host "Changing group domains" -ForegroundColor $CommandInfo
    foreach($group in $groups) {
        Write-Host "Group: $($group.DisplayName)"
        if ($group.mail -like "*$domainToRemove") {
            if ($group.groupTypes -contains "Unified") {
                $oldMail = $group.mail
                $newMail = $group.mail.Replace($domainToRemove, $domainToUse)
                Write-Warning "Changing M365 group mail '$oldMail' to '$newMail'"
                if (-Not $dryRun) {
                    Set-UnifiedGroup -Identity $group.id -EmailAddresses @{Add = $newMail}
                    Set-UnifiedGroup -Identity $group.id -PrimarySmtpAddress $newMail
                    Set-UnifiedGroup -Identity $group.id -EmailAddresses @{Remove = $oldMail}
                }
                $allChanges += @{
                    Object = "Group"
                    Action = "Changed"
                    Old = $oldMail
                    New = $newMail
                }
            }
            if ($group.groupTypes.Count -eq 0) {
                $oldMail = $group.mail
                $newMail = $group.mail.Replace($domainToRemove, $domainToUse)
                $grp = Get-DistributionGroup -Identity $group.id -ErrorAction SilentlyContinue
                if ($grp) {
                    Write-Warning "Changing dsitribution group mail '$oldMail' to '$newMail'"
                    $oldMail = $group.mail
                    $newMail = $group.mail.Replace($domainToRemove, $domainToUse)
                    if (-Not $dryRun) {
                        Set-DistributionGroup -Identity $group.id -EmailAddresses @{Add = $newMail}
                        Set-DistributionGroup -Identity $group.id -PrimarySmtpAddress $newMail
                        Set-DistributionGroup -Identity $group.id -EmailAddresses @{Remove = $oldMail}
                    }
                    $allChanges += @{
                        Object = "Group"
                        Action = "Changed"
                        Old = $oldMail
                        New = $newMail
                    }
                } else {
                    Write-Host "Don't know how to manage group '$oldMail' - '$($group.id))'" -ForegroundColor Red
                }
            }
        }
    }
    $allChanges | ConvertTo-Json -Depth 10 | Set-Content -Path "$($AlyaData)\exchange\RemoveDomain\$($domainToRemove)-changesGroupDomainChange.json"
    $nextUri = "https://graph.microsoft.com/beta/groups"
    $groupsAfterChange = @()
    do {
        $req = Invoke-MgGraphRequest -Method "Get" -Uri $nextUri
        $groupsAfterChange += $req.value
        $nextUri = $req.'@odata.nextLink'
    } while ($nextUri)
    $groupsAfterChange | ConvertTo-Json -Depth 10 | Set-Content -Path "$($AlyaData)\exchange\RemoveDomain\$($domainToRemove)-groupsAfterChange.json"

    # Changing group proxy addresses
    Write-Host "Changing group proxy addresses" -ForegroundColor $CommandInfo
    foreach($group in $groups) {
        Write-Host "Group: $($group.DisplayName)"
        $grp = Get-Mailbox -Identity $group.id -ErrorAction SilentlyContinue
        if ($grp) {
            foreach($mail in $grp.EmailAddresses) {
                if ($mail -like "smtp:*$domainToRemove" -and $mail -notlike "*$($group.mail)" -and $mail -notlike "*$($grp.PrimarySmtpAddress)") {
                    $newMail = $mail.Replace($domainToRemove, $domainToUse)
                    Write-Warning "Changing user '$($user.userPrincipalName)' proxy mail '$mail' to '$newMail'"
                    if (-Not $dryRun) {
                        Set-Mailbox -Identity $group.id -EmailAddresses @{Add = $newMail}
                        Set-Mailbox -Identity $group.id -EmailAddresses @{Remove = $mail}
                    }
                    $allChanges += @{
                        Object = "GroupProxy"
                        Action = "Changed"
                        Old = $mail
                        New = $newMail
                    }
                }
            }
        }
    }
    $allChanges | ConvertTo-Json -Depth 10 | Set-Content -Path "$($AlyaData)\exchange\RemoveDomain\$($domainToRemove)-changesGroupProxyChange.json"
    $nextUri = "https://graph.microsoft.com/beta/groups"
    $groupsAfterChange = @()
    do {
        $req = Invoke-MgGraphRequest -Method "Get" -Uri $nextUri
        $groupsAfterChange += $req.value
        $nextUri = $req.'@odata.nextLink'
    } while ($nextUri)
    $groupsAfterChange | ConvertTo-Json -Depth 10 | Set-Content -Path "$($AlyaData)\exchange\RemoveDomain\$($domainToRemove)-groupsAfterProxyChange.json"

    # Changing contacts
    Write-Host "Changing contacts" -ForegroundColor $CommandInfo
    $cntcts = Get-Contact -ResultSize 9999 | fl
    foreach($cntct in $cntcts) {
        Write-Host "Contact: $($cntct.DisplayName)"
        if ($cntct.WindowsEmailAddress -like "*$domainToRemove") {
            $newMail = $cntct.WindowsEmailAddress.Replace($domainToRemove, $domainToUse)
            Write-Warning "Changing contact '$($cntct.DisplayName)' mail '$($cntct.WindowsEmailAddress)' to '$newMail'"
            if (-Not $dryRun) {
                Set-Contact -Identity $cntct.id -WindowsEmailAddress $newMail
            }
            $allChanges += @{
                Object = "Contact"
                Action = "Changed"
                Old = $cntct.WindowsEmailAddress
                New = $newMail
            }
        }
    }
    $allChanges | ConvertTo-Json -Depth 10 | Set-Content -Path "$($AlyaData)\exchange\RemoveDomain\$($domainToRemove)-changesContactChange.json"

    # Changing contacts
    Write-Host "Changing mail contacts" -ForegroundColor $CommandInfo
    $cntcts = Get-MailContact -ResultSize 9999
    foreach($cntct in $cntcts) {
        Write-Host "MailContact: $($cntct.DisplayName)"
        if ($cntct.WindowsEmailAddress -like "*$domainToRemove") {
            $newMail = $cntct.WindowsEmailAddress.Replace($domainToRemove, $domainToUse)
            Write-Warning "Changing contact '$($cntct.DisplayName)' WindowsEmailAddress '$($cntct.WindowsEmailAddress)' to '$newMail'"
            if (-Not $dryRun) {
                Set-MailContact -Identity $cntct.id -WindowsEmailAddress $newMail
            }
            $allChanges += @{
                Object = "ContactWindowsEmailAddress"
                Action = "Changed"
                Old = $cntct.WindowsEmailAddress
                New = $newMail
            }
        }
        if ($cntct.ExternalEmailAddress -like "*$domainToRemove") {
            $newMail = $cntct.ExternalEmailAddress.Replace($domainToRemove, $domainToUse)
            Write-Warning "Changing contact '$($cntct.DisplayName)' ExternalEmailAddress '$($cntct.ExternalEmailAddress)' to '$newMail'"
            if (-Not $dryRun) {
                Set-MailContact -Identity $cntct.id -ExternalEmailAddress $newMail
            }
            $allChanges += @{
                Object = "ContactExternalEmailAddress"
                Action = "Changed"
                Old = $cntct.ExternalEmailAddress
                New = $newMail
            }
        }
    }
    $allChanges | ConvertTo-Json -Depth 10 | Set-Content -Path "$($AlyaData)\exchange\RemoveDomain\$($domainToRemove)-changesMailContactChange.json"

    #TODO SIP adresses

    # Changing mailboxes
    Write-Host "Changing mailboxes" -ForegroundColor $CommandInfo
    $mboxes = Get-Mailbox -ResultSize unlimited
    foreach($mbox in $mboxes) {
        Write-Host "Mailbox: $($mbox.DisplayName)"
        if ($mbox.WindowsEmailAddress -like "*$domainToRemove") {
            $newMail = $mbox.WindowsEmailAddress.Replace($domainToRemove, $domainToUse)
            Write-Warning "Changing mailbox '$($cntct.DisplayName)' mail '$($mbox.WindowsEmailAddress))' to '$newMail'"
            if (-Not $dryRun) {
                Set-Mailbox -Identity $mbox.id -WindowsEmailAddress $newMail
            }
            $allChanges += @{
                Object = "MailboxWindowsEmailAddress"
                Action = "Changed"
                Old = $mbox.WindowsEmailAddress
                New = $newMail
            }
        }
        if ($mbox.MicrosoftOnlineServicesID -like "*$domainToRemove") {
            $newMail = $mbox.MicrosoftOnlineServicesID.Replace($domainToRemove, $domainToUse)
            Write-Warning "Changing mailbox '$($cntct.DisplayName)' ms service id '$($mbox.MicrosoftOnlineServicesID))' to '$newMail'"
            if (-Not $dryRun) {
                Set-Mailbox -Identity $mbox.id -MicrosoftOnlineServicesID $newMail
            }
            $allChanges += @{
                Object = "MailboxMicrosoftOnlineServicesID"
                Action = "Changed"
                Old = $mbox.MicrosoftOnlineServicesID
                New = $newMail
            }
        }
        foreach($mail in $mbox.EmailAddresses) {
            if ($mail -like "smtp:*$domainToRemove") {
                $newMail = $mail.Replace($domainToRemove, $domainToUse)
                Write-Warning "Changing mailbox '$($mbox.DisplayName)'  mail '$mail' to '$newMail'"
                if (-Not $dryRun) {
                    Set-Mailbox -Identity $group.id -EmailAddresses @{Add = $newMail}
                    Set-Mailbox -Identity $group.id -EmailAddresses @{Remove = $mail}
                }
                $allChanges += @{
                    Object = "MailboxEmailAddresses"
                    Action = "Changed"
                    Old = $mail
                    New = $newMail
                }
            }
        }
    }
    $allChanges | ConvertTo-Json -Depth 10 | Set-Content -Path "$($AlyaData)\exchange\RemoveDomain\$($domainToRemove)-changesMailboxesChange.json"

    Disconnect-ExchangeOnline
    Disconnect-MgGraph

    Connect-AzAccount -Tenant $AlyaTenantId

    # Changing application uris
    Write-Host "Changing application uris" -ForegroundColor $CommandInfo
    $apps = Get-AzADApplication
    foreach($app in $apps) {
        if ($app.IdentifierUri -like "*$domainToRemove*") {
            Write-Warning "Please change application uri on app '$($app.DisplayName)' - '$($app.AppId)'"
            pause
        }
    }

    Disconnect-AzAccount

    # MSOnline

    # Connect-MsolService
    # Remove-MsolDomain -DomainName $domainToRemove -Force

    Write-Host "Please remove now domain in portal" -ForegroundColor Magenta
    Write-Host "https://admin.microsoft.com/Adminportal/Home?#/Domains"
    Write-Host "`n"
    Write-Host "Issues removing the domain? Check:" -ForegroundColor Magenta
    Write-Host "https://learn.microsoft.com/en-us/microsoft-365/troubleshoot/administration/error-remove-domain-from-office-365"
    Pause

}
catch {
    Write-Error $_.Exception.ToString() -ErrorAction Continue
}

Write-Host "We did following changes:" -ForegroundColor $CommandInfo
$allChanges | Format-List
$allChanges | Format-Table

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBdqZTKkwtGcq7G
# V4jYNGUiaJW2oAjxMdOaSZUrusVfFaCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIOQBRo0zMP8A7kkV
# mEcP9DwyzWZjyG+q3UguiQV0ItdMMA0GCSqGSIb3DQEBAQUABIICABu5kFqr0ikf
# 0Jbq/0tFzS6PCmcKLWVb/2jq08Q/CsO9Oav/LRQUXt0nsSCYXG5IPM/qIHH19/2Q
# nBtH6s4t+D98/rPART2zV55/eKeTn/lyJSj0E6JQmn4hza+p8ULcvgiVgfQwBTCG
# 3XGBjSuSwlI7jcxLZAOHvGBsDzRn1eOlDDx92+V5uWrN3iZ1+/otMm7Kwj87ruof
# NJf9SPI8O74zItsdbLURmCkm+6M016sibAttz3Ho37XcRr+oIjyBmmmOnhb0zERN
# nHHEepaFXDCOtBwBsHklnvGVCiuisGp0H3GpJvIPurBr1TLfGYiEkfx6bVQHsRng
# 10Nk7vAWUT05Moypf3Ddmjlpe5FqUcnM2pLsPD5PG+l0YQiy+mDleb0FN3IydPoG
# sN6/HDsQQ2XrskEwTahzRmrohiKOWI34vtre6A0a0gmAftbfzaV3KiyuwMCgozqR
# Dku7T3xL9nLlCw3TJKoHWR10UWzjb7guMiKSTtF0bg2L/unzqTYdJjFsFO1lHZ6V
# dut1jdd0cG00zq06HVgVRAghNdLd5RTufmguCBFqqHthPg1rkz14FxoXIGnhTOOb
# 4J58XGp8HWZ+4ApQ6GMh5k18X4tJLxLlILLWFFlBRN9Qb8Z2izWyBgQ6Yx+lHGin
# 3gsH/19NAruxAigd3qv0CLG5Uilr45kpoYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCBHH13qkU65EqfyFiF0osHQNunJUvPXFEUMvgEcspxMAgIUBaKDLfl0/CZC
# sv853+bSNpuoAA4YDzIwMjYwMTI0MTIyNzUxWjADAgEBoFikVjBUMQswCQYDVQQG
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
# IFvphTXpEAe1NQPrGgu5CvFafUp9sr50+OezTUSfHWG4MIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAdn4BLjuVuOtq
# 7kuvRudyGTSnKwoo4vLkm35DinJe+1jmScKqP/kZXg5R8wEW69v+dLgIvl/vwPHE
# 9PjUcMRcb0NuyNh8Sk0qqRIBNBXoZQZRnUR9UkHyu4Y2aBg5u56t78y4cHXupVWC
# B8ExgPwHkgJycoNws4imS0ouz8+OuFevmYsIRSrxFkvBK5O08VluTjdL1DnsX+wJ
# JhGWHw5ey9AKoSZ1gAEjB1Oc7ywwX3W7HtWI8Xsi0mrpMaY5K12q+6HkqTWey+/f
# 3ux8sUvAyYiRFmEznp7ZQ3ihwwVQ4PkhJR9a5Lwjmrczj0GzA7CDoCRxhcz1JD73
# 41ZMRqMJrbr0SlBNQ/+sJCcELg/+HmkmsNgIpVBuMSo5yAow+f9IjM3LzR+PY/NN
# qugLqztRLutU70z6bQDqCxNVEuuDTYVHR6zs6QbuQkebpfyBrMK9+PSSpTp3mtZK
# 9e5TF4Of8CPooGWnCx6C3JBR4+1cWmvZyNbxxXiuqNoYICL1kjZY
# SIG # End signature block
