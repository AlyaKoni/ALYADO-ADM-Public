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
    18.10.2021 Konrad Brunner       Initial Creation
    14.11.2023 Konrad Brunner       New naming option

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\exchange\Create-DefaultDistributionGroups-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Exchange stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "EXCHANGE | Create-DefaultDistributionGroups | EXCHANGE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}
$ownerEmail = $Context.Account.Id

try
{
    LoginTo-EXO

    $newNamingPart = ""
    if ($AlyaGeneralInformEmail.StartsWith("cloud."))
    {
        $newNamingPart = " Cloud"
    }
    
    # Privacy
    Write-Host "Checking distribution group Privacy" -ForegroundColor $CommandInfo
    $grpAlias = $AlyaPrivacyEmail.Replace("@$AlyaDomainName", "")
    if ($AlyaPrivacyEmail -like "*@$AlyaDomainName")
    {
        $dGrp = Get-DistributionGroup -Identity "$($AlyaCompanyName)$($newNamingPart) Privacy" -ErrorAction SilentlyContinue
        if (-Not $dGrp)
        {
            Write-Warning "  Distribution group Privacy does not exist. Creating it now"
            $dGrp = New-DistributionGroup -Name "$($AlyaCompanyName)$($newNamingPart) Privacy" -Alias $grpAlias -PrimarySmtpAddress $AlyaPrivacyEmail -MemberJoinRestriction Closed -MemberDepartRestriction Closed -RequireSenderAuthenticationEnabled $false
        }
        $dGrp | Set-DistributionGroup -Alias $grpAlias -PrimarySmtpAddress $AlyaPrivacyEmail -MemberJoinRestriction Closed -MemberDepartRestriction Closed -RequireSenderAuthenticationEnabled $false
    }
    Write-Host "  checking members"
    $retries = 5
    do {
        try {
            $retries--
            $membs = Get-DistributionGroupMember -Identity "$($AlyaCompanyName)$($newNamingPart) Privacy"
            break
        } catch {
            Start-Sleep -Seconds 4
        }
    } while ($retries -gt 0)
    if ($retries -eq 0)
    {
        Write-Error "Error checking member" -ErrorAction Continue
    }
    $memb = $membs | Where-Object { $_.PrimarySmtpAddress -eq $ownerEmail -or $_.WindowsLiveID -eq $ownerEmail }
    if (-Not $memb)
    {
        Write-Host "  adding member $ownerEmail"
        $retries = 5
        do {
            try {
                $retries--
                $memb = Add-DistributionGroupMember -Identity "$($AlyaCompanyName)$($newNamingPart) Privacy" -Member $ownerEmail
                break
            } catch {
                Start-Sleep -Seconds 4
            }
        } while ($retries -gt 0)
        if ($retries -eq 0)
        {
            Write-Error "Error adding member" -ErrorAction Continue
        }
    }

    # Security
    Write-Host "Checking distribution group Security" -ForegroundColor $CommandInfo
    $grpAlias = $AlyaSecurityEmail.Replace("@$AlyaDomainName", "")
    if ($AlyaSecurityEmail -like "*@$AlyaDomainName")
    {
        $dGrp = Get-DistributionGroup -Identity "$($AlyaCompanyName)$($newNamingPart) Security" -ErrorAction SilentlyContinue
        if (-Not $dGrp)
        {
            Write-Warning "  Distribution group Security does not exist. Creating it now"
            $dGrp = New-DistributionGroup -Name "$($AlyaCompanyName)$($newNamingPart) Security" -Alias $grpAlias -PrimarySmtpAddress $AlyaSecurityEmail -MemberJoinRestriction Closed -MemberDepartRestriction Closed -RequireSenderAuthenticationEnabled $false
        }
        $dGrp | Set-DistributionGroup -MemberJoinRestriction Closed -MemberDepartRestriction Closed -RequireSenderAuthenticationEnabled $false
    }
    Write-Host "  checking members"
    $retries = 5
    do {
        try {
            $retries--
            $membs = Get-DistributionGroupMember -Identity "$($AlyaCompanyName)$($newNamingPart) Security"
            break
        } catch {
            Start-Sleep -Seconds 4
        }
    } while ($retries -gt 0)
    if ($retries -eq 0)
    {
        Write-Error "Error checking member" -ErrorAction Continue
    }
    $memb = $membs | Where-Object { $_.PrimarySmtpAddress -eq $ownerEmail -or $_.WindowsLiveID -eq $ownerEmail }
    if (-Not $memb)
    {
        Write-Host "  adding member $ownerEmail"
        $retries = 5
        do {
            try {
                $retries--
                $memb = Add-DistributionGroupMember -Identity "$($AlyaCompanyName)$($newNamingPart) Security" -Member $ownerEmail
                break
            } catch {
                Start-Sleep -Seconds 4
            }
        } while ($retries -gt 0)
        if ($retries -eq 0)
        {
            Write-Error "Error adding member" -ErrorAction Continue
        }
    }

    # GeneralInform
    Write-Host "Checking distribution group GeneralInform" -ForegroundColor $CommandInfo
    $grpAlias = $AlyaGeneralInformEmail.Replace("@$AlyaDomainName", "")
    $newNamingSuffix = ""
    if ($AlyaGeneralInformEmail.StartsWith("cloud."))
    {
        $newNamingSuffix = " General"
    }
    if ($AlyaGeneralInformEmail -like "*@$AlyaDomainName")
    {
        $dGrp = Get-DistributionGroup -Identity "$($AlyaCompanyName) Cloud$($newNamingSuffix)" -ErrorAction SilentlyContinue
        if (-Not $dGrp)
        {
            Write-Warning "  Distribution group GeneralInform does not exist. Creating it now"
            $dGrp = New-DistributionGroup -Name "$($AlyaCompanyName) Cloud$($newNamingSuffix)" -Alias $grpAlias -PrimarySmtpAddress $AlyaGeneralInformEmail -MemberJoinRestriction Closed -MemberDepartRestriction Closed -RequireSenderAuthenticationEnabled $false
        }
        $dGrp | Set-DistributionGroup -MemberJoinRestriction Closed -MemberDepartRestriction Closed -RequireSenderAuthenticationEnabled $false
    }
    Write-Host "  checking members"
    $retries = 5
    do {
        try {
            $retries--
            $membs = Get-DistributionGroupMember -Identity "$($AlyaCompanyName) Cloud$($newNamingSuffix)"
            Get-DistributionGroupMember -Identity $dGrp.Id
            break
        } catch {
            Start-Sleep -Seconds 4
        }
    } while ($retries -gt 0)
    if ($retries -eq 0)
    {
        Write-Error "Error checking member" -ErrorAction Continue
    }
    $memb = $membs | Where-Object { $_.PrimarySmtpAddress -eq $ownerEmail -or $_.WindowsLiveID -eq $ownerEmail }
    if (-Not $memb)
    {
        Write-Host "  adding member $ownerEmail"
        $retries = 5
        do {
            try {
                $retries--
                $memb = Add-DistributionGroupMember -Identity "$($AlyaCompanyName)$($newNamingPart) Cloud" -Member $ownerEmail
                break
            } catch {
                Start-Sleep -Seconds 4
            }
        } while ($retries -gt 0)
        if ($retries -eq 0)
        {
            Write-Error "Error adding member" -ErrorAction Continue
        }
    }

    # Support
    Write-Host "Checking distribution group Support" -ForegroundColor $CommandInfo
    $grpAlias = $AlyaSupportEmail.Replace("@$AlyaDomainName", "")
    if ($AlyaSupportEmail -like "*@$AlyaDomainName")
    {
        $dGrp = Get-DistributionGroup -Identity "$($AlyaCompanyName)$($newNamingPart) Support" -ErrorAction SilentlyContinue
        if (-Not $dGrp)
        {
            Write-Warning "  Distribution group Support does not exist. Creating it now"
            $dGrp = New-DistributionGroup -Name "$($AlyaCompanyName)$($newNamingPart) Support" -Alias $grpAlias -PrimarySmtpAddress $AlyaSupportEmail -MemberJoinRestriction Closed -MemberDepartRestriction Closed -RequireSenderAuthenticationEnabled $false
        }
        $dGrp | Set-DistributionGroup -MemberJoinRestriction Closed -MemberDepartRestriction Closed -RequireSenderAuthenticationEnabled $false
    }
    Write-Host "  checking members"
    $retries = 5
    do {
        try {
            $retries--
            $membs = Get-DistributionGroupMember -Identity "$($AlyaCompanyName)$($newNamingPart) Support"
            break
        } catch {
            Start-Sleep -Seconds 4
        }
    } while ($retries -gt 0)
    if ($retries -eq 0)
    {
        Write-Error "Error checking member" -ErrorAction Continue
    }
    $memb = $membs | Where-Object { $_.PrimarySmtpAddress -eq $ownerEmail -or $_.WindowsLiveID -eq $ownerEmail }
    if (-Not $memb)
    {
        Write-Host "  adding member $ownerEmail"
        $retries = 5
        do {
            try {
                $retries--
                $memb = Add-DistributionGroupMember -Identity "$($AlyaCompanyName)$($newNamingPart) Support" -Member $ownerEmail
                break
            } catch {
                Start-Sleep -Seconds 4
            }
        } while ($retries -gt 0)
        if ($retries -eq 0)
        {
            Write-Error "Error adding member" -ErrorAction Continue
        }
    }

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

#Stopping Transscript
Stop-Transcript
