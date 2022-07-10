#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2021

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
    18.10.2021 Konrad Brunner       Initial Creation

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
Install-ModuleIfNotInstalled "Az"

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
    
    # Privacy
    Write-Host "Checking distribution group Privacy" -ForegroundColor $CommandInfo
    if ($AlyaPrivacyEmail -like "*@$AlyaDomainName")
    {
        $dGrp = Get-DistributionGroup -Identity "$AlyaCompanyName Privacy" -ErrorAction SilentlyContinue
        if (-Not $dGrp)
        {
            $grpAlias = $AlyaPrivacyEmail.Replace("@$AlyaDomainName", "")
            Write-Warning "  Distribution group Privacy does not exist. Creating it now"
            $dGrp = New-DistributionGroup -Name "$AlyaCompanyName Privacy" -Alias $grpAlias -PrimarySmtpAddress $AlyaPrivacyEmail -MemberJoinRestriction Closed -MemberDepartRestriction Closed -RequireSenderAuthenticationEnabled $false
        }
    }
    $dGrp | Set-DistributionGroup -Alias $grpAlias -PrimarySmtpAddress $AlyaPrivacyEmail -MemberJoinRestriction Closed -MemberDepartRestriction Closed -RequireSenderAuthenticationEnabled $false
    Write-Host "  checking members"
    $membs = Get-DistributionGroupMember -Identity "$AlyaCompanyName Privacy"
    $memb = $membs | where { $_.PrimarySmtpAddress -eq $ownerEmail }
    if (-Not $memb)
    {
        Write-Host "  adding member $ownerEmail"
        $memb = Add-DistributionGroupMember -Identity "$AlyaCompanyName Privacy" -Member $ownerEmail
    }

    # Security
    Write-Host "Checking distribution group Security" -ForegroundColor $CommandInfo
    if ($AlyaSecurityEmail -like "*@$AlyaDomainName")
    {
        $dGrp = Get-DistributionGroup -Identity "$AlyaCompanyName Security" -ErrorAction SilentlyContinue
        if (-Not $dGrp)
        {
            $grpAlias = $AlyaSecurityEmail.Replace("@$AlyaDomainName", "")
            Write-Warning "  Distribution group Security does not exist. Creating it now"
            $dGrp = New-DistributionGroup -Name "$AlyaCompanyName Security" -Alias $grpAlias -PrimarySmtpAddress $AlyaSecurityEmail -MemberJoinRestriction Closed -MemberDepartRestriction Closed -RequireSenderAuthenticationEnabled $false
        }
    }
    $dGrp | Set-DistributionGroup -MemberJoinRestriction Closed -MemberDepartRestriction Closed -RequireSenderAuthenticationEnabled $false
    Write-Host "  checking members"
    $membs = Get-DistributionGroupMember -Identity "$AlyaCompanyName Security"
    $memb = $membs | where { $_.PrimarySmtpAddress -eq $ownerEmail }
    if (-Not $memb)
    {
        Write-Host "  adding member $ownerEmail"
        $memb = Add-DistributionGroupMember -Identity "$AlyaCompanyName Security" -Member $ownerEmail
    }

    # GeneralInform
    Write-Host "Checking distribution group GeneralInform" -ForegroundColor $CommandInfo
    if ($AlyaGeneralInformEmail -like "*@$AlyaDomainName")
    {
        $dGrp = Get-DistributionGroup -Identity "$AlyaCompanyName Cloud" -ErrorAction SilentlyContinue
        if (-Not $dGrp)
        {
            $grpAlias = $AlyaGeneralInformEmail.Replace("@$AlyaDomainName", "")
            Write-Warning "  Distribution group GeneralInform does not exist. Creating it now"
            $dGrp = New-DistributionGroup -Name "$AlyaCompanyName Cloud" -Alias $grpAlias -PrimarySmtpAddress $AlyaGeneralInformEmail -MemberJoinRestriction Closed -MemberDepartRestriction Closed -RequireSenderAuthenticationEnabled $false
        }
    }
    $dGrp | Set-DistributionGroup -MemberJoinRestriction Closed -MemberDepartRestriction Closed -RequireSenderAuthenticationEnabled $false
    Write-Host "  checking members"
    $membs = Get-DistributionGroupMember -Identity "$AlyaCompanyName Cloud"
    $memb = $membs | where { $_.PrimarySmtpAddress -eq $ownerEmail }
    if (-Not $memb)
    {
        Write-Host "  adding member $ownerEmail"
        $memb = Add-DistributionGroupMember -Identity "$AlyaCompanyName Cloud" -Member $ownerEmail
    }

    # Support
    Write-Host "Checking distribution group Support" -ForegroundColor $CommandInfo
    if ($AlyaSupportEmail -like "*@$AlyaDomainName")
    {
        $dGrp = Get-DistributionGroup -Identity "$AlyaCompanyName Support" -ErrorAction SilentlyContinue
        if (-Not $dGrp)
        {
            $grpAlias = $AlyaSupportEmail.Replace("@$AlyaDomainName", "")
            Write-Warning "  Distribution group Support does not exist. Creating it now"
            $dGrp = New-DistributionGroup -Name "$AlyaCompanyName Support" -Alias $grpAlias -PrimarySmtpAddress $AlyaSupportEmail -MemberJoinRestriction Closed -MemberDepartRestriction Closed -RequireSenderAuthenticationEnabled $false
        }
    }
    $dGrp | Set-DistributionGroup -MemberJoinRestriction Closed -MemberDepartRestriction Closed -RequireSenderAuthenticationEnabled $false
    Write-Host "  checking members"
    $membs = Get-DistributionGroupMember -Identity "$AlyaCompanyName Support"
    $memb = $membs | where { $_.PrimarySmtpAddress -eq $ownerEmail }
    if (-Not $memb)
    {
        Write-Host "  adding member $ownerEmail"
        $memb = Add-DistributionGroupMember -Identity "$AlyaCompanyName Support" -Member $ownerEmail
    }

}
catch
{
    try { Write-Error ($_.Exception | ConvertTo-Json -Depth 3) -ErrorAction Continue } catch {}
	Write-Error ($_.Exception) -ErrorAction Continue
}
finally
{
    DisconnectFrom-EXOandIPPS
}

#Stopping Transscript
Stop-Transcript
