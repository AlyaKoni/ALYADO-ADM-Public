#Requires -Version 7.0

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
    02.12.2020 Konrad Brunner       Initial Version
    11.04.2023 Konrad Brunner       Fully PnP, removed all other modules, PnP has issues with other modules, TODO test with UseAppAuthentication = true
    27.01.2025 Konrad Brunner       New param IncludeOneDriveSites

#>

[CmdletBinding()]
Param(
    [bool]$UseAppAuthentication = $false,
    [bool]$IncludeOneDriveSites = $false
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Export-UsersAccessPerSite-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "PnP.PowerShell"

# =============================================================
# O365 stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "SharePoint | Export-UsersAccessPerSite | O365" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting role groups
$siteCon = LoginTo-PnP -Url $AlyaSharePointUrl
$web = Get-PnPWeb -Connection $siteCon

$spAdminRoleName = "Company Administrator"
try {
    $gauser = $web.EnsureUser($spAdminRoleName)
    $gauser.Context.Load($gauser)
    Invoke-PnPQuery -Connection $siteCon
    $gauserLoginName = $gauser.LoginName
}
catch {
    $spAdminRoleName = "Global Administrator"
    try {
        $gauser = $web.EnsureUser($spAdminRoleName)
        $gauser.Context.Load($gauser)
        Invoke-PnPQuery -Connection $siteCon
        $gauserLoginName = $gauser.LoginName
    }
    catch {
        $gauserLoginName = $null
    }
}

$spAdminRoleName = "SharePoint Service Administrator"
try {
    $sauser = $web.EnsureUser($spAdminRoleName)
    $sauser.Context.Load($sauser)
    Invoke-PnPQuery -Connection $siteCon
    $sauserLoginName = $sauser.LoginName
}
catch {
    $spAdminRoleName = "SharePoint Administrator"
    try {
        $sauser = $web.EnsureUser($spAdminRoleName)
        $sauser.Context.Load($sauser)
        Invoke-PnPQuery -Connection $siteCon
        $sauserLoginName = $sauser.LoginName
    }
    catch {
        $sauserLoginName = $null
    }
}

# Getting site collections
Write-Host "Getting site collections" -ForegroundColor $CommandInfo
if ($UseAppAuthentication)
{
    # Checking app
    if ((-Not $AlyaSharePointAppId) -or (-Not $AlyaSharePointAppCertificate))
    {
        . $AlyaScripts\sharepoint\Configure-ServiceApplication.ps1
    }

    # Checking app certificate
    Write-Host "Checking app certificate" -ForegroundColor $CommandInfo
    $cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Thumbprint -eq $AlyaSharePointAppCertificate }
    if (-Not $cert)
    {
        Write-Warning "Please install the app certificate by running following script in a admin powershell"
        Write-Warning "$PSScriptRoot\Install-ServiceApplicationCertificate.ps1"
        exit
    }

    #TODO login

}
else
{
    $script:adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl
}
if ($IncludeOneDriveSites)
{
    $sitesToProcess = Get-PnPTenantSite -Connection $script:adminCon -Detailed -IncludeOneDriveSites | Where-Object { $_.Url -like "*/sites/*" -or $_.Url -like "*-my.sharepoint.com/personal*" }
}
else
{
    $sitesToProcess = Get-PnPTenantSite -Connection $script:adminCon -Detailed | Where-Object { $_.Url -like "*/sites/*" -or $_.Url -like "*-my.sharepoint.com/personal*" }
}
$allUsers = Get-PnPAzureADUser -Connection $script:adminCon
$allGroups = Get-PnPAzureADGroup -Connection $script:adminCon

# Function definitions
function Process-Member
{
    param(
        $site,
        $web,
        $userOrGroup,
        $rolebindings,
        $access,
        $siteAcc
    )
    if ($access)
    {
        $rolebindings = @((New-Object PSObject -Property @{"Name" = $access}))
    }
    $loginName = Get-PnPProperty -Connection $script:siteCon -ClientObject $userOrGroup -Property "LoginName"
    $principalType = Get-PnPProperty -Connection $script:siteCon -ClientObject $userOrGroup -Property "PrincipalType"
    if ($principalType -eq "SharePointGroup")
    {
        foreach($rolebinding in $rolebindings)
        {
            $obj = New-Object PSObject -Property @{
			    "site" = $site.Url
			    "title" = $site.Title
			    "web" = $web.ServerRelativeUrl
			    "parent" = ""
			    "loginType" = $principalType
			    "loginName" = $loginName
			    "loginDisplayName" = $loginName
			    "access" = $rolebinding.Name
			    "exists" = "Yes"
		    }
            $siteAcc.Add($obj) | Out-Null
		}
        $members = Get-PnPGroupMember -Connection $script:siteCon -Identity $loginName #TODO does this work for sub webs?
        foreach($member in $members)
        {
            if ($gauserLoginName -eq $member.LoginName -or $sauserLoginName -eq $member.LoginName)
            {
                $dispName = "Global Administrator"
                if ($sauserLoginName -eq $member.LoginName) { $dispName = "SharePoint Administrator" }
                foreach($rolebinding in $rolebindings)
                {
                    $obj = New-Object PSObject -Property @{
                        "site" = $site.Url
                        "title" = $site.Title
                        "web" = $web.ServerRelativeUrl
                        "parent" = $loginName
                        "loginType" = "SharePointRoleGroup"
                        "loginName" = $member.LoginName
                        "loginDisplayName" = $dispName
                        "access" = $rolebinding.Name
                        "exists" = "Yes"
                    }
                    $siteAcc.Add($obj) | Out-Null
                }
            }
            else
            {
                if ($member.LoginName -like "*|federateddirectoryclaimprovider|*" -or $member.LoginName -like "*|tenant|*")
                {
                    $oGroupId = $member.LoginName.Substring($member.LoginName.LastIndexOf("|")+1)
                    if ($oGroupId.LastIndexOf("_") -gt -1)
                    {
                        $oGroupId = $oGroupId.Substring(0, $oGroupId.LastIndexOf("_"))
                    }
                    $oGroup = $allGroups | Where-Object { $_.id -eq $oGroupId }
                    if ($oGroup)
                    {
                        $grpType = "AadSecurityGroup"
                        if ($oGroup.GroupTypes -contains "Unified")
                        {
                            $grpType = "AadUnifiedGroup"
                        }
                        $dispName = $oGroup.DisplayName
                        if ($member.LoginName.EndsWith("_o"))
                        {
                            $ogMembers = Get-PnPAzureADGroupOwner -Connection $script:adminCon -Identity $oGroupId
                            $dispName += " Owners"
                        }
                        else
                        {
                            $ogMembers = Get-PnPAzureADGroupMember -Connection $script:adminCon -Identity $oGroupId
                            $dispName += " Members"
                        }
                        foreach($rolebinding in $rolebindings)
                        {
                            $obj = New-Object PSObject -Property @{
                                "site" = $site.Url
                                "title" = $site.Title
                                "web" = $web.ServerRelativeUrl
                                "parent" = $loginName
                                "loginType" = $grpType
                                "loginName" = $member.LoginName
                                "loginDisplayName" = $dispName
                                "access" = $rolebinding.Name
                                "exists" = "Yes"
                            }
                            $siteAcc.Add($obj) | Out-Null
                        }
                        foreach($ogMember in $ogMembers)
                        {
                            $exists = "Yes"
                            $ogUser = $allUsers | Where-Object { $_.Id -eq $ogMember.Id }
                            if (-not $ogUser -and $ogMember.Id -ne "SHAREPOINT\system")
                            {
                                Write-Warning "User $($ogMember.Id) not found [1]"
                                $exists = "No"
                            }
                            $userType = "AadUser"
                            $dispName = $ogUser.Mail
                            if ($ogUser.UserPrincipalName -like "*#EXT#*")
                            {
                                $userType = "AadGuest"
                            }
                            if ([string]::IsNullOrEmpty($dispName))
                            {
                                if ($ogUser.OtherMails -and $ogUser.OtherMails.Count -gt 0)
                                {
                                    $dispName = $ogUser.OtherMails[0]
                                }
                                else
                                {
                                    if ($ogUser.UserPrincipalName -like "*#EXT#*")
                                    {
                                        $dispName = $ogUser.UserPrincipalName
                                        $dispName = $dispName.Substring(0, $dispName.IndexOf("@") - 5)
                                        $dispName = $dispName.Substring(0, $dispName.LastIndexOf("_")) + "@" + $dispName.Substring($dispName.LastIndexOf("_")+1)
                                    }
                                    else
                                    {
                                        $dispName = $ogUser.UserPrincipalName
                                    }
                                }
                            }
                            foreach($rolebinding in $rolebindings)
                            {
                                $obj = New-Object PSObject -Property @{
                                    "site" = $site.Url
                                    "title" = $site.Title
                                    "web" = $web.ServerRelativeUrl
                                    "parent" = $member.LoginName
                                    "loginType" = $userType
                                    "loginName" = $ogUser.UserPrincipalName
                                    "loginDisplayName" = $dispName
                                    "access" = $rolebinding.Name
                                    "exists" = $exists
                                }
                                $siteAcc.Add($obj) | Out-Null
                            }
                        }
                    }
                    else
                    {
                        [regex]$guidRegex = '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$'
                        if ($oGroupId -match $guidRegex)
                        {
                            Write-Warning "Group with id $oGroupId not found [1]"
                        }
                        else
                        {
                            Write-Warning "Group $($member.LoginName) not found [1]"
                        }
                    }
                }
                else
                {
                    $exists = "Yes"
                    $dispName = $member.LoginName
                    if ($dispName.LastIndexOf("|") -gt -1)
                    {
                        $dispName = $dispName.Substring($dispName.LastIndexOf("|")+1)
                    }
                    $ogUser = $allUsers | Where-Object { $_.UserPrincipalName -eq $dispName -or $_.Mail -eq $dispName -or $_.DisplayName -eq $dispName }
                    if (-not $ogUser -and $dispName -ne "SHAREPOINT\system")
                    {
                        Write-Warning "User $($dispName) not found [2]"
                        $exists = "No"
                    }
                    if ($dispName -like "*#EXT#*")
                    {
                        if ($ogUser)
                        {
                            $dispName = $ogUser.Mail
                        }
                    }
                    if ($ogUser -and [string]::IsNullOrEmpty($dispName))
                    {
                        if ($ogUser.OtherMails -and $ogUser.OtherMails.Count -gt 0)
                        {
                            $dispName = $ogUser.OtherMails[0]
                        }
                        else
                        {
                            if ($dispName -like "*#EXT#*")
                            {
                                $dispName = $dispName.Substring(0, $dispName.IndexOf("@") - 5)
                                $dispName = $dispName.Substring(0, $dispName.LastIndexOf("_")) + "@" + $dispName.Substring($dispName.LastIndexOf("_")+1)
                            }
                            else
                            {
                                $dispName = $ogUser.UserPrincipalName
                            }
                        }
                    }
                    foreach($rolebinding in $rolebindings)
                    {
                        $obj = New-Object PSObject -Property @{
                            "site" = $site.Url
                            "title" = $site.Title
                            "web" = $web.ServerRelativeUrl
                            "parent" = $loginName
                            "loginType" = "User"
                            "loginName" = $member.LoginName
                            "loginDisplayName" = $dispName
                            "access" = $rolebinding.Name
                            "exists" = $exists
                        }
                        $siteAcc.Add($obj) | Out-Null
                    }
                }
            }
		}
    }
    else
    {
        if ($loginName -like "*|federateddirectoryclaimprovider|*" -or $loginName -like "*|tenant|*")
        {
            if ($principalType -eq "User")
            {
                $oUserId = $loginName.Substring($loginName.LastIndexOf("|")+1)
                if ($oUserId.LastIndexOf("_") -gt -1)
                {
                    $oUserId = $oUserId.Substring(0, $oUserId.LastIndexOf("_"))
                }
                $ogUser = $allUsers | Where-Object { $_.Id -eq $oUserId }
                $exists = "Yes"
                if (-Not $oUser)
                {
                    Write-Warning "AzureAD user with id $oUserId not found [3]"
                    $exists = "No"
                }
                foreach($rolebinding in $rolebindings)
                {
                    $obj = New-Object PSObject -Property @{
                        "site" = $site.Url
                        "title" = $site.Title
                        "web" = $web.ServerRelativeUrl
                        "parent" = ""
                        "loginType" = "AadUser"
                        "loginName" = $loginName
                        "loginDisplayName" = ($oUser.UserPrincipalName ? $oUser.UserPrincipalName : "")
                        "access" = $rolebinding.Name
                        "exists" = $exists
                    }
                    $siteAcc.Add($obj) | Out-Null
                }
            }
            else
            {
                if ($gauserLoginName -eq $loginName -or $sauserLoginName -eq $loginName)
                {
                    $dispName = "Global Administrator"
                    if ($sauserLoginName -eq $loginName) { $dispName = "SharePoint Administrator" }
                    foreach($rolebinding in $rolebindings)
                    {
                        $obj = New-Object PSObject -Property @{
                            "site" = $site.Url
                            "title" = $site.Title
                            "web" = $web.ServerRelativeUrl
                            "parent" = $loginName
                            "loginType" = "SharePointRoleGroup"
                            "loginName" = $member.LoginName
                            "loginDisplayName" = $dispName
                            "access" = $rolebinding.Name
                            "exists" = "Yes"
                        }
                        $siteAcc.Add($obj) | Out-Null
                    }
                }
                else
                {
                    $oGroupId = $loginName.Substring($loginName.LastIndexOf("|")+1)
                    if ($oGroupId.LastIndexOf("_") -gt -1)
                    {
                        $oGroupId = $oGroupId.Substring(0, $oGroupId.LastIndexOf("_"))
                    }
                    $oGroup = $allGroups | Where-Object { $_.id -eq $oGroupId }
                    if ($oGroup)
                    {
                        $grpType = "Security"
                        if ($oGroup.GroupTypes -contains "Unified")
                        {
                            $grpType = "Office365Group"
                        }
                        $dispName = $oGroup.DisplayName
                        if ($loginName.EndsWith("_o"))
                        {
                            $ogMembers = Get-PnPAzureADGroupOwner -Connection $script:adminCon -Identity $oGroupId
                            $dispName += " Owners"
                        }
                        else
                        {
                            $ogMembers = Get-PnPAzureADGroupMember -Connection $script:adminCon -Identity $oGroupId
                            $dispName += " Members"
                        }
                        foreach($rolebinding in $rolebindings)
                        {
                            $obj = New-Object PSObject -Property @{
                                "site" = $site.Url
                                "title" = $site.Title
                                "web" = $web.ServerRelativeUrl
                                "parent" = ""
                                "loginType" = $grpType
                                "loginName" = $loginName
                                "loginDisplayName" = $dispName
                                "access" = $rolebinding.Name
                                "exists" = "Yes"
                            }
                            $siteAcc.Add($obj) | Out-Null
                        }
                        foreach($ogMember in $ogMembers)
                        {
                            $exists = "Yes"
                            $ogUser = $allUsers | Where-Object { $_.Id -eq $ogMember.Id }
                            if (-not $ogUser -and $ogMember.Id -ne "SHAREPOINT\system")
                            {
                                Write-Warning "User $($ogMember.Id) not found [4]"
                                $exists = "No"
                            }
                            $userType = "AadUser"
                            if ($loginName -like "*#EXT#*")
                            {
                                $userType = "AadGuest"
                            }
                            $dispName = $ogUser.Mail
                            if ([string]::IsNullOrEmpty($dispName))
                            {
                                if ($ogUser.OtherMails -and $ogUser.OtherMails.Count -gt 0)
                                {
                                    $dispName = $ogUser.OtherMails[0]
                                }
                                else
                                {
                                    if ($ogUser.UserPrincipalName -like "*#EXT#*")
                                    {
                                        $dispName = $ogUser.UserPrincipalName
                                        $dispName = $dispName.Substring(0, $dispName.IndexOf("@") - 5)
                                        $dispName = $dispName.Substring(0, $dispName.LastIndexOf("_")) + "@" + $dispName.Substring($dispName.LastIndexOf("_")+1)
                                    }
                                    else
                                    {
                                        $dispName = $ogUser.UserPrincipalName
                                    }
                                }
                            }
                            foreach($rolebinding in $rolebindings)
                            {
                                $obj = New-Object PSObject -Property @{
                                    "site" = $site.Url
                                    "title" = $site.Title
                                    "web" = $web.ServerRelativeUrl
                                    "parent" = $loginName
                                    "loginType" = $userType
                                    "loginName" = $ogUser.UserPrincipalName
                                    "loginDisplayName" = $dispName
                                    "access" = $rolebinding.Name
                                    "exists" = $exists
                                }
                                $siteAcc.Add($obj) | Out-Null
                            }
                        }
                    }
                    else
                    {
                        [regex]$guidRegex = '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$'
                        if ($oGroupId -match $guidRegex)
                        {
                            Write-Warning "Group with id $oGroupId not found [4]"
                        }
                        else
                        {
                            Write-Warning "Group $loginName not found [4]"
                        }
                    }
                }
            }
        }
        else
        {
            $exists = "Yes"
            $dispName = $loginName
            if ($dispName.LastIndexOf("|") -gt -1)
            {
                $dispName = $dispName.Substring($dispName.LastIndexOf("|")+1)
            }
            $ogUser = $allUsers | Where-Object { $_.UserPrincipalName -eq $dispName -or $_.Mail -eq $dispName -or $_.DisplayName -eq $dispName }
            if (-not $ogUser -and $dispName -ne "SHAREPOINT\system")
            {
                Write-Warning "User $($dispName) not found [5]"
                $exists = "No"
            }
            if ($dispName -like "*#EXT#*")
            {
                if ($ogUser)
                {
                    $dispName = $ogUser.Mail
                }
            }
            if ($ogUser -and [string]::IsNullOrEmpty($dispName))
            {
                if ($ogUser.OtherMails -and $ogUser.OtherMails.Count -gt 0)
                {
                    $dispName = $ogUser.OtherMails[0]
                }
                else
                {
                    if ($ogUser.UserPrincipalName -like "*#EXT#*")
                    {
                        $dispName = $ogUser.UserPrincipalName
                        $dispName = $dispName.Substring(0, $dispName.IndexOf("@") - 5)
                        $dispName = $dispName.Substring(0, $dispName.LastIndexOf("_")) + "@" + $dispName.Substring($dispName.LastIndexOf("_")+1)
                    }
                    else
                    {
                        $dispName = $ogUser.UserPrincipalName
                    }
                }
            }
            foreach($rolebinding in $rolebindings)
            {
                $obj = New-Object PSObject -Property @{
                    "site" = $site.Url
                    "title" = $site.Title
			        "web" = $web.ServerRelativeUrl
			        "parent" = ""
			        "loginType" = $principalType
			        "loginName" = $loginName
			        "loginDisplayName" = $dispName
			        "access" = $rolebinding.Name
                    "exists" = $exists
		        }
                $siteAcc.Add($obj) | Out-Null
		    }
		}
    }
}
function Get-WebAccess
{
    param(
        $site,
        $web
    )
    Write-Host "Web $($web.ServerRelativeUrl)"
    $siteAcc = New-Object System.Collections.ArrayList
    $roleAssignments = Get-PnPProperty -Connection $script:siteCon -ClientObject $web -Property "RoleAssignments"
    foreach($ra in $roleAssignments)
    {
        $rolebindings = Get-PnPProperty -Connection $script:siteCon -ClientObject $ra -Property "RoleDefinitionBindings"
        Process-Member -site $site -web $web -userOrGroup $ra.Member -rolebindings $rolebindings -siteAcc $siteAcc
    }

    $subWebs = Get-PnPSubWeb -Recurse -Connection $script:siteCon
    foreach($sWeb in $subWebs)
    {
        #TODO required? $script:siteCon = LoginTo-PnP -Url $siteUrl
        $subSiteAcc = Get-WebAccess -site $site -web $sWeb
        if ($subSiteAcc -and $subSiteAcc.Count -gt 0)
        {
            $siteAcc.AddRange($subSiteAcc)
        }
    }

    return $siteAcc
}

# Getting site access
Write-Host "Getting site access" -ForegroundColor $CommandInfo
$allSiteAcc = New-Object System.Collections.ArrayList
foreach($site in $sitesToProcess)
{
    $siteUrl = $site.Url
    Write-Host "Site $siteUrl"
    if ($site.Template -like "REDIRECTSITE*") 
    { 
        Write-Host "  Ignored: REDIRECTSITE"
        continue 
    }
    if ($script:adminCon)
    {
        Set-PnPTenantSite -Connection $script:adminCon -Identity $site.Url -Owners $AlyaSharePointNewSiteCollectionAdmins
    }

    $retries = 10
    do
    {
        try
        {
            if ($UseAppAuthentication)
            {
                $script:siteCon = LoginTo-PnP -Url $siteUrl -ClientId $AlyaSharePointAppId -Thumbprint $AlyaSharePointAppCertificate
            }
            else
            {
                $script:siteCon = LoginTo-PnP -Url $siteUrl
            }
            $web = Get-PnPWeb -Connection $script:siteCon
            $admins = Get-PnPSiteCollectionAdmin -Connection $script:siteCon
            foreach($admin in $admins)
            {
                Process-Member -site $site -web $web -userOrGroup $admin -access "SiteColAdmin" -siteAcc $allSiteAcc
            }
            $siteAcc = Get-WebAccess -site $site -web $web
            if ($siteAcc -and $siteAcc.Count -gt 0)
            {
                $allSiteAcc.AddRange(@($siteAcc))
            }
            break
        }
        catch
        {
            Write-Error $_.Exception -ErrorAction Continue
            Write-Warning "Retrying $retries times"
            Start-Sleep -Seconds 15
            $retries--
            if ($retries -lt 0) { throw }
        }
    } while ($true)

}

$allSiteAcc | ConvertTo-Csv -NoTypeInformation | Set-Content -Path "$AlyaData\sharepoint\UsersPerSites.csv" -Encoding $AlyaUtf8Encoding -Force
Write-Host "Report expoted to $AlyaData\sharepoint\UsersPerSites.csv"

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAr3RAhKsyiLQ6M
# tqL12mcafvf3+scZTrsZV3/XT11mmKCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDCjuDGjuxOV7dX3H
# 9DANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjEzMTYxODAwWhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAqrm7S5R5kmdYT3Q2wIa1m1BQW5EfmzvCg+WYiBY94XQTAxEACqVq
# 4+3K/ahp+8c7stNOJDZzQyLLcZvtLpLmkj4ZqwgwtoBrKBk3ofkEMD/f46P2Iuky
# tvmyUxdM4730Vs6mRvQP+Y6CfsUrWQDgJkiGTldCSH25D3d2eO6PeSdYTA3E3kMH
# BiFI3zxgCq3ZgbdcIn1bUz7wnzxjuAqI7aJ/dIBKDmaNR0+iIhrCFvhDo6nZ2Iwj
# 1vAQsSHlHc6SwEvWfNX+Adad3cSiWfj0Bo0GPUKHRayf2pkbOW922shL1yf/30OV
# yct8rPkMrIKzQhog2R9qJrKJ2xUWwEwiSblWX4DRpdxOROS5PcQB45AHhviDcudo
# 30gx8pjwTeCVKkG2XgdqEZoxdAa4ospWn3va+Dn6OumYkUQZ1EkVhDfdsbCXAJvY
# NCbOyx5tPzeZEFP19N5edi6MON9MC/5tZjpcLzsQUgIbHqFfZiQTposx/j+7m9WS
# aK0cDBfYKFOVQJF576yeWaAjMul4gEkXBn6meYNiV/iL8pVcRe+U5cidmgdUVveo
# BPexERaIMz/dIZIqVdLBCgBXcHHoQsPgBq975k8fOLwTQP9NeLVKtPgftnoAWlVn
# 8dIRGdCcOY4eQm7G4b+lSili6HbU+sir3M8pnQa782KRZsf6UruQpqsCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBT5XqSepeGcYSU4OKwKELHy/3vCoTANBgkq
# hkiG9w0BAQsFAAOCAgEAlSgt2/t+Z6P9OglTt1+sobomrQT0Mb97lGDQZpE364hO
# TSYkbcqxlRXZ+aINgt2WEe7GPFu+6YoZimCPV4sOfk5NZ6I3ZU+uoTsoVYpQr3Io
# zYLLNMWEK2WswPHcxx34Il6F59V/wP1RdB73g+4ZprkzsYNqQpXMv3yoDsPU9IHP
# /w3jQRx6Maqlrjn4OCaE3f6XVxDRHv/iFnipQfXUqY2dV9gkoiYL3/dQX6ibUXqj
# Xk6trvZBQr20M+fhhFPYkxfLqu1WdK5UGbkg1MHeWyVBP56cnN6IobNpHbGY6Eg0
# RevcNGiYFZsE9csZPp855t8PVX1YPewvDq2v20wcyxmPcqStJYLzeirMJk0b9UF2
# hHmIMQRuG/pjn2U5xYNp0Ue0DmCI66irK7LXvziQjFUSa1wdi8RYIXnAmrVkGZj2
# a6/Th1Z4RYEIn1Pc/F4yV9OJAPYN1Mu1LuRiaHDdE77MdhhNW2dniOmj3+nmvWbZ
# fNAI17VybYom4MNB1Cy2gm2615iuO4G6S6kdg8fTaABRh78i8DIgT6LL/yMvbDOH
# hREfFUfowgkx9clsBF1dlAG357pYgAsbS/hqTS0K2jzv38VbhMVuWgtHdwO39ACa
# udnXvAKG9w50/N0DgI54YH/HKWxVyYIltzixRLXN1l+O5MCoXhofW4QhtrofETAx
# ghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEICNf6W08rhg8XLpo
# ud5VPtUnQ6szFLdWf/+R3iUkIo5yMA0GCSqGSIb3DQEBAQUABIICAKdtHnHykHf+
# uIQUFND+f1jDOv62+SNBZTihyVd5KhkRbD9PkvELJROFGPjKQ98wX+rbm4eWsv5R
# FFN/ogIKLj7icpkbAv++ToyRJZUb8ikD/ta4Kj5ypuDc1yC4rqVVbsgAJviSu+Op
# Vu/8qqD+W3sRGALkdssaXHKoxP38K+VbWt/zoudz6F3nsxsKaPi3bMJXRpUmhdWs
# i7bR4WckMhf0exBubOG5Bl1s2XQ5KEK0PdyZUulhS8OjSUCmaL+HncdivccO0e4b
# v5tkFPo1ZioX9mPvZw8eW7v3R2s0OA3FTsQWzgRgVq0trpb4wjICaPR0vQMW0EVZ
# kwlTW72YF7qqYsoQcVKYHd370AkjKd2OMf3h2KoqRFs8BulZierkRkSFmZb0kVNl
# wlw8Vyd8yefaF1fXpr1hEuDLruXOWsJzAowWZLLQeXrdz/ytzToDjP5oW2m1KkS1
# nsExfObyH70HZVXej0VcVCtrTx45wIQGDZ7mWH16bUZwRdlzi24Q0DxJk0MWDZGv
# U/2/tVtwP74i1qiFJT0XGh9NXJM6TP63Fqo1YS7G03+3C9j/bBu1z9z1gv8+Txr1
# A/3U0hMHhs3m7djFSXFBzXa2w9KsHWW3GMpSiu9x9ppMhEsv8wzkxEzyzwGr7AC7
# iGi5hfvl/hsKDu4wnunr2TOVmcHxCzBMoYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCAzxwirl/Nfz6XoLjaz8Jd9+D6v56+//eiUMs9xSqvA1QIUEwbigC2uFAxZ
# zkv1SBiEIgxtaPwYDzIwMjYwMTIwMTAwNTE3WjADAgEBoFikVjBUMQswCQYDVQQG
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
# IIS/ES3jXIMqZMg6J0i1uY8xgVr7vMTrsadVy2pJ2m0uMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAGvmgONHLEt9n
# BVzpILi4/scMPsiYyE0dLlbkUXhVkCW6IPLgAWiljk4ECWnkgFihAdwgY084rcZa
# GxF21vEB7Vrsa+tRPZZZkB/mwVfEsyr5ZUF2uC97Sl6O5TDu50wP6EfqgrBvRMml
# e2F20nuDfKOSsYEK6rcyXz9R3w5B4jWN6C/5WQCFfDi7JqJHVoq09rJDEZMg2E1b
# 5Quji+1d7u74VrggslwntmGpW/+Tlu/cdAVuLaH1+AKAQ+oTl0jd6bvPyiYtmvSK
# V3EPZfvyZAtVDHUfX2G+gw26lRr1/ERvk+P3mRo/PLvL5VU1BqbfqrZJKCI7fOWS
# WGouWyAIkQ6Sb9oXDGkvQZzltX7bTgk8bkc2L1RItWYPlTQSTl/NH2GsLBM0Bgqk
# Ji1uv47kAhlQ+Ax/pLLsP7pE0LZ9WA1rlsq1bHRIdnv6CcIIrFz1uqMTYsrBHbMp
# AQ+FMoIkhs6M5LdDJYM9mUxUS/rl283XrutTzmVGv3/vWLPZV4Xw
# SIG # End signature block
