#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2020-2021

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
    02.12.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Export-UsersAccessPerSite-$($AlyaTimeString).log" | Out-Null

# Checking modules
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "AzureAdPreview"
Install-ModuleIfNotInstalled "PnP.PowerShell"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad

# Getting app information
Write-Host "Getting SharePoint app information" -ForegroundColor $CommandInfo
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
    throw "App certificate not found"
}

#Login to Az
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Getting site collections
Write-Host "Getting site collections" -ForegroundColor $CommandInfo
$retries = 10
do
{
    try
    {
        $adminCon = LoginTo-PnP -Url $AlyaSharePointAdminUrl -ClientId $AlyaSharePointAppId -Thumbprint $AlyaSharePointAppCertificate
        $sitesToProcess = Get-PnPTenantSite -Detailed -IncludeOneDriveSites | where { $_.Url -like "*/sites/*" -or $_.Url -like "*-my.sharepoint.com/personal*" }
        try { $AlyaConnection = Disconnect-PnPOnline } catch {}
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

# Function definitions
function Process-Member
{
    param(
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
    $loginName = Get-PnPProperty -ClientObject $userOrGroup -Property "LoginName"
    $principalType = Get-PnPProperty -ClientObject $userOrGroup -Property "PrincipalType"
    if ($principalType -eq "SharePointGroup")
    {
        foreach($rolebinding in $rolebindings)
        {
            $obj = New-Object PSObject -Property @{
			    "web" = $web.ServerRelativeUrl
			    "parent" = ""
			    "loginType" = $principalType
			    "loginName" = $loginName
			    "loginDisplayName" = $loginName
			    "access" = $rolebinding.Name
		    }
            $siteAcc.Add($obj) | Out-Null
		}
        $members = Get-PnPGroupMembers -Web $web -Identity $loginName
        foreach($member in $members)
        {
            if ($member.LoginName -like "*|federateddirectoryclaimprovider|*" -or $member.LoginName -like "*|tenant|*")
            {
                $oGroupId = $member.LoginName.Substring($member.LoginName.LastIndexOf("|")+1)
                if ($oGroupId.LastIndexOf("_") -gt -1)
                {
                    $oGroupId = $oGroupId.Substring(0, $oGroupId.LastIndexOf("_"))
                }
                $oGroup = $null
                try { $oGroup = Get-AzureADMSGroup -Id $oGroupId -ErrorAction SilentlyContinue } catch {}
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
                        $ogMembers = Get-AzureADGroupOwner -ObjectId $oGroupId
                        $dispName += " Owners"
                    }
                    else
                    {
                        $ogMembers = Get-AzureADGroupMember -ObjectId $oGroupId
                        $dispName += " Members"
                    }
                    foreach($rolebinding in $rolebindings)
                    {
                        $obj = New-Object PSObject -Property @{
			                "web" = $web.ServerRelativeUrl
			                "parent" = $loginName
			                "loginType" = $grpType
			                "loginName" = $member.LoginName
			                "loginDisplayName" = $dispName
			                "access" = $rolebinding.Name
		                }
                        $siteAcc.Add($obj) | Out-Null
                    }
                    foreach($ogMember in $ogMembers)
                    {
                        $ogUser = Get-AzureADUser -ObjectId $ogMember.ObjectId
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
			                    "web" = $web.ServerRelativeUrl
			                    "parent" = $member.LoginName
			                    "loginType" = $userType
			                    "loginName" = $ogUser.UserPrincipalName
			                    "loginDisplayName" = $dispName
			                    "access" = $rolebinding.Name
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
                        Write-Warning "Group with id $oGroupId not found"
                    }
                }
            }
            else
            {
                $dispName = $member.LoginName
                if ($dispName.LastIndexOf("|") -gt -1)
                {
                    $dispName = $dispName.Substring($dispName.LastIndexOf("|")+1)
                }
                $ogUser = $null
                try { $ogUser = Get-AzureADUser -ObjectId $dispName -ErrorAction SilentlyContinue } catch {}
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
			            "web" = $web.ServerRelativeUrl
			            "parent" = $loginName
			            "loginType" = "User"
			            "loginName" = $member.LoginName
			            "loginDisplayName" = $dispName
			            "access" = $rolebinding.Name
		            }
                    $siteAcc.Add($obj) | Out-Null
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
                $oUser = Get-AzureADUser -Id $oUserId -ErrorAction SilentlyContinue
                if ($oUser)
                {
                    foreach($rolebinding in $rolebindings)
                    {
                        $obj = New-Object PSObject -Property @{
			                "web" = $web.ServerRelativeUrl
			                "parent" = ""
			                "loginType" = "AadUser"
			                "loginName" = $loginName
			                "loginDisplayName" = $oUser.UserPrincipalName
			                "access" = $rolebinding.Name
		                }
                        $siteAcc.Add($obj) | Out-Null
                    }
                }
                else
                {
                    Write-Warning "AzureAD user with id $oUserId not found"
                }
            }
            else
            {
                $oGroupId = $loginName.Substring($loginName.LastIndexOf("|")+1)
                if ($oGroupId.LastIndexOf("_") -gt -1)
                {
                    $oGroupId = $oGroupId.Substring(0, $oGroupId.LastIndexOf("_"))
                }
                $oGroup = $null
                try { $oGroup = Get-AzureADMSGroup -Id $oGroupId -ErrorAction SilentlyContinue } catch {}
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
                        $ogMembers = Get-AzureADGroupOwner -ObjectId $oGroupId
                        $dispName += " Owners"
                    }
                    else
                    {
                        $ogMembers = Get-AzureADGroupMember -ObjectId $oGroupId
                        $dispName += " Members"
                    }
                    foreach($rolebinding in $rolebindings)
                    {
                        $obj = New-Object PSObject -Property @{
			                "web" = $web.ServerRelativeUrl
			                "parent" = ""
			                "loginType" = $grpType
			                "loginName" = $loginName
			                "loginDisplayName" = $dispName
			                "access" = $rolebinding.Name
		                }
                        $siteAcc.Add($obj) | Out-Null
                    }
                    foreach($ogMember in $ogMembers)
                    {
                        $ogUser = Get-AzureADUser -ObjectId $ogMember.ObjectId
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
			                    "web" = $web.ServerRelativeUrl
			                    "parent" = $loginName
			                    "loginType" = $userType
			                    "loginName" = $ogUser.UserPrincipalName
			                    "loginDisplayName" = $dispName
			                    "access" = $rolebinding.Name
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
                        Write-Warning "Group with id $oGroupId not found"
                    }
                }
            }
        }
        else
        {
            $dispName = $loginName
            if ($dispName.LastIndexOf("|") -gt -1)
            {
                $dispName = $dispName.Substring($dispName.LastIndexOf("|")+1)
            }
            $ogUser = $null
            try { $ogUser = Get-AzureADUser -ObjectId $dispName -ErrorAction SilentlyContinue } catch {}
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
			        "web" = $web.ServerRelativeUrl
			        "parent" = ""
			        "loginType" = $principalType
			        "loginName" = $loginName
			        "loginDisplayName" = $dispName
			        "access" = $rolebinding.Name
		        }
                $siteAcc.Add($obj) | Out-Null
		    }
		}
    }
}
function Get-WebAccess
{
    param(
        $web
    )
    $siteAcc = New-Object System.Collections.ArrayList
    $web = Get-PnPWeb -Identity $web.ServerRelativeUrl -Includes "RoleAssignments"
    foreach($ra in $web.RoleAssignments)
    {
        $rolebindings = Get-PnPProperty -ClientObject $ra -Property "RoleDefinitionBindings"
        Process-Member -web $web -userOrGroup $ra.Member -rolebindings $rolebindings -siteAcc $siteAcc
    }

    $subWebs = Get-PnPSubWebs -Web $web
    foreach($sWeb in $subWebs)
    {
        $subSiteAcc = Get-WebAccess $sWeb
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

    $retries = 10
    do
    {
        try
        {
            $siteCon = ReloginTo-PnP -Url $siteUrl -ClientId $AlyaSharePointAppId -Thumbprint $AlyaSharePointAppCertificate
            $web = Get-PnPWeb
            $admins = Get-PnPSiteCollectionAdmin
            foreach($admin in $admins)
            {
                Process-Member -web $web -userOrGroup $admin -access "SiteColAdmin" -siteAcc $allSiteAcc
            }
            $siteAcc = Get-WebAccess $web
            if ($siteAcc -and $siteAcc.Count -gt 0)
            {
                $allSiteAcc.AddRange($siteAcc)
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

$allSiteAcc | ConvertTo-Csv -NoTypeInformation | Set-Content -Path "$AlyaData\sharepoint\UsersPerSites.csv" -Encoding UTF8 -Force

#Stopping Transscript
Stop-Transcript