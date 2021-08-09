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
    15.10.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    $overwriteExistingSPOUPAValue = $false
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\sharepoint\Sync-ProfileInformation-$($AlyaTimeString).log" | Out-Null

# Checking modules
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "AzureAdPreview"
Install-ModuleIfNotInstalled "PnP.PowerShell"
Install-ModuleIfNotInstalled "MSOnline"
Install-ModuleIfNotInstalled "Microsoft.Online.SharePoint.PowerShell"
Install-PackageIfNotInstalled "Microsoft.SharePointOnline.CSOM"
Add-Type -Path "$($AlyaTools)\Packages\Microsoft.SharePointOnline.CSOM\lib\net45\Microsoft.SharePoint.Client.dll"
Add-Type -Path "$($AlyaTools)\Packages\Microsoft.SharePointOnline.CSOM\lib\net45\Microsoft.SharePoint.Client.Runtime.dll"
Add-Type -Path "$($AlyaTools)\Packages\Microsoft.SharePointOnline.CSOM\lib\net45\Microsoft.SharePoint.Client.UserProfiles.dll"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-Ad
LoginTo-SPO
LoginTo-MSOL
LoginTo-PnP -Url $AlyaSharePointAdminUrl
$ctx= Get-PnPContext
$ctx.ExecuteQuery()

$spoPeopleManager = New-Object Microsoft.SharePoint.Client.UserProfiles.PeopleManager($ctx)

# Get all AzureAD Users
Write-Output "Getting all users"
$AzureADUsers = Get-MSolUser -All
foreach ($AzureADUser in $AzureADUsers)
{
    #$AzureADUser = $AzureADUsers | where UserPrincipalName -eq "konrad.brunner@alyaconsulting.ch"
    #if ($AzureADUser.UserPrincipalName -ne "konrad.brunner@alyaconsulting.ch") { continue }

    $targetUPN = $AzureADUser.UserPrincipalName.ToString()
    Write-Output "  User: $targetUPN"
    $targetSPOUserAccount = ("i:0#.f|membership|" + $targetUPN)

    $mobilePhone = $AzureADUser.MobilePhone
    if (!([string]::IsNullOrEmpty($mobilePhone))) {
        $targetUserCellPhone = $spoPeopleManager.GetUserProfilePropertyFor($targetSPOUserAccount, "CellPhone")
        $ctx.ExecuteQuery()
        $userCellPhone = $targetUserCellPhone.Value
        if ([string]::IsNullOrEmpty($userCellPhone)) {
            $targetspoUserAccount = ("i:0#.f|membership|" + $AzureADUser.UserPrincipalName.ToString())
            $spoPeopleManager.SetSingleValueProfileProperty($targetspoUserAccount, "CellPhone", $mobilePhone)
            $ctx.ExecuteQuery()
            Write-Output "    Target SPO UPA CellPhone overwritten with: $mobilePhone"
        }
        else {
            if ($overwriteExistingSPOUPAValue) {
                $targetspoUserAccount = ("i:0#.f|membership|" + $AzureADUser.UserPrincipalName.ToString())
                $spoPeopleManager.SetSingleValueProfileProperty($targetspoUserAccount, "CellPhone", $mobilePhone)
                $ctx.ExecuteQuery()
                Write-Output "    Target SPO UPA CellPhone overwritten with: $mobilePhone"
            }
            else {
                Write-Output "    Target SPO UPA CellPhone is not empty for $targetUPN and we're to preserve existing properties"
            }
        }
    }
    else {
        Write-Output "    AzureAD MobilePhone Property is Null or Empty for $targetUPN"
    }

    $workPhone = $AzureADUser.PhoneNumber
    if (!([string]::IsNullOrEmpty($workPhone))) {
        $targetUserCellPhone = $spoPeopleManager.GetUserProfilePropertyFor($targetSPOUserAccount, "WorkPhone")
        $ctx.ExecuteQuery()
        $userCellPhone = $targetUserCellPhone.Value
        if ([string]::IsNullOrEmpty($userCellPhone)) {
            $targetspoUserAccount = ("i:0#.f|membership|" + $AzureADUser.UserPrincipalName.ToString())
            $spoPeopleManager.SetSingleValueProfileProperty($targetspoUserAccount, "WorkPhone", $workPhone)
            $ctx.ExecuteQuery()
            Write-Output "    Target SPO UPA WorkPhone overwritten with: $workPhone"
        }
        else {
            if ($overwriteExistingSPOUPAValue) {
                $targetspoUserAccount = ("i:0#.f|membership|" + $AzureADUser.UserPrincipalName.ToString())
                $spoPeopleManager.SetSingleValueProfileProperty($targetspoUserAccount, "WorkPhone", $workPhone)
                $ctx.ExecuteQuery()
                Write-Output "    Target SPO UPA WorkPhone overwritten with: $workPhone"
            }
            else {
                Write-Output "    Target SPO UPA WorkPhone is not empty for $targetUPN and we're to preserve existing properties"
            }
        }
    }
    else {
        Write-Output "    AzureAD PhoneNumber Property is Null or Empty for $targetUPN"
    }

}

#Stopping Transscript
Stop-Transcript