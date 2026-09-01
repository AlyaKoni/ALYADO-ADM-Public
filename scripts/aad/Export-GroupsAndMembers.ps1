#Requires -Version 2.0

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
    30.08.2026 Konrad Brunner       Initial Version

#>

<#
.SYNOPSIS
Exports all Azure AD groups and their members to an Excel file.

.DESCRIPTION
The Export-GroupsAndMembers.ps1 script connects to Microsoft Graph using the Microsoft.Graph modules to retrieve all Azure Active Directory groups (Microsoft 365, Security, Distribution, Mail-enabled Security and dynamic groups) and exports their details into the "Groups" worksheet of an Excel file. Additionally it retrieves the members of every group, resolves the member details (type, display name, userPrincipalName/mail) and exports them into a second "Members" worksheet. It dynamically collects all properties from group objects, formats complex properties into readable strings or JSON where appropriate, and saves the output in a formatted Excel file using the ImportExcel module. The script creates necessary directories, ensures required modules are installed, and logs the execution to a transcript file.

.PARAMETER outputFile
Specifies the path to the output Excel file. If not provided, the script defaults to "$AlyaData\aad\GroupsAndMembers.xlsx".

.INPUTS
None. The script does not accept input from the pipeline.

.OUTPUTS
An Excel file with two worksheets ("Groups" and "Members") containing the exported Azure AD group and membership information.

.EXAMPLE
PS> .\Export-GroupsAndMembers.ps1 -outputFile "C:\Exports\GroupsAndMembers.xlsx"

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [string]$outputFile = $null #Defaults to "$AlyaData\aad\GroupsAndMembers.xlsx"
)

# Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transcript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Export-GroupsAndMembers-$($AlyaTimeString).log" | Out-Null

#Members
if (-Not $outputFile)
{
    $outputFile = "$AlyaData\aad\GroupsAndMembers.xlsx"
}
$outputDirectory = Split-Path $outputFile -Parent
if (-Not (Test-Path $outputDirectory))
{
    New-Item -Path $outputDirectory -ItemType Directory -Force
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ImportExcel"
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Groups"
Install-ModuleIfNotInstalled "Microsoft.Graph.Users"
Install-ModuleIfNotInstalled "Microsoft.Graph.Identity.DirectoryManagement"
Install-ModuleIfNotInstalled "Microsoft.Graph.Applications"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes "Group.Read.All","Directory.Read.All"

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Export-GroupsAndMembers | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting groups
Write-Host "Getting groups" -ForegroundColor $CommandInfo
$groups = Get-MgGroup -Property "*" -All

$propNames = @()
foreach($group in $groups)
{
    foreach($prop in $group.PSObject.Properties)
    {
        if (-Not $propNames.Contains($prop.Name))
        {
            $propNames += $prop.Name
        }
    }
}

function MoveFront($propName)
{
    $idx = $propNames.IndexOf($propName)
    for ($i=$idx; $i -gt 0; $i--)
    {
        $propNames[$i] = $propNames[$i-1]
    }
    $propNames[0] = $propName
}
MoveFront "OnPremisesSyncEnabled"
MoveFront "MembershipRuleProcessingState"
MoveFront "MembershipRule"
MoveFront "Visibility"
MoveFront "ResourceProvisioningOptions"
MoveFront "ResourceBehaviorOptions"
MoveFront "ExpirationDateTime"
MoveFront "RenewedDateTime"
MoveFront "CreatedDateTime"
MoveFront "ProxyAddresses"
MoveFront "OnPremisesSecurityIdentifier"
MoveFront "MailNickname"
MoveFront "Mail"
MoveFront "SecurityEnabled"
MoveFront "MailEnabled"
MoveFront "GroupTypes"
MoveFront "Description"
MoveFront "Id"
MoveFront "DisplayName"

$psgroups = @()
foreach($group in $groups)
{
    Write-Host "  Exporting $($group.DisplayName)"
    $psgroup = New-Object PSObject
    $allProps = $group.PSObject.Properties
    foreach($prop in $propNames)
    {
        $psProp = $allProps | Where-Object { $_.Name -eq $prop }
        if (-Not $psProp)
        {
            Add-Member -InputObject $psgroup -MemberType NoteProperty -Name $prop -Value ""
            continue
        }
        switch ($psProp.TypeNameOfValue)
        {
            "System.Xml.XmlElement" {
                Add-Member -InputObject $psgroup -MemberType NoteProperty -Name $prop -Value $group."$prop".OuterXml
            }
            "System.String" {
                Add-Member -InputObject $psgroup -MemberType NoteProperty -Name $prop -Value $group."$prop"
            }
            "System.String[]" {
                Add-Member -InputObject $psgroup -MemberType NoteProperty -Name $prop -Value ($group."$prop" -join ";")
            }
            default {
                $val = ""
                if ($psProp.TypeNameOfValue.Contains("DateTime"))
                {
                    if ($null -ne $group."$prop")
                    {
                        $val = $group."$prop".ToString("s")
                    }
                }
                elseif ($psProp.TypeNameOfValue.Contains("Microsoft.Graph.Beta.PowerShell.Models") -or `
                $psProp.TypeNameOfValue.Contains("Microsoft.Graph.PowerShell.Models") -or `
                $psProp.TypeNameOfValue.Contains("StrongAuthenticationUserDetails") -or `
                $psProp.TypeNameOfValue.Contains("StrongAuthenticationMethod") -or `
                $psProp.TypeNameOfValue.Contains("ExtensionDataObject"))
                {
                    $val = ($group."$prop" | ConvertTo-Json -Compress -Depth 1 -WarningAction SilentlyContinue)
                }
                elseif ($psProp.TypeNameOfValue.Contains("[]") -or `
                    $psProp.TypeNameOfValue.Contains("System.Collections.Generic.Dictionary") -or `
                    $psProp.TypeNameOfValue.Contains("System.Collections.Generic.List"))
                {
                    $val = ""
                    foreach($prt in $group."$prop")
                    {
                        if ($null -ne $prt)
                        {
                            $val += $prt.ToString() + ";"
                        }
                    }
                    $val = $val.TrimEnd(";")
                }
                elseif ($psProp.TypeNameOfValue.Contains("[[System.String") -and $psProp.TypeNameOfValue.Contains(",[System.Object") -and $psProp.TypeNameOfValue.Contains("System.Collections.Generic.IDictionary"))
                {
                    $val = ""
                    foreach($prt in $group."$prop".GetEnumerator())
                    {
                        if ($null -ne $prt.Value)
                        {
                            $val += $prt.Key + "=" + $prt.Value.ToString() + ";"
                        }
                        else
                        {
                            $val += $prt.Key + "=;"
                        }
                    }
                    $val = $val.TrimEnd(";")
                }
                else
                {
                    if ($null -ne $group."$prop")
                    {
                        $val = $group."$prop".ToString()
                    }
                    else
                    {
                        $val = ""
                    }
                }
                Add-Member -InputObject $psgroup -MemberType NoteProperty -Name $prop -Value $val
            }
        }
    }
    $psgroups += $psgroup
}

# Getting group members
Write-Host "Getting group members" -ForegroundColor $CommandInfo
$memberRows = @()
$groupCounter = 0
foreach($group in $groups)
{
    $groupCounter++
    $members = Get-MgGroupMember -GroupId $group.Id -All
    if (-Not $members -or $members.Count -eq 0)
    {
        continue
    }
    Write-Host "  [$($groupCounter)/$($groups.Count)] $($group.DisplayName): $($members.Count) members" -ForegroundColor $CommandInfo
    foreach($member in $members)
    {
        $memberType = "Unknown"
        $memberDisplayName = ""
        $memberUpnOrMail = ""
        if ($member.AdditionalProperties)
        {
            $odataType = $member.AdditionalProperties["@odata.type"]
            switch ($odataType)
            {
                "#microsoft.graph.user" { $memberType = "User" }
                "#microsoft.graph.group" { $memberType = "Group" }
                "#microsoft.graph.device" { $memberType = "Device" }
                "#microsoft.graph.servicePrincipal" { $memberType = "ServicePrincipal" }
                "#microsoft.graph.orgContact" { $memberType = "OrgContact" }
            }
            if ($member.AdditionalProperties.displayName)
            {
                $memberDisplayName = $member.AdditionalProperties.displayName
            }
            if ($memberType -eq "User")
            {
                if ($member.AdditionalProperties.userPrincipalName)
                {
                    $memberUpnOrMail = $member.AdditionalProperties.userPrincipalName
                }
            }
            elseif ($member.AdditionalProperties.mail)
            {
                $memberUpnOrMail = $member.AdditionalProperties.mail
            }
        }
        if ($memberType -eq "Unknown")
        {
            # Fallback: Mitglied ist kein Basis-DirectoryObject mit @odata.type,
            # per Einzelabfrage auflösen (ohne -All, nur Punkt-Treffer).
            $memberUser = Get-MgUser -UserId $member.Id -Property DisplayName,UserPrincipalName,Mail -ErrorAction SilentlyContinue
            if ($memberUser)
            {
                $memberType = "User"
                $memberDisplayName = $memberUser.DisplayName
                if ($memberUser.UserPrincipalName)
                {
                    $memberUpnOrMail = $memberUser.UserPrincipalName
                }
                elseif ($memberUser.Mail)
                {
                    $memberUpnOrMail = $memberUser.Mail
                }
            }
            else
            {
                $memberGroup = Get-MgGroup -GroupId $member.Id -Property DisplayName,Mail -ErrorAction SilentlyContinue
                if ($memberGroup)
                {
                    $memberType = "Group"
                    $memberDisplayName = $memberGroup.DisplayName
                    $memberUpnOrMail = $memberGroup.Mail
                }
                else
                {
                    $memberDevice = Get-MgDevice -DeviceId $member.Id -Property DisplayName -ErrorAction SilentlyContinue
                    if ($memberDevice)
                    {
                        $memberType = "Device"
                        $memberDisplayName = $memberDevice.DisplayName
                    }
                    else
                    {
                        $memberSp = Get-MgServicePrincipal -ServicePrincipalId $member.Id -Property DisplayName -ErrorAction SilentlyContinue
                        if ($memberSp)
                        {
                            $memberType = "ServicePrincipal"
                            $memberDisplayName = $memberSp.DisplayName
                        }
                    }
                }
            }
        }
        $memberRows += [pscustomobject]@{
            GroupDisplayName = $group.DisplayName
            GroupId = $group.Id
            MemberDisplayName = $memberDisplayName
            MemberUserPrincipalName = $memberUpnOrMail
            MemberType = $memberType
            MemberId = $member.Id
        }
    }
}

# Saving to Excel (beide Sheets in dieselbe Datei; zwei unabhängige Export-Excel-Aufrufe,
# ohne Close-ExcelPackage/-Show/Start-Process — funktioniert plattformübergreifend)
Write-Host "Saving to $outputFile" -ForegroundColor $CommandInfo
do
{
    try
    {
        $psgroups | Select-Object -Property $propNames | Export-Excel -Path $outputFile -WorksheetName "Groups" -TableName "Groups" -BoldTopRow -AutoFilter -FreezeTopRowFirstColumn -ClearSheet
        if ($memberRows.Count -gt 0)
        {
            $memberRows | Export-Excel -Path $outputFile -WorksheetName "Members" -TableName "Members" -BoldTopRow -AutoFilter -FreezeTopRowFirstColumn -ClearSheet
        }
        else
        {
            @([pscustomobject]@{ GroupDisplayName=""; GroupId=""; MemberDisplayName=""; MemberUserPrincipalName=""; MemberType=""; MemberId="" }) | Export-Excel -Path $outputFile -WorksheetName "Members" -TableName "Members" -BoldTopRow -AutoFilter -FreezeTopRowFirstColumn -ClearSheet
        }
        break
    } catch
    {
        if ($_.Exception.Message.Contains("Could not open Excel Package"))
        {
            Write-Host "Please close excel sheet $outputFile"
            pause
        }
        else
        {
            throw
        }
    }
} while ($true)

Write-Host "Groups and members saved to $outputFile ($($psgroups.Count) groups, $($memberRows.Count) member rows)" -ForegroundColor $CommandInfo

# Stopping Transcript
Stop-Transcript
