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
    21.09.2020 Konrad Brunner       Initial Version
    16.12.2020 Konrad Brunner       Fixed bug, not removing users from groups
    19.10.2021 Konrad Brunner       Changed LIC group names
    15.11.2021 Konrad Brunner       Fixed not existing group
    21.04.2023 Konrad Brunner       Switched to Graph, removed AzureAdPreview
    03.08.2023 Konrad Brunner       Processing groups and users if useDirectAssignment
    13.09.2023 Konrad Brunner       Handling OnPrem and Cloud Licenses
    10.09.2025 Konrad Brunner       Cleaning of direct assignments
    06.02.2026 Konrad Brunner       Added powershell documentation

#>

<#
.SYNOPSIS
Configures Azure AD licenses for users based on Excel configuration files and optionally manages direct license assignments or group-based assignments.

.DESCRIPTION
The Configure-Licenses.ps1 script automates the synchronization of Azure AD user licenses by reading configurations from Excel files. It supports both group-based license management and direct license assignments. The script ensures that users are correctly added to or removed from relevant license groups, assigns required licenses directly if configured, and optionally removes licenses not specified in the configuration. It can also clean up direct license assignments if required. The script uses Microsoft Graph PowerShell modules to interact with Azure AD and requires proper authentication and permissions.

.PARAMETER inputFile
Specifies the path to the Excel file containing license definitions. Defaults to "$AlyaData\aad\Lizenzen.xlsx" if not provided.

.PARAMETER useDirectAssignment
Indicates whether to assign licenses directly to users instead of using group-based assignments. Default is $true.

.PARAMETER cleanDirectAssignments
Removes direct license assignments according to the configuration. Cannot be used simultaneously with useDirectAssignment set to $true. Default is $false.

.PARAMETER useOnPremAndCloudGroups
Enables processing of both on-premises and cloud license groups. Default is $false.

.PARAMETER groupsInputFileForDirectAssignment
Specifies the path to the Excel file containing group definitions for direct license assignment. Defaults to "$AlyaData\aad\Gruppen.xlsx" if not provided.

.INPUTS
None. The script reads data from Excel configuration files.

.OUTPUTS
Generates a log file under "$AlyaLogs\scripts\aad\" containing detailed processing information. Outputs progress and warnings to the console.

.EXAMPLE
PS> .\Configure-Licenses.ps1 -inputFile "C:\Data\aad\Lizenzen.xlsx" -useDirectAssignment $true -useOnPremAndCloudGroups $true

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [string]$inputFile = $null, #Defaults to "$AlyaData\aad\Lizenzen.xlsx"
    [bool]$useDirectAssignment = $true,
    [bool]$cleanDirectAssignments = $false,
    [bool]$useOnPremAndCloudGroups = $false,
    [string]$groupsInputFileForDirectAssignment = $null #Defaults to "$AlyaData\aad\Gruppen.xlsx"
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Configure-Licenses-$($AlyaTimeString).log" | Out-Null

#Members
if (-Not $inputFile)
{
    $inputFile = "$AlyaData\aad\Lizenzen.xlsx"
}
if (-Not $groupsInputFileForDirectAssignment)
{
    $groupsInputFileForDirectAssignment = "$AlyaData\aad\Gruppen.xlsx"
}
if ($useDirectAssignment -and $cleanDirectAssignments)
{
    Write-Warning "Cleaning direct assignments of licenses is not possible if useDirectAssignment is also set. Please set useDirectAssignment to false."
    exit
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.DirectoryManagement"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users.Actions"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Groups"
Install-ModuleIfNotInstalled "ImportExcel"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes "Directory.ReadWrite.All"

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Configure-Licenses | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Reading input file
Write-Host "Reading input file from '$inputFile'" -ForegroundColor $CommandInfo
if (-Not (Test-Path $inputFile))
{
    throw "Input file not found!"
}
$licDefs = Import-Excel $inputFile -ErrorAction Stop

# Configured licenses
Write-Host "Configured licenses:" -ForegroundColor $CommandInfo
$grpSuffixes = @("")
if ($true -eq $useOnPremAndCloudGroups) { $grpSuffixes = @("", "ONPREM", "CLOUD") }
$licNames = $null
$fndMissingGroup = $false
$byGroup = @{}
$licDefs | Foreach-Object {
    $licDef = $_
    if ($licDef.Name -like "User*")
    {
        $licNames = $licDef
    }
    if ($licDef.Name -like "*@*")
    {
        $outStr = " - $($licDef.Name): "
        for ($i = 1; $i -le 40; $i++)
        {
            $propName = "Lic"+$i
            if ($licDef.$propName -eq 1)
            {
                $outStr += "$($licNames.$propName),"
                $exist = $false
                foreach($grpSuffix in $grpSuffixes)
                {
                    $grpName = $AlyaCompanyNameShort.ToUpper() + "SG-LIC-" + $licNames.$propName + $grpSuffix
                    if (-Not $byGroup.$grpName) {
                        $byGroup.$grpName = @{}
                        $byGroup.$grpName.Users = @()
                    }
                    $byGroup.$grpName.Users += $licDef.Name
                    $exGrp = Get-MgBetaGroup -Filter "DisplayName eq '$grpName'"
                    if ($exGrp) {
                        $exist = $true
                        $byGroup.$grpName.Id = $exGrp.Id
                    }
                }
                if (-Not $exist)
                {
                    Write-Warning "  Please add missing group $($grpName)"
                    $fndMissingGroup = $true
                }
            }
        }
        Write-Host $outStr.TrimEnd(",")
    }
}
for ($i = 1; $i -le 40; $i++)
{
    $propName = "Lic"+$i
    if ($licNames.$propName)
    {
        foreach($grpSuffix in $grpSuffixes)
        {
            $grpName = $AlyaCompanyNameShort.ToUpper() + "SG-LIC-" + $licNames.$propName + $grpSuffix
            if (-Not $byGroup.$grpName) {
                $byGroup.$grpName = @{}
                $byGroup.$grpName.Users = @()
                $exGrp = Get-MgBetaGroup -Filter "DisplayName eq '$grpName'"
                if ($exGrp) {
                    $byGroup.$grpName.Id = $exGrp.Id
                }
            }
        }
    }
}

if (-Not $useDirectAssignment -and $fndMissingGroup)
{
    Write-Error "Found missing groups. Please add them to data\ad\Groups.xlsx and run Configure-Groups.ps1" -ErrorAction Continue
    exit
}

# Syncing licensed users with license groups
Write-Host "Syncing licensed users with license groups" -ForegroundColor $CommandInfo
foreach ($group in $byGroup.Keys)
{
    if ($byGroup.$group -ne $null -and $byGroup.$group.Id -ne $null)
    {
        Write-Host "  Group '$group'"
        $members = Get-MgBetaGroupMember -GroupId $byGroup[$group].Id
        foreach ($member in $members)
        {
            if (-Not $byGroup[$group].Users.Contains($member.AdditionalProperties.userPrincipalName))
            {
                #Remove member
                Write-Host "    Removing member '$($member.AdditionalProperties.userPrincipalName)'"
                Remove-MgBetaGroupMemberByRef -GroupId $byGroup[$group].Id -DirectoryObjectId $member.Id
            }
        }
        foreach ($user in $byGroup[$group].Users)
        {
            $adUser = Get-MgBetaUser -UserId $user
            if (-Not $adUser)
            {
                Write-Warning "     Member '$user' not found in AAD"
                continue
            }
            if ($group.EndsWith("ONPREM") -and $null -eq $adUser.OnPremisesSyncEnabled) { continue }
            if ($group.EndsWith("CLOUD") -and $null -ne $adUser.OnPremisesSyncEnabled) { continue }
            $fnd = $false
            foreach ($member in $members)
            {
                if ($member.AdditionalProperties.userPrincipalName -eq $user)
                {
                    $fnd = $true
                }
            }
            if (-Not $fnd)
            {
                #Adding member
                if ($group.EndsWith("ONPREM")) {
                    Write-Host "    Please add member '$user' in local AD"
                } else {
                    Write-Host "    Adding member '$user'"
                    New-MgBetaGroupMember -GroupId $byGroup[$group].Id -DirectoryObjectId $adUser.Id
                }
            }
        }
    }
}

if ($useDirectAssignment)
{
    
    # Reading groups file
    Write-Host "Reading groups file from '$groupsInputFileForDirectAssignment" -ForegroundColor $CommandInfo
    if (-Not (Test-Path $groupsInputFileForDirectAssignment))
    {
        throw "Groups file '$groupsInputFileForDirectAssignment' not found!"
    }
    $AllGroups = Import-Excel $groupsInputFileForDirectAssignment -WorksheetName "Gruppen" -ErrorAction Stop

    # Syncing licensed users with direct access
    Write-Host "Syncing licensed users with direct access" -ForegroundColor $CommandInfo

    $assignedLicenses = @{}
    foreach ($group in $byGroup.Keys)
    {
        Write-Host "  Group '$group'"
        if ($byGroup[$group] -ne $null -and $byGroup[$group].Id -ne $null)
        {
            $groupDef = $AllGroups | Where-Object { $_.DisplayName -eq $group }
            foreach ($user in $byGroup[$group].Users)
            {
                Write-Host "    User '$user'"
                $adUser = Get-MgBetaUser -UserId $user
                if ($null -eq $assignedLicenses."$($user)")
                {
                    $assignedLicenses."$($user)" = [System.Collections.ArrayList]@()
                }
                if (-Not $adUser.UsageLocation)
                {
                    Write-Host "      Setting usage location to '$AlyaDefaultUsageLocation'"
                    Update-MgBetaUser -UserId $adUser.Id -UsageLocation $AlyaDefaultUsageLocation
                }
                $userLics = $assignedLicenses."$($user)"
                $licDets = Get-MgBetaUserLicenseDetail -UserId $adUser.Id
                foreach($lic in $groupDef.Licenses)
                {
                    if (-Not $userLics.Contains($lic)) { $userLics.Add($lic) | Out-Null }
                    if ($licDets.SkuPartNumber -notcontains $lic)
                    {
                        Write-Host "      Adding license '$lic'"
                        $Sku = Get-MgBetaSubscribedSku -All | Where-Object { $_.SkuPartNumber -eq $lic }
                        Set-MgBetaUserLicense -UserId $adUser.Id -AddLicenses @{SkuId = $Sku.SkuId} -RemoveLicenses @() | Out-Null
                    }
                }
            }
        }
    }

    # Removing not configured licenses
    Write-Host "Removing not configured licenses" -ForegroundColor $CommandInfo

    foreach ($assLic in $assignedLicenses.GetEnumerator())
    {
        $adUser = Get-MgBetaUser -UserId $assLic.Name
        Write-Host "  User '$($assLic.Name)'"
        $userLics = $assignedLicenses."$($assLic.Name)"
        $licDets = Get-MgBetaUserLicenseDetail -UserId $adUser.Id
        foreach($lic in $licDets.SkuPartNumber)
        {
            if (-Not $userLics.Contains($lic))
            {
                Write-Host "    Removing license '$lic'"
                $Sku = Get-MgBetaSubscribedSku -All | Where-Object { $_.SkuPartNumber -eq $lic }
                Set-MgBetaUserLicense -UserId $adUser.Id -AddLicenses @() -RemoveLicenses @($Sku.SkuId) | Out-Null
            }
        }
    }

}

if ($cleanDirectAssignments)
{
    # Reading groups file
    Write-Host "Reading groups file from '$groupsInputFileForDirectAssignment" -ForegroundColor $CommandInfo
    if (-Not (Test-Path $groupsInputFileForDirectAssignment))
    {
        throw "Groups file '$groupsInputFileForDirectAssignment' not found!"
    }
    $AllGroups = Import-Excel $groupsInputFileForDirectAssignment -WorksheetName "Gruppen" -ErrorAction Stop | Where-Object { $_.Activ -eq "Yes" -and $_.Name -like "*-LIC-*" }
    $AllLicenses = $AllGroups.Licenses.Split(",") | Sort-Object -Unique

    # Cleaning all direct assignments
    Write-Host "Cleaning all direct assignments" -ForegroundColor $CommandInfo
    $allUsers = Get-MgBetaUser -All -Property Id, UserPrincipalName, AssignedLicenses, LicenseAssignmentStates, DisplayName
    foreach ($adUser in $allUsers)
    {
        $directAssignments = $adUser.LicenseAssignmentStates | Where-Object { $_.AssignedByGroup -eq $null }
        foreach ($assignment in $directAssignments)
        {
            $Sku = Get-MgBetaSubscribedSku -All | Where-Object { $_.SkuId -eq $assignment.SkuId }
            if ($AllLicenses -contains $Sku.SkuPartNumber)
            { 
                Write-Host "  User '$($adUser.UserPrincipalName)' - Removing direct assignment '$($Sku.SkuPartNumber)'"
                Set-MgBetaUserLicense -UserId $adUser.Id -AddLicenses @() -RemoveLicenses @($Sku.SkuId) | Out-Null
            }
        }
    }
}

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAfYVH4WVi3OZ+S
# /41iT0fB+U8NjzCsW5jbGfDD7kGUcaCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKKgz7JKn788Ib5P
# 6qOLx0MJmHu1yy4U6ypyl6xkYPu3MA0GCSqGSIb3DQEBAQUABIICAIiyGhDCEBlw
# hpqSBXTqXjYI3WKV4FrVvs8CS0wEV6GNv2Xc5qzTeLptf/4SWELLN/zviSCMqHc3
# EnDIKwywAzj1QAhT01MzzDNtVT5f+0M1bL0xPtxFpKNaJxZNxrnvuNOpka5HULy/
# /Q18Zj8EXQ5Cj0+w66pSJYsBdmaqNWNiU9DdmAQCKyVNjn0G4poeJDw4Xg7fFek9
# hBONM5px1jA3HTnCRYbBtJ+UN8uAqlowxKtAjgZUSLPTWjF2f+VAi9QqefLKStx0
# CPcz7xirQIJ4uPhUJkg89PsfylDqbr/ZwZWuxlAT99SG8oGiRa5KwgLfG1VIuoNO
# 1nXchBzeI4juDLqxOTp9uNQUJvNhQmc3+Vfp+JqgONfCm9in4GTzGhOn3lrf5ZgZ
# D9TKG9mHbkTkt3kMaHSbWfB+Q2IIYjqZN+Yfi9ZzNrvXR4hGtzXFkCRz/hr8UOmS
# r0Q6GKhdvkAMt6Ds59jRdGuDYMY2ycGp2f/Sm+aGNKtEFzSMhucvG8ry9XakMwlJ
# xXmV6gFG2C+5zcODN3YtiBS3ua9kuC16Aq4IbGsrm/MAPSRv2jGUPr4rEzLOtCKi
# z0qN0doEGcI41QjWPqFaAgUEex2ccX/G61bDUjCn5NUtjFqc6bgVbRPIhVWPRkVJ
# p+Ag0xKUDwhsA9xH83ROWfSoUqAe/c8boYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCCpu+wAXR5DQlNaSIY0ii3NTuGkA/wXWriqAuYbrJVxdAIUExWXJ+TAtMWY
# 7a/QOBZcIvWeBusYDzIwMjYwMjA2MTEzODM4WjADAgEBoFikVjBUMQswCQYDVQQG
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
# IKX5xL6My/yFX0PKnYGSm4Avx6xM3v5G5tqFfVQRiMQMMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAZ9+zEXiEGJ5h
# aLIF8xm4Oj9c/rdigIh0ftJGMWkD6aYlmpFnUVqEAPWEE4x1Uj9oGaHSWuZzXiA4
# 2sNyfumD1x+/tIlUIdANW98/ERZGXyqvA8bHXQiSf2Tq0xx/rdvpJvkKmmpjj5Ya
# McsazUM1T423OexOYjRSTQR0kHu6pwDqfQT8ycvMjudAT2eIGc1febGorQk6vlPq
# Drl2SnSsm28YM/fJySNffo5xnfrH1tbhyuA2nIvZF+n98LaidiKAfTGO4OjNjMMt
# ttGCHrexWqF1Tsp8BDRkHBZqSUEtKRlIq5ZcwfH6O/jhK64KUbC7LS11PvRV6p5z
# ZWJeLRiVyhit7r0XO+Jx2Kupe9ZR78jT2IAVzEOtyS2Ih2CCX/OFm1EeZ09c3Sne
# CjX3ZGfaJET4BnTpCiqigCKUshOGnsESaoQAVlUpFPIsPu7pywGuiVe5wE7p6pwb
# nFV+sD8drSavwYjJz8itTC5Ipsjgyxac6ByM0FaQF1vaSMEBwGul
# SIG # End signature block
