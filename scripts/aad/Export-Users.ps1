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
    08.10.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$outputFile = $null #Defaults to "$AlyaData\aad\Users.xlsx"
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\aad\Export-Users-$($AlyaTimeString).log" | Out-Null

#Members
if (-Not $outputFile)
{
    $outputFile = "$AlyaData\aad\Users.xlsx"
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
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.DirectoryManagement"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-MgGraph -Scopes "Directory.Read.All"

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Export-Users | Graph" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Functions
function Convert-ObjectIdToSid
{
    param([String] $ObjectId)
    $d=[UInt32[]]::new(4);[Buffer]::BlockCopy([Guid]::Parse($ObjectId).ToByteArray(),0,$d,0,16);"S-1-12-1-$d".Replace(' ','-')
}

# Getting users
Write-Host "Getting users" -ForegroundColor $CommandInfo
#$users = Get-MsolUser -All
$users = Get-MgBetaUser -Property "*" -All

$propNames = @()
foreach($user in $users)
{
    foreach($prop in $user.PSObject.Properties)
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
MoveFront "Id"
MoveFront "SecurityIdentifier"
MoveFront "LicenseDetails"
MoveFront "Surname"
MoveFront "GivenName"
MoveFront "OtherMails"
MoveFront "Mail"
MoveFront "DisplayName"
MoveFront "UserType"
MoveFront "UserPrincipalName"

$psusers = @()
foreach($user in $users)
{
    Write-Host "  Exporting $($user.UserPrincipalName)"
    $psuser = New-Object PSObject
    $allProps = $user.PSObject.Properties
    foreach($prop in $propNames)
    {
        $psProp = $allProps | Where-Object { $_.Name -eq $prop }
        if (-Not $psProp)
        {
            Add-Member -InputObject $psuser -MemberType NoteProperty -Name $prop -Value ""
            continue
        }
        switch ($psProp.TypeNameOfValue)
        {
            "System.Xml.XmlElement" {
                Add-Member -InputObject $psuser -MemberType NoteProperty -Name $prop -Value $user."$prop".OuterXml
            }
            "System.String" {
                Add-Member -InputObject $psuser -MemberType NoteProperty -Name $prop -Value $user."$prop"
            }
            "System.String[]" {
                Add-Member -InputObject $psuser -MemberType NoteProperty -Name $prop -Value ($user."$prop" -join ";")
            }
            default {
                $val = ""
                if ($psProp.TypeNameOfValue.Contains("DateTime"))
                {
                    if ($null -ne $user."$prop")
                    {
                        $val = $user."$prop".ToString("s")
                    }
                }
                elseif ($psProp.TypeNameOfValue.Contains("Microsoft.Graph.Beta.PowerShell.Models") -or `
                $psProp.TypeNameOfValue.Contains("StrongAuthenticationUserDetails") -or `
                $psProp.TypeNameOfValue.Contains("StrongAuthenticationMethod") -or `
                $psProp.TypeNameOfValue.Contains("ExtensionDataObject"))
                {
                    $val = ($user."$prop" | ConvertTo-Json -Compress -Depth 1 -WarningAction SilentlyContinue)
                }
                elseif ($psProp.TypeNameOfValue.Contains("[]") -or `
                    $psProp.TypeNameOfValue.Contains("System.Collections.Generic.Dictionary") -or `
                    $psProp.TypeNameOfValue.Contains("System.Collections.Generic.List"))
                {
                    $val = ""
                    foreach($prt in $user."$prop")
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
                    foreach($prt in $user."$prop".GetEnumerator())
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
                    if ($null -ne $user."$prop")
                    {
                        $val = $user."$prop".ToString()
                    }
                    else
                    {
                        $val = ""
                    }
                }
                Add-Member -InputObject $psuser -MemberType NoteProperty -Name $prop -Value $val
            }
        }
    }
    $psusers += $psuser
}

do
{
    try
    {
        $excel = $psusers | Select-Object -Property $propNames | Export-Excel -Path $outputFile -WorksheetName "Users" -TableName "Users" -BoldTopRow -AutoFilter -FreezeTopRowFirstColumn -ClearSheet -PassThru
        #$ws = $excel.Workbook.Worksheets['Users']
        #Set-Format -Worksheet $ws -Range "A:BZ" -
        Close-ExcelPackage $excel -Show
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

#Stopping Transscript
Stop-Transcript
