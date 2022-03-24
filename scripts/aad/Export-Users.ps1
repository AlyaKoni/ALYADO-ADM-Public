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

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ImportExcel"
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "MSOnline"

# Logging in
Write-Host "Logging in" -ForegroundColor $CommandInfo
LoginTo-Az -SubscriptionName $AlyaSubscriptionName
LoginTo-MSOL

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AAD | Export-Users | MSOL" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Functions
function Convert-ObjectIdToSid
{
    param([String] $ObjectId)
    $d=[UInt32[]]::new(4);[Buffer]::BlockCopy([Guid]::Parse($ObjectId).ToByteArray(),0,$d,0,16);"S-1-12-1-$d".Replace(' ','-')
}

# Getting users
Write-Host "Getting users" -ForegroundColor $CommandInfo
$users = Get-MsolUser -All

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
$propNames += "SID"
function MoveFront($propName)
{
    $idx = $propNames.IndexOf($propName)
    for ($i=$idx; $i -gt 0; $i--)
    {
        $propNames[$i] = $propNames[$i-1]
    }
    $propNames[0] = $propName
}
MoveFront "ObjectId"
MoveFront "SID"
MoveFront "Licenses"
MoveFront "LastName"
MoveFront "FirstName"
MoveFront "AlternateEmailAddresses"
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
        if ($prop -eq "SID") { continue }
        $psProp = $allProps | where { $_.Name -eq $prop }
        if (-Not $psProp)
        {
            Add-Member -InputObject $psuser -MemberType NoteProperty -Name $prop -Value ""
        }
        if ($prop -eq "ObjectId")
        {
            Add-Member -InputObject $psuser -MemberType NoteProperty -Name "SID" -Value (Convert-ObjectIdToSid -ObjectId $user."$prop")
        }
        switch ($psProp.TypeNameOfValue)
        {
            "System.Runtime.Serialization.ExtensionDataObject" {
                Add-Member -InputObject $psuser -MemberType NoteProperty -Name $prop -Value ""
            }
            "System.Xml.XmlElement" {
                Add-Member -InputObject $psuser -MemberType NoteProperty -Name $prop -Value $user."$prop".OuterXml
            }
            default {
                if ($psProp.TypeNameOfValue.StartsWith("System.Collections.Generic.List"))
                {
                    Add-Member -InputObject $psuser -MemberType NoteProperty -Name $prop -Value ($user."$prop" | ConvertTo-Json -Compress)
                }
                else
                {
                    $val = ""
                    if ($psProp.TypeNameOfValue.Contains("DateTime"))
                    {
                        if ($user."$prop")
                        {
                            $val = $user."$prop".ToString("s")
                        }
                    }
                    elseif ($psProp.TypeNameOfValue.Contains("StrongAuthenticationUserDetails") -or `
                            $psProp.TypeNameOfValue.Contains("StrongAuthenticationMethod"))
                    {
                        $val = ($user."$prop" | ConvertTo-Json -Compress)
                    }
                    else
                    {
                        $val = "$($user."$prop")"
                    }
                    Add-Member -InputObject $psuser -MemberType NoteProperty -Name $prop -Value $val
                }
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
            Write-Host "Please close excel sheet"
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