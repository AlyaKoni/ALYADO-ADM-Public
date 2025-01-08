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
    27.05.2024 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [string]$outputFile = $null #Defaults to "$AlyaData\exchange\Devices.xlsx"
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\exchange\Export-Devices-$($AlyaTimeString).log" | Out-Null

#Members
if (-Not $outputFile)
{
    $outputFile = "$AlyaData\exchange\Devices.xlsx"
}
$outputDirectory = Split-Path $outputFile -Parent
if (-Not (Test-Path $outputDirectory))
{
    New-Item -Path $outputDirectory -ItemType Directory -Force
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "ImportExcel"
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Exchange | Export-Devices | Exchange" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

try
{
    Write-Host "  Connecting to Exchange Online" -ForegroundColor $CommandInfo
    LoginTo-EXO

    # Getting devices
    Write-Host "Getting devices" -ForegroundColor $CommandInfo
    $mailboxUsers = Get-Mailbox -ResultSize Unlimited
    $devices = @()
    foreach($user in $mailboxUsers)
    {
        $devices += Get-MobileDevice -Mailbox $user.UserPrincipalName
    }

    $propNames = @()
    foreach($device in $devices)
    {
        foreach($prop in $device.PSObject.Properties)
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
    MoveFront "UserDisplayName"
    MoveFront "DeviceModel"
    MoveFront "DeviceOS"
    MoveFront "DeviceType"
    MoveFront "DeviceId"
    MoveFront "Name"

    $psdevices = @()
    foreach($device in $devices)
    {
        Write-Host "  Exporting $($device.DisplayName)"
        $psdevice = New-Object PSObject
        $allProps = $device.PSObject.Properties
        foreach($prop in $propNames)
        {
            $psProp = $allProps | Where-Object { $_.Name -eq $prop }
            if (-Not $psProp)
            {
                Add-Member -InputObject $psdevice -MemberType NoteProperty -Name $prop -Value ""
                continue
            }
            switch ($psProp.TypeNameOfValue)
            {
                "System.Xml.XmlElement" {
                    Add-Member -InputObject $psdevice -MemberType NoteProperty -Name $prop -Value $device."$prop".OuterXml
                }
                "System.String" {
                    Add-Member -InputObject $psdevice -MemberType NoteProperty -Name $prop -Value $device."$prop"
                }
                "System.String[]" {
                    Add-Member -InputObject $psdevice -MemberType NoteProperty -Name $prop -Value ($device."$prop" -join ";")
                }
                default {
                    $val = ""
                    if ($psProp.TypeNameOfValue.Contains("DateTime"))
                    {
                        if ($null -ne $device."$prop")
                        {
                            $val = $device."$prop".ToString("s")
                        }
                    }
                    elseif ($psProp.TypeNameOfValue.Contains("Microsoft.Graph.Beta.PowerShell.Models") -or `
                    $psProp.TypeNameOfValue.Contains("StrongAuthenticationdeviceDetails") -or `
                    $psProp.TypeNameOfValue.Contains("StrongAuthenticationMethod") -or `
                    $psProp.TypeNameOfValue.Contains("ExtensionDataObject"))
                    {
                        $val = ($device."$prop" | ConvertTo-Json -Compress -Depth 1 -WarningAction SilentlyContinue)
                    }
                    elseif ($psProp.TypeNameOfValue.Contains("[]") -or `
                        $psProp.TypeNameOfValue.Contains("System.Collections.Generic.Dictionary") -or `
                        $psProp.TypeNameOfValue.Contains("System.Collections.Generic.List"))
                    {
                        $val = ""
                        foreach($prt in $device."$prop")
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
                        foreach($prt in $device."$prop".GetEnumerator())
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
                        if ($null -ne $device."$prop")
                        {
                            $val = $device."$prop".ToString()
                        }
                        else
                        {
                            $val = ""
                        }
                    }
                    Add-Member -InputObject $psdevice -MemberType NoteProperty -Name $prop -Value $val
                }
            }
        }
        $psdevices += $psdevice
    }

    do
    {
        try
        {
            $excel = $psdevices | Select-Object -Property $propNames | Export-Excel -Path $outputFile -WorksheetName "devices" -TableName "devices" -BoldTopRow -AutoFilter -FreezeTopRowFirstColumn -ClearSheet -PassThru
            #$ws = $excel.Workbook.Worksheets['devices']
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

}
catch
{
    try { Write-Error ($_.Exception | ConvertTo-Json -Depth 1) -ErrorAction Continue } catch {}
	Write-Error ($_.Exception) -ErrorAction Continue
}

#Stopping Transscript
Stop-Transcript
