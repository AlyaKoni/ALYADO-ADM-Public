#Requires -Version 2

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


#>

$sids = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked' -name |where-object {$_.Length -gt 25}
 
foreach ($sid in $sids)
{
 
    Write-Host "Found a registered device. Would you like to remove the device registration settings for SID: $($sid)?" -ForegroundColor Yellow
    $Readhost = Read-Host " ( y / n ) "
    Switch ($ReadHost)
    {
        Y {Write-Host "Yes, Remove registered device"; $removedevice=$true}
        N {Write-Host "No, do not remove device registration"; $removedevice=$false}
        Default {Write-Host "Default, Do not remove device registration"; $removedevice=$false}
    }
 
    if ($removedevice -eq $true)
    {
 
        $enrollmentpath = "HKLM:\SOFTWARE\Microsoft\Enrollments\$($sid)"
        $entresourcepath = "HKLM:\SOFTWARE\Microsoft\EnterpriseResourceManager\Tracked\$($sid)"
 
        $value1 = Test-Path $enrollmentpath
        if ($value1 -eq $true)
        {
            Write-Host "$($sid) exists and will be removed"
            Remove-Item -Path $enrollmentpath -Recurse -confirm:$false
            Remove-Item -Path $entresourcepath -Recurse -confirm:$false
        }
        else
        {
            Write-Host "The value does not exist, skipping"
        }
 
        Get-ScheduledTask -TaskPath "\Microsoft\Windows\EnterpriseMgmt\$($sid)\*"| Unregister-ScheduledTask -Confirm:$false
        $scheduleObject = New-Object -ComObject Schedule.Service
        $scheduleObject.connect()
        $rootFolder = $scheduleObject.GetFolder("\Microsoft\Windows\EnterpriseMgmt")
        $rootFolder.DeleteFolder($sid,$null)
 
        Write-Host "Device registration cleaned up for $($sid)"
        pause
 
    }
    else
    {
        Write-Host "Removal has been cancelled for $($sid)"
    }
}

Write-Host "Cleanup of device registration has been completed."
Write-Host "Please remove the device '$($env:COMPUTERNAME)' in portal."
