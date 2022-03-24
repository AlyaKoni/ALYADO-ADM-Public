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
