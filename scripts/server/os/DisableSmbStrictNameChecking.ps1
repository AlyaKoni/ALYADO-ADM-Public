#Requires -RunAsAdministrator

Write-Host "This method is not suggested by microsoft!"
pause

$aname = $env:COMPUTERNAME
$cname = "srv"
$domain = $env:USERDNSDOMAIN

$prop = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "DisableStrictNameChecking" -ErrorAction SilentlyContinue
if (-Not $prop)
{
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "DisableStrictNameChecking" -Value 1 -PropertyType "DWord"
}
else
{
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "DisableStrictNameChecking" -Value 1
}

setspn -a host/$cname $aname
setspn -a host/$cname.$domain $aname
setspn -L $aname
