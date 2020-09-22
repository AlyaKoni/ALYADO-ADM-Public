#Requires -RunAsAdministrator 
#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

    This unpublished material is proprietary to Alya Consulting.
    All rights reserved. The methods and techniques described
    herein are considered trade secrets and/or confidential. 
    Reproduction or distribution, in whole or in part, is 
    forbidden except by express written permission of Alya Consulting.

    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    12.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\test\50_resizeVhdFiles-$($AlyaTimeString).log" | Out-Null

# Main
$tmp = New-TemporaryFile
$vhdFiles = Get-ChildItem -Path "E:\Shares\lmagtinfhpol001\Profiles" -Filter *.vhd -Recurse
foreach ($vhdFile in $vhdFiles)
{
    Write-Host "Processing $($vhdFile.FullName)" -ForegroundColor $CommandInfo
    @"
select vdisk file="$($vhdFile.FullName)"
expand vdisk maximum=102400
attach vdisk
select partition 1
extend
list partition
detach vdisk
exit
"@ | Set-Content -Path $tmp.FullName -Force
    diskpart /s $tmp.FullName
}
Remove-Item -Path $tmp.FullName -Force

#Stopping Transscript
Stop-Transcript
