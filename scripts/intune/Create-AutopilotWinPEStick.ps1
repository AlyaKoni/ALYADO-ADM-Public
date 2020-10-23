#Requires -Version 2.0
#Requires -RunAsAdministrator

<#
    Copyright (c) Alya Consulting: 2019, 2020

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
    16.10.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

# Loading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Pscx"

# Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\intune\Create-AutopilotWinPEStick-$($AlyaTimeString).log" -IncludeInvocationHeader -Force

# =============================================================
# Intune stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "Intune | Create-AutopilotWinPEStick | Local" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

Write-Host "Checking ADK dir" -ForegroundColor $CommandInfo
if (-Not (Test-Path "$($AlyaTools)\ADK"))
{
    $tmp = New-Item -Path "$($AlyaTools)\ADK" -ItemType Directory -Force
}

Write-Host "Checking AlyaADK" -ForegroundColor $CommandInfo
if (-Not (Test-Path "C:\AlyaADK"))
{
    Write-Host "Creating C:\AlyaADK"
    $tmp = New-Item -Path "C:\AlyaADK" -ItemType Directory -Force
}

Write-Host "Checking Assessment and Deployment Kit" -ForegroundColor $CommandInfo
if (-Not (Test-Path "C:\AlyaADK\Assessment and Deployment Kit"))
{
    Write-Host "Checking adksetup" -ForegroundColor $CommandInfo
    if (-Not (Test-Path "$($AlyaTools)\ADK\adksetup.exe"))
    {
        Write-Host "Downloading ADK setup tool"
        Invoke-RestMethod -Uri $AlyaAdkDownload -OutFile "$($AlyaTools)\ADK\adksetup.exe"
    }
    if (-Not (Test-Path "$($AlyaTools)\ADK\adksetup.exe"))
    {
        Write-Error "Problems downloding the adk setup" -ErrorAction Continue
        exit 92
    }

    Write-Host "Checking adk layout" -ForegroundColor $CommandInfo
    if (-Not (Test-Path "$($AlyaTemp)\ADKoffline"))
    {
        Write-Host "Downloading adk layout"
        & "$($AlyaTools)\ADK\adksetup.exe" /quiet /layout "$($AlyaTemp)\ADKoffline"
        do
        {
            Start-Sleep -Seconds 5
            $process = Get-Process -Name "adksetup" -ErrorAction SilentlyContinue
        } while ($process)
    }

    Write-Host "Installing ADK"
    Push-Location -Path "$($AlyaTemp)\ADKoffline"
    & ".\adksetup.exe" /quiet /installpath "C:\AlyaADK" /features OptionId.DeploymentTools
    do
    {
        Start-Sleep -Seconds 5
        $process = Get-Process -Name "adksetup" -ErrorAction SilentlyContinue
    } while ($process)
    Pop-Location
}

Write-Host "Checking Windows Preinstallation Environment" -ForegroundColor $CommandInfo
if (-Not (Test-Path "C:\AlyaADK\Assessment and Deployment Kit\Windows Preinstallation Environment"))
{
    Write-Host "Checking adkwinpesetup" -ForegroundColor $CommandInfo
    if (-Not (Test-Path "$($AlyaTools)\ADK\adkwinpesetup.exe"))
    {
        Write-Host "Downloading ADK WinPE setup tool"
        Invoke-RestMethod -Uri $AlyaADKpeDownload -OutFile "$($AlyaTools)\ADK\adkwinpesetup.exe"
    }
    if (-Not (Test-Path "$($AlyaTools)\ADK\adkwinpesetup.exe"))
    {
        Write-Error "Problems downloding the adk WinPE setup" -ErrorAction Continue
        exit 92
    }

    Write-Host "Checking adk WinPE layout" -ForegroundColor $CommandInfo
    if (-Not (Test-Path "$($AlyaTemp)\ADKPEoffline"))
    {
        Write-Host "Downloading adk WinPE layout"
        & "$($AlyaTools)\ADK\adkwinpesetup.exe" /quiet /layout "$($AlyaTemp)\ADKPEoffline"
        do
        {
            Start-Sleep -Seconds 5
            $process = Get-Process -Name "adkwinpesetup" -ErrorAction SilentlyContinue
        } while ($process)
    }

    Write-Host "Installing WinPE"
    Push-Location -Path "$($AlyaTemp)\ADKPEoffline"
    & ".\adkwinpesetup.exe" /quiet /installpath "C:\AlyaADK" /features OptionId.WindowsPreinstallationEnvironment
    do
    {
        Start-Sleep -Seconds 5
        $process = Get-Process -Name "adkwinpesetup" -ErrorAction SilentlyContinue
    } while ($process)
    Pop-Location
}

Write-Host "Getting WinPE environment" -ForegroundColor $CommandInfo
Invoke-BatchFile "C:\AlyaADK\Assessment and Deployment Kit\Deployment Tools\DandISetEnv.bat"

Write-Host "Checking iso image" -ForegroundColor $CommandInfo
$adkAutopilot = "$($AlyaTools)\ADK\Autopilot"
$adkAutopilotIso = "$($AlyaTools)\ADK\Autopilot.iso"
if (-Not (Test-Path "$($AlyaTools)\ADK") -or -Not (Test-Path $($adkAutopilotIso)))
{
    Write-Host "Creating new iso image"
    if ((Test-Path $($adkAutopilot)))
    {
        $tmp = Remove-Item -Path $($adkAutopilot) -Recurse -Force
    }

    Write-Host "Copying pe image"
    cmd /c copype amd64 $($adkAutopilot)

    Write-Host "Mounting image"
    if ((Test-Path "C:\AlyaADKpe"))
    {
        cmd /c rmdir "C:\AlyaADKpe"
    }
    Start-Sleep -Seconds 1
    cmd /c mklink /d "C:\AlyaADKpe" $($adkAutopilot)
    Start-Sleep -Seconds 1
    if (-Not (Test-Path "C:\AlyaADKpe"))
    {
        throw "Not able to create symbolic link"
    }

    Push-Location -Path "C:\AlyaADKpe"
    cmd /c Dism /mount-image /ImageFile:Media\Sources\boot.wim /Index:1 /MountDir:mount

    Write-Host "Customizing image"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-Fonts-Legacy.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-Fonts-Legacy_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-RNDIS.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-RNDIS_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-WMI.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-WMI_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-NetFx.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-NetFx_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-Scripting.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-Scripting_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-PowerShell.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-PowerShell_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-EnhancedStorage.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-EnhancedStorage_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-FMAPI.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-FMAPI_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-HTA.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-HTA_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-StorageWMI.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-StorageWMI_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-SecureStartup.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-SecureStartup_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-WDS-Tools.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-WDS-Tools_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-MDAC.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-MDAC_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-PPPoE.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-PPPoE_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-Setup.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-Setup_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-Setup-Client.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-Setup-Client_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-PlatformId.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-PlatformId_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-SecureBootCmdlets.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-SecureBootCmdlets_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-DismCmdlets.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-DismCmdlets_en-us.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\WinPE-PmemCmdlets.cab"
    cmd /c Dism /Image:mount /Add-Package /PackagePath:"$($env:WinPERoot)\amd64\WinPE_OCs\en-us\WinPE-PmemCmdlets_en-us.cab"

    $sourceRoot = "C:\AlyaADKpe\mount\Windows\System32\wbem"
    cmd /c xcopy /herky "C:\Windows\System32\wbem\MDMAppProv*" "$($sourceRoot)"
    cmd /c xcopy /herky "C:\Windows\System32\wbem\MDMSettingsProv*" "$($sourceRoot)"
    cmd /c xcopy /herky "C:\Windows\System32\wbem\DMWmiBridgeProv*" "$($sourceRoot)"

    $ACL = Get-ACL "$sourceRoot\cimwin32.dll"
    Set-Acl -Path "$sourceRoot\MDMAppProv.dll" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\MDMSettingsProv.dll" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\DMWmiBridgeProv.dll" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\DMWmiBridgeProv1.dll" -AclObject $ACL

    $ACL = Get-ACL "$sourceRoot\cimwin32.mof"
    Set-Acl -Path "$sourceRoot\MDMAppProv.mof" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\MDMSettingsProv.mof" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\DMWmiBridgeProv.mof" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\DMWmiBridgeProv1.mof" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\MDMAppProv_Uninstall.mof" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\MDMSettingsProv_Uninstall.mof" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\DMWmiBridgeProv_Uninstall.mof" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\DMWmiBridgeProv1_Uninstall.mof" -AclObject $ACL

    $ACL = Get-ACL "$sourceRoot\en-US\cimwin32.mfl"
    Set-Acl -Path "$sourceRoot\en-US\MDMAppProv.mfl" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\en-US\MDMSettingsProv.mfl" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\en-US\MDMAppProv_Uninstall.mfl" -AclObject $ACL
    Set-Acl -Path "$sourceRoot\en-US\MDMSettingsProv_Uninstall.mfl" -AclObject $ACL

    $sourceRoot = "C:\AlyaADKpe\mount\Alya"
    if (-Not (Test-Path $sourceRoot))
    {
        $tmp = New-Item -Path $sourceRoot -ItemType Directory -Force
    }
    if (-Not (Test-Path "$sourceRoot\data"))
    {
        $tmp = New-Item -Path "$sourceRoot\data" -ItemType Directory -Force
    }
    cmd /c robocopy "$($AlyaRoot)" "$($sourceRoot)" /MIR /XF 9*.cmd /XF .gitignore /XD data /XD .git /XD WVD /XD Solutions /XD _logs /XD _local /XD _temp /XD tools
    cmd /c copy /y "$($AlyaData)\ConfigureEnv.ps1" "$($sourceRoot)\data"
    cmd /c copy /y "$($AlyaData)\GlobalConfig.json" "$($sourceRoot)\data"

    $sourceRoot = "C:\AlyaADKpe\mount\Alya\tools\WindowsPowerShell"
    if (-Not (Test-Path $sourceRoot))
    {
        $tmp = New-Item -Path $sourceRoot -ItemType Directory -Force
    }
    if (-Not (Test-Path "$($sourceRoot)\Scripts"))
    {
        $tmp = New-Item -Path "$($sourceRoot)\Scripts" -ItemType Directory -Force
    }
    if (-Not (Test-Path "$($sourceRoot)\Modules"))
    {
        $tmp = New-Item -Path "$($sourceRoot)\Modules" -ItemType Directory -Force
    }
    Save-Module -Name PackageManagement -Path "$($sourceRoot)\Modules" -Force
    Save-Module -Name PowershellGet -Path "$($sourceRoot)\Modules" -Force
    Save-Module -Name Microsoft.Graph.Intune -Path "$($sourceRoot)\Modules" -Force
    Save-Module -Name WindowsAutopilotIntune -Path "$($sourceRoot)\Modules" -Force
    Save-Module -Name PSWindowsUpdate -Path "$($sourceRoot)\Modules" -Force
    Save-Module -Name AzureAD -Path "$($sourceRoot)\Modules" -Force
    Save-Script -Name Get-WindowsAutoPilotInfo -Path "$($sourceRoot)\Scripts" -Force

    cmd /c Dism /image:mount /Set-AllIntl:en-US
    cmd /c Dism /image:mount /Set-InputLocale:0409:00000807

    #Create init script
    $initScript = @"
powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
wpeutil initializenetwork
wpeutil disablefirewall
"@
<#
netsh int ip set addr Eth static 192.168.2.15 255.255.255.0 192.168.2.1
net start dnscache
netsh int ip set dns Eth static 192.168.20.1 primary
#>
    $initScript | Set-Content -Path "C:\AlyaADKpe\mount\Alya\80_Init.cmd" -Encoding Ascii

    #Register MDM CIM providers
    $providerRegFile = @"
Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\CLSID]

; %systemroot%\system32\wbem\MDMAppProv.dll

[HKEY_CLASSES_ROOT\CLSID\{6E7E2EF2-F881-472A-8E32-17CA95710402}]
@="MDM Enterprise Application Provider"

[HKEY_CLASSES_ROOT\CLSID\{6E7E2EF2-F881-472A-8E32-17CA95710402}\InprocServer32]
@=hex(2):25,00,73,00,79,00,73,00,74,00,65,00,6d,00,72,00,6f,00,6f,00,74,00,25,\
  00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,77,00,62,00,\
  65,00,6d,00,5c,00,4d,00,44,00,4d,00,41,00,70,00,70,00,50,00,72,00,6f,00,76,\
  00,2e,00,64,00,6c,00,6c,00,00,00
"ThreadingModel"="Both"

; %systemroot%\system32\wbem\MDMSettingsProv.dll

[HKEY_CLASSES_ROOT\CLSID\{8B19C1CD-C80C-4AEC-AAE2-4E39FEDD24D0}]
@="Microsoft Device Management Settings Provider"

[HKEY_CLASSES_ROOT\CLSID\{8B19C1CD-C80C-4AEC-AAE2-4E39FEDD24D0}\InprocServer32]
@=hex(2):25,00,73,00,79,00,73,00,74,00,65,00,6d,00,72,00,6f,00,6f,00,74,00,25,\
  00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,77,00,62,00,\
  65,00,6d,00,5c,00,4d,00,44,00,4d,00,53,00,65,00,74,00,74,00,69,00,6e,00,67,\
  00,73,00,50,00,72,00,6f,00,76,00,2e,00,64,00,6c,00,6c,00,00,00
"ThreadingModel"="Both"

; %systemroot%\system32\wbem\DMWmiBridgeProv.dll

[HKEY_CLASSES_ROOT\CLSID\{0E9847B3-13E8-44E6-9659-2B60A140A573}]
@="DM WMI Bridge Provider"

[HKEY_CLASSES_ROOT\CLSID\{0E9847B3-13E8-44E6-9659-2B60A140A573}\InprocServer32]
@=hex(2):25,00,73,00,79,00,73,00,74,00,65,00,6d,00,72,00,6f,00,6f,00,74,00,25,\
  00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,77,00,62,00,\
  65,00,6d,00,5c,00,44,00,4d,00,57,00,6d,00,69,00,42,00,72,00,69,00,64,00,67,\
  00,65,00,50,00,72,00,6f,00,76,00,2e,00,64,00,6c,00,6c,00,00,00
"ThreadingModel"="Both"

; %systemroot%\system32\wbem\DMWmiBridgeProv1.dll

[HKEY_CLASSES_ROOT\CLSID\{E17A999C-97F7-4213-BF6F-DE08E9D7ECF5}]
@="DM WMI Bridge Provider"

[HKEY_CLASSES_ROOT\CLSID\{E17A999C-97F7-4213-BF6F-DE08E9D7ECF5}\InprocServer32]
@=hex(2):25,00,73,00,79,00,73,00,74,00,65,00,6d,00,72,00,6f,00,6f,00,74,00,25,\
  00,5c,00,73,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,77,00,62,00,\
  65,00,6d,00,5c,00,44,00,4d,00,57,00,6d,00,69,00,42,00,72,00,69,00,64,00,67,\
  00,65,00,50,00,72,00,6f,00,76,00,31,00,2e,00,64,00,6c,00,6c,00,00,00
"ThreadingModel"="Both"
"@
    $providerRegFile | Set-Content -Path "C:\AlyaADKpe\mount\Alya\81_RegisterProviders.reg" -Encoding Ascii

    $providerRegistration = @"
net stop winmgmt

regsvr32 /s %systemroot%\system32\wbem\MDMAppProv.dll
regsvr32 /s %systemroot%\system32\wbem\MDMSettingsProv.dll
regsvr32 /s %systemroot%\system32\wbem\DMWmiBridgeProv.dll
regsvr32 /s %systemroot%\system32\wbem\DMWmiBridgeProv1.dll
rem start %~dp081_RegisterProviders.reg

net start winmgmt

mofcomp %systemroot%\system32\wbem\MDMAppProv.mof
mofcomp %systemroot%\system32\wbem\MDMSettingsProv.mof
mofcomp %systemroot%\system32\wbem\DMWmiBridgeProv.mof
mofcomp %systemroot%\system32\wbem\DMWmiBridgeProv1.mof

mofcomp %systemroot%\system32\wbem\en-US\MDMAppProv.mfl
mofcomp %systemroot%\system32\wbem\en-US\MDMSettingsProv.mfl

mofcomp %systemroot%\system32\wbem\MDMAppProv_Uninstall.mof
mofcomp %systemroot%\system32\wbem\MDMSettingsProv_Uninstall.mof
mofcomp %systemroot%\system32\wbem\DMWmiBridgeProv_Uninstall.mof
mofcomp %systemroot%\system32\wbem\DMWmiBridgeProv1_Uninstall.mof

mofcomp %systemroot%\system32\wbem\en-US\MDMAppProv_Uninstall.mfl
mofcomp %systemroot%\system32\wbem\en-US\MDMSettingsProv_Uninstall.mfl

rem Register-CimProvider.exe -Namespace "root/cimv2/mdm" -ProviderName "MDMAppProv" -Path %systemroot%\system32\wbem\MDMAppProv.dll -Verbose -ForceUpdate
rem Register-CimProvider.exe -Namespace "root/cimv2/mdm" -ProviderName "MDMSettingsProv" -Path %systemroot%\system32\wbem\MDMSettingsProv.dll -Verbose -ForceUpdate
rem Register-CimProvider.exe -Namespace "root/cimv2/mdm/dmmap" -ProviderName "DMWmiBridgeProv" -Path %systemroot%\system32\wbem\DMWmiBridgeProv.dll -Verbose -ForceUpdate
rem other params: -Impersonation True -HostingModel LocalServiceHost -SupportWQL
"@
    $providerRegistration | Set-Content -Path "C:\AlyaADKpe\mount\Alya\81_RegisterProviders.cmd" -Encoding Ascii
    
    #Create PowerShell script
    $startPowerShellScript = @"
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& {Start-Process PowerShell -ArgumentList 'Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force' -Verb RunAs}"
set PSModulePath=%SystemDrive%\Alya\tools\WindowsPowerShell\modules;%PSModulePath%
set Path=%SystemDrive%\Alya\tools\WindowsPowerShell\scripts;%Path%
PowerShell
"@
    $startPowerShellScript | Set-Content -Path "C:\AlyaADKpe\mount\Alya\82_StartPowerShell.cmd" -Encoding Ascii

    #Create autopilot script
    $startAutopilotScript = @"
PowerShell -NoProfile -ExecutionPolicy Bypass -Command "& '\Alya\scripts\intune\Get-AutopilotDeviceInfos.ps1'"
"@
    $startAutopilotScript | Set-Content -Path "C:\AlyaADKpe\mount\Alya\83_GetAutopilotDeviceInfos.cmd" -Encoding Ascii
    
    #Create images finder script
    $imagesFinder = @"
@echo Find a drive that has a folder titled Images.
@for %%a in (C D E F G H I J K L M N O P Q R S T U V W X Y Z) do @if exist %%a:\Images\ set IMAGESDRIVE=%%a
@echo The Images folder is on drive: %IMAGESDRIVE%
@dir %IMAGESDRIVE%:\Images /w
"@
    $imagesFinder | Set-Content -Path "C:\AlyaADKpe\mount\Alya\89_FindImages.cmd" -Encoding Ascii

    #wpeinit
    $Startnetcmd = @"
wpeinit
"@
    $Startnetcmd | Set-Content -Path "C:\AlyaADKpe\mount\Windows\System32\startnet.cmd" -Encoding Ascii

    #Launch powershell on start
    $Winpeshlini = @"
[LaunchApp]
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
"@
    $Winpeshlini | Set-Content -Path "C:\AlyaADKpe\mount\Windows\System32\winpeshl.ini" -Encoding Ascii
    $ACL = Get-ACL "C:\AlyaADKpe\mount\Windows\System32\startnet.cmd"
    Set-Acl -Path "C:\AlyaADKpe\mount\Windows\System32\winpeshl.ini" -AclObject $ACL

    #Set the background image
    $ACL = Get-ACL "C:\AlyaADKpe\mount\Windows\System32\WinPE.jpg"
    $Group = New-Object System.Security.Principal.NTAccount("Builtin", "Administrators")
    $ACL.SetOwner($Group)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($Group,"FullControl","None","None","Allow")
    $acl.SetAccessRule($rule)
    Set-Acl -Path "C:\AlyaADKpe\mount\Windows\System32\WinPE.jpg" -AclObject $ACL
    Copy-Item -Path $AlyaWinPEBackgroundJpgImage -Destination "C:\AlyaADKpe\mount\Windows\System32\WinPE.jpg" -Force

    Write-Host "Getting actual features"
    cmd /c Dism /Image:mount /Get-Features

    Write-Host "Commiting image"
    #cmd /c Dism /unmount-image /MountDir:mount /discard
    cmd /c Dism /unmount-image /MountDir:mount /commit

    Write-Host "Building iso"
    $actPref = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    cmd /c MakeWinPEMedia /iso /f "$adkAutopilot" "$adkAutopilotIso"
    $ErrorActionPreference = $actPref
    Pop-Location

    if (-Not (Test-Path $($adkAutopilotIso)))
    {
        Write-Error "Could not create iso image" -ErrorAction Continue
        Exit 92
    }
}

Write-Host "Writing iso image to usb stick" -ForegroundColor $CommandInfo
$disk = Get-Disk | Where-Object BusType -eq USB | Out-GridView -Title 'Select USB Drive to use' -OutputMode Single
if ($disk)
{
    $res = $disk | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false -PassThru | New-Partition -UseMaximumSize -IsActive -AssignDriveLetter | Format-Volume -FileSystem NTFS
    cmd /c bootsect.exe /nt60 "$($res.DriveLetter):" /force /mbr
    $vol = Mount-DiskImage -ImagePath $adkAutopilotIso -StorageType ISO -PassThru | Get-DiskImage | Get-Volume
    cmd /c xcopy /herky "$($vol.DriveLetter):\*.*" "$($res.DriveLetter):\"
    Dismount-DiskImage -ImagePath $adkAutopilotIso
}
else
{
    Write-Warning "No disk selected!"
    Write-Warning "If there was no selection dialog, we were not able to recognise your usb stick"
}
if ((Test-Path "C:\AlyaADKpe"))
{
    cmd /c rmdir "C:\AlyaADKpe"
}

#Stopping Transscript
Stop-Transcript