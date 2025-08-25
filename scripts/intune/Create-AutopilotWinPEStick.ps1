#Requires -Version 2.0
#Requires -RunAsAdministrator

<#
    Copyright (c) Alya Consulting, 2019-2025

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
    $null = New-Item -Path "$($AlyaTools)\ADK" -ItemType Directory -Force
}

Write-Host "Checking AlyaADK" -ForegroundColor $CommandInfo
if (-Not (Test-Path "C:\AlyaADK"))
{
    Write-Host "Creating C:\AlyaADK"
    $null = New-Item -Path "C:\AlyaADK" -ItemType Directory -Force
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
        cmd /c "$($AlyaTools)\ADK\adksetup.exe" /quiet /layout "$($AlyaTemp)\ADKoffline"
        do
        {
            Start-Sleep -Seconds 5
            $process = Get-Process -Name "adksetup" -ErrorAction SilentlyContinue
        } while ($process)
    }

    Write-Host "Installing ADK"
    Push-Location -Path "$($AlyaTemp)\ADKoffline"
    cmd /c ".\adksetup.exe" /quiet /installpath "C:\AlyaADK" /features OptionId.DeploymentTools
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
        cmd /c "$($AlyaTools)\ADK\adkwinpesetup.exe" /quiet /layout "$($AlyaTemp)\ADKPEoffline"
        do
        {
            Start-Sleep -Seconds 5
            $process = Get-Process -Name "adkwinpesetup" -ErrorAction SilentlyContinue
        } while ($process)
    }

    Write-Host "Installing WinPE"
    Push-Location -Path "$($AlyaTemp)\ADKPEoffline"
    cmd /c ".\adkwinpesetup.exe" /quiet /installpath "C:\AlyaADK" /features OptionId.WindowsPreinstallationEnvironment
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
        $null = Remove-Item -Path $($adkAutopilot) -Recurse -Force
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
        $null = New-Item -Path $sourceRoot -ItemType Directory -Force
    }
    if (-Not (Test-Path "$sourceRoot\data"))
    {
        $null = New-Item -Path "$sourceRoot\data" -ItemType Directory -Force
    }
    cmd /c robocopy "$($AlyaRoot)" "$($sourceRoot)" /MIR /XF 9*.cmd /XF .gitignore /XD data /XD .git /XD WVD /XD Solutions /XD _logs /XD _local /XD _temp /XD tools
    cmd /c copy /y "$($AlyaData)\ConfigureEnv.ps1" "$($sourceRoot)\data"
    cmd /c copy /y "$($AlyaData)\GlobalConfig.json" "$($sourceRoot)\data"

    $sourceRoot = "C:\AlyaADKpe\mount\Alya\tools\WindowsPowerShell"
    if (-Not (Test-Path $sourceRoot))
    {
        $null = New-Item -Path $sourceRoot -ItemType Directory -Force
    }
    if (-Not (Test-Path "$($sourceRoot)\Scripts"))
    {
        $null = New-Item -Path "$($sourceRoot)\Scripts" -ItemType Directory -Force
    }
    if (-Not (Test-Path "$($sourceRoot)\Modules"))
    {
        $null = New-Item -Path "$($sourceRoot)\Modules" -ItemType Directory -Force
    }
    Save-Module -Name PackageManagement -Path "$($sourceRoot)\Modules" -Force
    Save-Module -Name PowershellGet -Path "$($sourceRoot)\Modules" -Force
    Save-Module -Name Microsoft.Graph.Beta.Intune -Path "$($sourceRoot)\Modules" -Force
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
$disk = $null
$usbDisk = Get-Disk | Where-Object BusType -eq USB
switch (($usbDisk | Measure-Object | Select-Object Count).Count)
{
    1 {
        $disk = $usbDisk[0]
    }
    {$_ -gt 1} {
        $disk = Get-Disk | Where-Object BusType -eq USB | Out-GridView -Title 'Select USB Drive to use' -OutputMode Single
    }
}
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
    Write-Warning "No stick selected or detected!"
}
if ((Test-Path "C:\AlyaADKpe"))
{
    cmd /c rmdir "C:\AlyaADKpe"
}

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA7UyyGwO0s3Unp
# ihGIh92wPIt7YZTq8/7M73h4xvOjCaCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDCjuDGjuxOV7dX3H
# 9DANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjUwMjEzMTYxODAwWhcNMjgwMjA1MDgyNzE5WjCC
# ATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQFEw9DSEUt
# MjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEEAYI3PAIB
# AhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYwFAYDVQQH
# Ew1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoGA1UEChMj
# QWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNVBAMTI0Fs
# eWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZIhvcNAQkB
# FhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAqrm7S5R5kmdYT3Q2wIa1m1BQW5EfmzvCg+WYiBY94XQTAxEACqVq
# 4+3K/ahp+8c7stNOJDZzQyLLcZvtLpLmkj4ZqwgwtoBrKBk3ofkEMD/f46P2Iuky
# tvmyUxdM4730Vs6mRvQP+Y6CfsUrWQDgJkiGTldCSH25D3d2eO6PeSdYTA3E3kMH
# BiFI3zxgCq3ZgbdcIn1bUz7wnzxjuAqI7aJ/dIBKDmaNR0+iIhrCFvhDo6nZ2Iwj
# 1vAQsSHlHc6SwEvWfNX+Adad3cSiWfj0Bo0GPUKHRayf2pkbOW922shL1yf/30OV
# yct8rPkMrIKzQhog2R9qJrKJ2xUWwEwiSblWX4DRpdxOROS5PcQB45AHhviDcudo
# 30gx8pjwTeCVKkG2XgdqEZoxdAa4ospWn3va+Dn6OumYkUQZ1EkVhDfdsbCXAJvY
# NCbOyx5tPzeZEFP19N5edi6MON9MC/5tZjpcLzsQUgIbHqFfZiQTposx/j+7m9WS
# aK0cDBfYKFOVQJF576yeWaAjMul4gEkXBn6meYNiV/iL8pVcRe+U5cidmgdUVveo
# BPexERaIMz/dIZIqVdLBCgBXcHHoQsPgBq975k8fOLwTQP9NeLVKtPgftnoAWlVn
# 8dIRGdCcOY4eQm7G4b+lSili6HbU+sir3M8pnQa782KRZsf6UruQpqsCAwEAAaOC
# AdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYB
# BQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2Nj
# cjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3Nw
# Lmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAE
# TjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9i
# YWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1Ud
# HwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVl
# dmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFjb25zdWx0
# aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd0PxZCYZj
# xezzsRM7VxwDkjYRMB0GA1UdDgQWBBT5XqSepeGcYSU4OKwKELHy/3vCoTANBgkq
# hkiG9w0BAQsFAAOCAgEAlSgt2/t+Z6P9OglTt1+sobomrQT0Mb97lGDQZpE364hO
# TSYkbcqxlRXZ+aINgt2WEe7GPFu+6YoZimCPV4sOfk5NZ6I3ZU+uoTsoVYpQr3Io
# zYLLNMWEK2WswPHcxx34Il6F59V/wP1RdB73g+4ZprkzsYNqQpXMv3yoDsPU9IHP
# /w3jQRx6Maqlrjn4OCaE3f6XVxDRHv/iFnipQfXUqY2dV9gkoiYL3/dQX6ibUXqj
# Xk6trvZBQr20M+fhhFPYkxfLqu1WdK5UGbkg1MHeWyVBP56cnN6IobNpHbGY6Eg0
# RevcNGiYFZsE9csZPp855t8PVX1YPewvDq2v20wcyxmPcqStJYLzeirMJk0b9UF2
# hHmIMQRuG/pjn2U5xYNp0Ue0DmCI66irK7LXvziQjFUSa1wdi8RYIXnAmrVkGZj2
# a6/Th1Z4RYEIn1Pc/F4yV9OJAPYN1Mu1LuRiaHDdE77MdhhNW2dniOmj3+nmvWbZ
# fNAI17VybYom4MNB1Cy2gm2615iuO4G6S6kdg8fTaABRh78i8DIgT6LL/yMvbDOH
# hREfFUfowgkx9clsBF1dlAG357pYgAsbS/hqTS0K2jzv38VbhMVuWgtHdwO39ACa
# udnXvAKG9w50/N0DgI54YH/HKWxVyYIltzixRLXN1l+O5MCoXhofW4QhtrofETAx
# ghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25p
# bmcgQ0EgMjAyMAIMKO4MaO7E5Xt1fcf0MA0GCWCGSAFlAwQCAQUAoHwwEAYKKwYB
# BAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIA02U4O2B7NGL8U9
# ME7SKM/JXvL0y2qQlGxbX1BxNjB4MA0GCSqGSIb3DQEBAQUABIICAC8/uD5cS2FS
# YHPr7OkqJUcWDic/FOG6sl+VXH9+Ub1W7nuKlW2EtAHDGuXpJIW4w9caDYKrFOkc
# +dt8xedzeZoJ/Q9VB11mr8CEzKpKT45MOd3wBhjMJodDhQYlWALFfVM48vKyV1fN
# OsT0lK/kVJcDIDsyaGdaBkX+y5E55AGYFCo5Jsg5GaewhcVTjhMw3Q7aWq4Tl20J
# 6epkTlHQuF+fvCoOY5B7FRiIYVQMKnOQ1VfQstZ+S/DSocOmCpJXXjnt+ey3kmmz
# OYybtLf+naJFtCd3u7eOiw69hdgtaBA0uU+U8Vc4g0bpL++Tji9wNPfrkV2Qdqa2
# 1sVismupNfc7xMoAa2qQsRVpGkv+lNjXfoi3PV5xVvcYSj7uChAd6tLs7A/0qG6e
# 38bzzqQho6BLI8yWNfGUMYsuLoaVPY46SFkjsx2DgpvPl6x+xPXLq0rdYNiaZe2F
# TBOqUY7RJvgjs7yff8bFfVRyYaBwI3lG+J4yrmflu9Qxoz8T5gGW0ibWwlFf2H/9
# NKxd3CUUZivQK1sBbHSEEKlHsJjm8EHwi6ghes3/pnHOY8mThywEXLtUl7jzjM++
# gnOVEht0vWcdLJWk8h3CZ6OiKSjUgPf1scA4kbBFT++o6o7lfFug6hLlMGRiqi54
# HUkL6u6Dj9dVQIq+wxLjo6MJaZVAxUAtoYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCAtSX2LWtiFYP6e502WaPmKqaQHiyO4or6LEJo1R3K3SQIUMfWnJT1eSVVb
# prtRZ/HBkzDNUHEYDzIwMjUwODI1MTUzODQ3WjADAgEBoFikVjBUMQswCQYDVQQG
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
# ID0wi8PY3Y8M7R9EN3WGfBrynw5RX8y3zbdqOgkxaVVCMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGATpE9CwMWvc3X
# NArjVsuWa6ssabmy1sg8ieJUXoVHvb9b4fuXyEfngc1jJU7EWa6V/nQYpsf3yKLP
# 6yDkz/qQYuULMu7xn5tJa0x/GepjBfd+NPRUjtH/fYuLg3Q6VEekVbWyVtX2PrWF
# wGGsib6qSsH1Y9vJwmQ6f8kSKudecEIGQAGNN0/Z3JzJdv2u7Q+hQdEOOCPrepl0
# l/8Qy9wAo1VH5tVy5DGiULrCIzQUAyiZTWXYGbtGqHWXRi85gOUHfA4KYomRdzUZ
# /Lbajytgoy4Q1ab6ZMipJGLHKUOLXBg9o5zvLsTznxOHTWOOSY+vXs8OfRd3iwOG
# 5XYX23j9Sb+rzDqGH+ywuTyPl8J8RpgnMlpcidBU6R/ncuALhdW3YU+0/2Kd3RbK
# Z/7X0WMalK7fFZ0K0ybfz19hPzIutFVXEAkCKJOxHHIDDqcCl3SAcYvFpoiSc4fh
# Fz8ZbV0pI9pEaUIfe+z3eFjhz2iJxo5404IuPv40if0ieHClW13e
# SIG # End signature block
