#Requires -Version 2.0
#Requires -RunAsAdministrator

<#
    Copyright (c) Alya Consulting, 2019-2023

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
    18.05.2021 Konrad Brunner       Initial Version

    #Script from https://purple.telstra.com.au/blog/zero-touch-bitlocker-with-powershell

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\client\os\Enable-BitLocker-$($AlyaTimeString).log" | Out-Null

#Check BitLocker prerequisites
$TPMNotEnabled = Get-WmiObject win32_tpm -Namespace root\cimv2\security\microsofttpm | Where-Object {$_.IsEnabled_InitialValue -eq $false} -ErrorAction SilentlyContinue
$TPMEnabled = Get-WmiObject win32_tpm -Namespace root\cimv2\security\microsofttpm | Where-Object {$_.IsEnabled_InitialValue -eq $true} -ErrorAction SilentlyContinue
$WindowsVer = Get-WmiObject -Query 'select * from Win32_OperatingSystem where (Version like "6.2%" or Version like "6.3%" or Version like "10.0%") and ProductType = "1"' -ErrorAction SilentlyContinue
$BitLockerReadyDrive = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
$BitLockerDecrypted = Get-BitLockerVolume -MountPoint $env:SystemDrive | Where-Object {$_.VolumeStatus -eq "FullyDecrypted"} -ErrorAction SilentlyContinue
$BLVS = Get-BitLockerVolume | Where-Object {$_.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'}} -ErrorAction SilentlyContinue
$IsInDomain = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain

#Check AD connection
if (-Not $IsInDomain -or "\\$($env:COMPUTERNAME)" -eq "$($env:LOGONSERVER)")
{
    throw "This script only works on a domain joined pc"
}
$HasDomainConnection = Test-ComputerSecureChannel
if (-Not $HasDomainConnection)
{
    throw "Not able to connect the domain"
}

#Step 1 - Check if TPM is enabled and initialise if required
if ($WindowsVer -and !$TPMNotEnabled)
{
    Initialize-Tpm -AllowClear -AllowPhysicalPresence -ErrorAction SilentlyContinue
}

#Step 2 - Check if BitLocker volume is provisioned and partition system drive for BitLocker if required
if ($WindowsVer -and $TPMEnabled -and !$BitLockerReadyDrive)
{
    Get-Service -Name defragsvc -ErrorAction SilentlyContinue | Set-Service -Status Running -ErrorAction SilentlyContinue
    BdeHdCfg -target $env:SystemDrive shrink -quiet
}

#Step 3 - Check BitLocker AD Key backup Registry values exist and if not, create them.
$BitLockerRegLoc = 'HKLM:\SOFTWARE\Policies\Microsoft'
if (Test-Path "$BitLockerRegLoc\FVE")
{
  Write-Verbose '$BitLockerRegLoc\FVE Key already exists' -Verbose
}
else
{
  New-Item -Path "$BitLockerRegLoc" -Name 'FVE'
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'ActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'ActiveDirectoryInfoToStore' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'EncryptionMethod' -Value '00000003' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'EncryptionMethodNoDiffuser' -Value '00000003' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'EncryptionMethodWithXtsFdv' -Value '00000006' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'EncryptionMethodWithXtsOs' -Value '00000006' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'EncryptionMethodWithXtsRdv' -Value '00000003' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVActiveDirectoryInfoToStore' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVEncryptionType' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVHideRecoveryPage' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVManageDRA' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVRecovery' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVRecoveryKey' -Value '00000002' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVRecoveryPassword' -Value '00000002' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVRequireActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSActiveDirectoryInfoToStore' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSAllowSecureBootForIntegrity' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSEncryptionType' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSHideRecoveryPage' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSManageDRA' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSRecovery' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSRecoveryKey' -Value '00000002' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSRecoveryPassword' -Value '00000002' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSRequireActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'RDVActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'RDVActiveDirectoryInfoToStore' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'RDVHideRecoveryPage' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'RDVManageDRA' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'RDVRecovery' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'RDVRecoveryKey' -Value '00000002' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'RDVRecoveryPassword' -Value '00000002' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'RDVRequireActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'RequireActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
}

#Step 4 - If all prerequisites are met, then enable BitLocker
if ($WindowsVer -and $TPMEnabled -and $BitLockerReadyDrive -and $BitLockerDecrypted) 
{
    Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector
    Enable-BitLocker -MountPoint $env:SystemDrive -RecoveryPasswordProtector -ErrorAction SilentlyContinue
}

#Step 5 - Backup BitLocker recovery passwords to AD
if ($BLVS) 
{
    ForEach ($BLV in $BLVS) 
    {
        $Key = $BLV | Select-Object -ExpandProperty KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'}
        ForEach ($obj in $key)
        { 
            Backup-BitLockerKeyProtector -MountPoint $BLV.MountPoint -KeyProtectorID $obj.KeyProtectorId
        }
    }
}
#Stopping Transscript
Stop-Transcript
