#Requires -Version 2.0
#Requires -RunAsAdministrator

<#
    Copyright (c) Alya Consulting, 2019-2026

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
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
    05.04.2026 Konrad Brunner       Initial Version

	https://support.microsoft.com/en-us/topic/how-to-manage-the-windows-boot-manager-revocations-for-secure-boot-changes-associated-with-cve-2023-24932-41a975df-beb2-40c1-99a3-b3ff139f832d#bkmk_mitigation_guidelines

#>

<#
.SYNOPSIS
Checks and validates installation and status of the Windows UEFI Secure Boot CA 2023 update.

.DESCRIPTION
The Check-CA2023Update.ps1 script verifies whether Secure Boot is enabled and ensures that the system has applied the Windows UEFI CA 2023 certificates update (KB5036210 or later). It collects extensive system and firmware details, checks registry values associated with Secure Boot, and analyzes system events related to Secure Boot updates (Event IDs 1801 and 1808). The script also manipulates registry values to trigger the update process, executes the Secure Boot update task, and validates if the UEFI Secure Boot database has been updated with the new CA certificates.

.INPUTS
None. The script does not accept piped input.

.OUTPUTS
Displays system, firmware, and Secure Boot configuration details to the console. Outputs also include recent Secure Boot-related system events, registry values, and verification results for UEFI certificates.

.EXAMPLE
PS> .\Check-CA2023Update.ps1
Runs the Secure Boot CA 2023 update verification, outputs current status, and applies pending updates if required.

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

#Reading configuration
. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\client\os\Check-CA2023Update-$($AlyaTimeString).log" | Out-Null

#Checking system information and prerequisites
$isSecureBootEnabled = Confirm-SecureBootUEFI
if (-Not $isSecureBootEnabled)
{
	throw "SecureBootUEFI is not enabled on this device!"
}

$taskPresent = Get-ScheduledTask -TaskName Secure-Boot-Update
if (-Not $taskPresent)
{
	throw "Looks like KB5036210 or later is not installed!"
}

$update = Get-Item -Path "C:\Windows\system32\SecureBootUpdates\DBUpdate3P2023.bin"
if (-Not $update)
{
	throw "Looks like DBUpdate3P2023 is not installed!"
}

Write-Warning "Please ensure that you have backed up your BitLocker recovery keys before proceeding, as Secure Boot updates can sometimes lead to BitLocker recovery mode on next reboot."
pause

$UEFISecureBootEnabled = try { (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State -Name UEFISecureBootEnabled -ErrorAction SilentlyContinue).UEFISecureBootEnabled } catch {}
$HighConfidenceOptOut = try { (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot -Name HighConfidenceOptOut -ErrorAction SilentlyContinue).HighConfidenceOptOut } catch {}
$AvailableUpdates = try { (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot -Name AvailableUpdates -ErrorAction SilentlyContinue).AvailableUpdates } catch {}
$UEFICA2023Status = try { (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing -Name UEFICA2023Status -ErrorAction SilentlyContinue).UEFICA2023Status } catch {}
$WindowsUEFICA2023Capable = try { (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing -Name WindowsUEFICA2023Capable -ErrorAction SilentlyContinue).WindowsUEFICA2023Capable } catch {}
$UEFICA2023Error = try { (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing -Name UEFICA2023Error -ErrorAction SilentlyContinue).UEFICA2023Error } catch {}
$OEMManufacturerName = try { (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes -Name OEMManufacturerName -ErrorAction SilentlyContinue).OEMManufacturerName } catch {}
$OEMModelSystemFamily = try { (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes -Name OEMModelSystemFamily -ErrorAction SilentlyContinue).OEMModelSystemFamily } catch {}
$OEMModelNumber = try { (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes -Name OEMModelNumber -ErrorAction SilentlyContinue).OEMModelNumber } catch {}
$FirmwareVersion = try { (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes -Name FirmwareVersion -ErrorAction SilentlyContinue).FirmwareVersion } catch {}
$FirmwareReleaseDate = try { (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes -Name FirmwareReleaseDate -ErrorAction SilentlyContinue).FirmwareReleaseDate } catch {}
$OSArchitecture = try { (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes -Name OSArchitecture -ErrorAction SilentlyContinue).OSArchitecture } catch {}
$CanAttemptUpdateAfter = try { (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing\DeviceAttributes -Name CanAttemptUpdateAfter -ErrorAction SilentlyContinue).CanAttemptUpdateAfter } catch {}
$HostName = (Get-CIMInstance Win32_ComputerSystem).Name
$OSVersion = (Get-CimInstance Win32_OperatingSystem).Version
$Manufacturer = (Get-CIMInstance Win32_ComputerSystem).Manufacturer
$Model = (Get-CIMInstance Win32_ComputerSystem).Model
$BiosSerialNumber = (Get-CIMInstance Win32_BIOS).SerialNumber
$BiosVersion = (Get-CIMInstance Win32_BIOS).Version
$BaseBoardManufacturer = (Get-CimInstance Win32_BaseBoard).Manufacturer
$BaseBoardSerialNumber = (Get-CimInstance Win32_BaseBoard).SerialNumber
$BaseBoardProduct = (Get-CIMInstance Win32_BaseBoard).Product
$TpmVersion = (tpmtool getdeviceinformation | Where-Object { $_ -like "*TPM-Version*" }).Split()[-1]

Write-Host "`nSystem information"
Write-Host "==============================================="
Write-Host "UEFISecureBootEnabled: $UEFISecureBootEnabled"
Write-Host "HighConfidenceOptOut: $HighConfidenceOptOut"
Write-Host "AvailableUpdates: $AvailableUpdates"
Write-Host "UEFICA2023Status: $UEFICA2023Status"
Write-Host "WindowsUEFICA2023Capable: $WindowsUEFICA2023Capable"
Write-Host "UEFICA2023Error: $UEFICA2023Error"
Write-Host "OEMManufacturerName: $OEMManufacturerName"
Write-Host "OEMModelSystemFamily: $OEMModelSystemFamily"
Write-Host "OEMModelNumber: $OEMModelNumber"
Write-Host "FirmwareVersion: $FirmwareVersion"
Write-Host "FirmwareReleaseDate: $FirmwareReleaseDate"
Write-Host "OSArchitecture: $OSArchitecture"
Write-Host "CanAttemptUpdateAfter: $CanAttemptUpdateAfter"
Write-Host "HostName: $HostName"
Write-Host "OSVersion: $OSVersion"
Write-Host "Manufacturer: $Manufacturer"
Write-Host "Model: $Model"
Write-Host "BiosSerialNumber: $BiosSerialNumber"
Write-Host "BiosVersion: $BiosVersion"
Write-Host "BaseBoardManufacturer: $BaseBoardManufacturer"
Write-Host "BaseBoardSerialNumber: $BaseBoardSerialNumber"
Write-Host "BaseBoardProduct: $BaseBoardProduct"
Write-Host "TPMVersion: $TpmVersion"
#Get-ComputerInfo

if ($Manufacturer -like "*DELL*")
{
	Write-Host "`nKnown manufacturer exceptions"
	Write-Host "==============================================="
	Write-Warning "DELL system detected - please check DELL support site for latest UEFI firmware updates and apply them if available. DELL has been known to have issues with the Windows UEFI CA 2023 update on some models, and may require a firmware update to resolve compatibility issues. It's also possible that some settings have to be configured in the BIOS."
	pause
}
if ($Manufacturer -like "*HP*")
{
	Write-Host "`nKnown manufacturer exceptions"
	Write-Host "==============================================="
	Write-Warning "HP system detected - please check HP support site for latest UEFI firmware updates and apply them if available. HP has been known to have issues with the Windows UEFI CA 2023 update on some models, and may require a firmware update to resolve compatibility issues. It's also possible that some settings have to be configured in the BIOS."
	pause
}
if ($OSArchitecture -like "*ARM64*")
{
	Write-Host "`nKnown manufacturer exceptions"
	Write-Host "==============================================="
	Write-Warning "ARM64 system detected - please check your device manufacturer's support site for latest UEFI firmware updates and apply them if available. ARM64 devices have been known to have issues with the Windows UEFI CA 2023 update, and may require a firmware update to resolve compatibility issues. It's also possible that some settings have to be configured in the BIOS."
	Write-Warning "Do not continue this script on Qualcomm-based devices!"
	pause
}

Write-Host "`nChecking system events"
Write-Host "==============================================="
$allEventIds = @(1801,1808,1037,1042)
$events = @(Get-WinEvent -FilterHashtable @{LogName='System'; ID=$allEventIds} -MaxEvents 200 -ErrorAction SilentlyContinue)

$latest_1801_Event = $events | Where-Object {$_. ID -eq 1801} | Sort-Object TimeCreated -Descending | Select-Object -First 1
$latest_1808_Event = $events | Where-Object {$_. ID -eq 1808} | Sort-Object TimeCreated -Descending | Select-Object -First 1
$latest_1037_Event = $events | Where-Object {$_. ID -eq 1037} | Sort-Object TimeCreated -Descending | Select-Object -First 1
$latest_1042_Event = $events | Where-Object {$_. ID -eq 1042} | Sort-Object TimeCreated -Descending | Select-Object -First 1

$bootLoaderPending = $false
$zertPending = $true

if ($latest_1808_Event -and $latest_1037_Event -and $latest_1042_Event) {
	Write-Host "Ereignis 1808 gefunden - Zertifikate der Zertifizierungsstelle für den sicheren Start wurden aktualisiert"
	Write-Host "Ereignis 1037 gefunden - Das alte Zertifikat wurde aus dem UEFI Secure Boot DBX entfernt"
	Write-Host "Ereignis 1042 gefunden - Boot manager wurde aktualisiert"
	Write-Host "Ereigniszeit: $($latest_1808_Event.TimeCreated)"

	$zertPending = $false
	$bootLoaderPending = $false

	$errorMsg = ""
	if ([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI DB).Bytes) -notmatch 'Microsoft Option ROM UEFI CA 2023')
	{
		Write-Warning "Microsoft Option ROM UEFI CA 2023 certificate is not present in the UEFI Secure Boot ROM. Update may not have been applied successfully. On some systems (servers) this certificate is not available."
	}

	if ([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI DBX).Bytes) -notmatch 'Microsoft Windows Production PCA 2011')
	{
		$errorMsg += "`nMicrosoft Windows Production PCA 2011 certificate is not present in the UEFI Secure Boot DBX. Update may not have been applied successfully."
		$bootLoaderPending = $true
	}

	if ([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI DB).Bytes) -notmatch 'Windows UEFI CA 2023')
	{
		$errorMsg += "`nWindows UEFI CA 2023 certificate is not present in the UEFI Secure Boot DB. Update may not have been applied successfully."
		$zertPending = $true
	}

	if ([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI DB).Bytes) -notmatch 'Microsoft UEFI CA 2023')
	{
		$errorMsg += "`nMicrosoft UEFI CA 2023 certificate is not present in the UEFI Secure Boot DB. Update may not have been applied successfully."
		$zertPending = $true
	}

	if ([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI KEK).Bytes) -notmatch 'Microsoft Corporation KEK 2K CA 2023')
	{
		$errorMsg += "`nMicrosoft Corporation KEK 2K CA 2023 certificate is not present in the UEFI Secure Boot KEK. Update may not have been applied successfully."
		$zertPending = $true
	}

	if (-Not [string]::IsNullOrWhiteSpace($UEFICA2023Error))
	{
		$errorMsg += "`nUEFICA2023Error is set: $($UEFICA2023Error)."
		$zertPending = $true
	}

	$configQuery = (WinCsFlags.exe /query) -join "`n"
	if ($configQuery -notmatch 'Current Configuration: F33E0C8E002')
	{
		$errorMsg += "`nWindows UEFI CA 2023 update does not appear to have been applied successfully. Expected key 'F33E0C8E002' not found in WinCsFlags.exe /query output."
		$zertPending = $true
	}

	if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing").UEFICA2023Status -ne "Updated")
	{
		$errorMsg += "`nUEFICA2023Status registry value does not indicate 'Updated'. Update may not have been applied successfully."
		$zertPending = $true
	}

	mountvol s: /s | Out-Null
	if ((Get-AuthenticodeSignature "S:\EFI\Microsoft\Boot\bootmgfw.efi").SignerCertificate.Issuer -notmatch 'Windows UEFI CA 2023')
	{
		$errorMsg += "`nWindows UEFI CA 2023 certificate is not present in the boot manager. Update may not have been applied successfully."
		$bootLoaderPending = $true
	}
	if ((Get-AuthenticodeSignature "S:\EFI\Boot\bootx64.efi").SignerCertificate.Issuer -notmatch 'Windows UEFI CA 2023')
	{
		$errorMsg += "`nWindows UEFI CA 2023 certificate is not present in the boot manager. Update may not have been applied successfully."
		$bootLoaderPending = $true
	}
	mountvol s: /d | Out-Null

	if ([string]::IsNullOrWhiteSpace($errorMsg))
	{
		$errorMsg = "All checks passed - Secure Boot CA certificates appear to be updated successfully and boot manager has been replaced."
		exit
	}
	else
	{
		Write-Error $errorMsg -ErrorAction Continue
		Write-Warning "To retry an update, you have to comment out the 'exit 1' in this script"
		exit 1
	}

} elseif ($latest_1808_Event) {
	Write-Host "Ereignis 1808 gefunden - Zertifikate der Zertifizierungsstelle für den sicheren Start wurden aktualisiert"
	Write-Host "Ereignis 1037 aber nicht - Das alte Zertifikat wurde NOCH NICHT aus dem UEFI Secure Boot DBX entfernt und der boot loader wurde NOCH NICHT ersetzt"
	Write-Host "Ereigniszeit: $($latest_1808_Event.TimeCreated)"

	$zertPending = $false
	$bootLoaderPending = $true

	$errorMsg = ""
	if ([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI DB).Bytes) -notmatch 'Microsoft Option ROM UEFI CA 2023')
	{
		Write-Warning "Microsoft Option ROM UEFI CA 2023 certificate is not present in the UEFI Secure Boot ROM. Update may not have been applied successfully. On some systems (servers) this certificate is not available."
	}

	if ([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI DB).Bytes) -notmatch 'Windows UEFI CA 2023')
	{
		$errorMsg += "`nWindows UEFI CA 2023 certificate is not present in the UEFI Secure Boot DB. Update may not have been applied successfully."
		$zertPending = $true
	}

	if ([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI DB).Bytes) -notmatch 'Microsoft UEFI CA 2023')
	{
		$errorMsg += "`nMicrosoft UEFI CA 2023 certificate is not present in the UEFI Secure Boot DB. Update may not have been applied successfully."
		$zertPending = $true
	}

	if ([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI KEK).Bytes) -notmatch 'Microsoft Corporation KEK 2K CA 2023')
	{
		$errorMsg += "`nMicrosoft Corporation KEK 2K CA 2023 certificate is not present in the UEFI Secure Boot KEK. Update may not have been applied successfully."
		$zertPending = $true
	}

	if (-Not [string]::IsNullOrWhiteSpace($UEFICA2023Error))
	{
		$errorMsg += "`nUEFICA2023Error is set: $($UEFICA2023Error)."
		$zertPending = $true
	}

	$configQuery = (WinCsFlags.exe /query) -join "`n"
	if ($configQuery -notmatch 'Current Configuration: F33E0C8E002')
	{
		$errorMsg += "`nWindows UEFI CA 2023 update does not appear to have been applied successfully. Expected key 'F33E0C8E002' not found in WinCsFlags.exe /query output."
		$zertPending = $true
	}

	if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing").UEFICA2023Status -ne "Updated")
	{
		$errorMsg += "`nUEFICA2023Status registry value does not indicate 'Updated'. Update may not have been applied successfully."
		$zertPending = $true
	}

	if ([string]::IsNullOrWhiteSpace($errorMsg))
	{
		$errorMsg = "All checks passed - Secure Boot CA certificates appear to be updated successfully."
	}
	else
	{
		Write-Error $errorMsg -ErrorAction Continue
		Write-Warning "To retry an update, you have to comment out the 'exit 1' in this script"
		exit 1
	}

}

if ($zertPending) {

	Write-Warning "Kein Ereignis 1808 oder andere Probleme gefunden - Secure Boot CA Zertifikate sind noch nicht aktualisiert"
	if ($latest_1801_Event) {
		if ($latest_1801_Event.Message -match '(Hohe Zuverlässigkeit|Benötigt mehr Daten|Unbekannt|Angehalten|High Confidence|Needs More Data|Unknown|Paused)') { 
			$confidence = $matches[1]
			Write-Host "Vertrauen: $confidence"
		} else {
			Write-Host "Ereignis 1801 gefunden, aber Konfidenzwert nicht im erwarteten Format"
		}
	} else {
		Write-Host "Kein Ereignis 1801 gefunden"
	}

	Write-Warning "Starte Updateprozess: Neue Zertifikate installieren."

	Write-Host "Setze WinCsFlags auf F33E0C8E002"
	WinCsFlags.exe /apply --key "F33E0C8E002"

	$RegSecureBoot = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
	Write-Host "AvailableUpdates hat derzeit den Wert: 0x$($RegSecureBoot.AvailableUpdates.ToString("X"))"
	$RegValue = 0x0
	$RegValue += 0x0040 # add the Windows UEFI CA 2023 certificate to the Secure Boot DB.
	$RegValue += 0x0800 # apply the Microsoft Option ROM UEFI CA 2023 to the DB
	$RegValue += 0x1000 # apply the Microsoft UEFI CA 2023 to the DB
	$RegValue += 0x0004 # look for a Key Exchange Key signed by the device’s Platform Key (PK)
	$RegValue += 0x0100 # replaces the boot manager?
	$RegValue += 0x4000 # apply update only if 2011 certificate is trusted

	Write-Host "Setze AvailableUpdates auf: 0x$($RegValue.ToString("X"))"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "AvailableUpdates" -Value $RegValue

	$StartTimeStamp = (Get-Date).AddSeconds(-1)
	Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
	do {
		$task = Get-ScheduledTask -TaskName "Secure-Boot-Update"
		$task
		Start-Sleep -Seconds 20
	} while ( $task.State -eq "Running" )

	Get-WinEvent -FilterHashtable @{ProviderName='microsoft-windows-tpm-wmi'; StartTime=$StartTimeStamp } -ErrorAction SilentlyContinue | Format-Table -Wrap -AutoSize
	Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=$StartTimeStamp } -ErrorAction SilentlyContinue | Format-Table -Wrap -AutoSize

	$RegSecureBoot = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
	Write-Host "AvailableUpdates hat nun den Wert: 0x$($RegSecureBoot.AvailableUpdates.ToString("X"))"

	Write-Warning "Please reboot now and rerun this script to run the next step."
	pause

}

if ($bootLoaderPending) {

	Write-Warning "Starte Updateprozess: Altes Zertifikat entfernen."
	$RegSecureBoot = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
	Write-Host "AvailableUpdates hat derzeit den Wert: 0x$($RegSecureBoot.AvailableUpdates.ToString("X"))"
	$RegValue = 0x0
	$RegValue += 0x0080 # revoke old certificates.

	Write-Host "Setze AvailableUpdates auf: 0x$($RegValue.ToString("X"))"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "AvailableUpdates" -Value $RegValue

	$StartTimeStamp = (Get-Date).AddSeconds(-1)
	Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
	do {
		$task = Get-ScheduledTask -TaskName "Secure-Boot-Update"
		$task
		Start-Sleep -Seconds 20
	} while ( $task.State -eq "Running" )

	$events = @(Get-WinEvent -FilterHashtable @{LogName='System'; ID=$allEventIds; StartTime=$StartTimeStamp} -MaxEvents 200 -ErrorAction SilentlyContinue)
	$events | Format-Table -Wrap -AutoSize
	if (-Not $events -or @($events).Count -eq 0)
	{
		throw "No relevant events found in the System log after running the Secure Boot update task. This may indicate that the update process did not run successfully or that event logging is not working as expected."
	}
	if (@($events)[0].Message -notlike "*erfolgreich angewendet*")
	{
		throw "The most recent event in the System log after running the Secure Boot update task does not appear to be related to the Secure Boot update process. Please review the events above for any relevant information or errors."
	}

	$RegSecureBoot = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
	Write-Host "AvailableUpdates hat nun den Wert: 0x$($RegSecureBoot.AvailableUpdates.ToString("X"))"


	Write-Warning "Starte Updateprozess: Boot manager ersetzen."
	$RegSecureBoot = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
	Write-Host "AvailableUpdates hat derzeit den Wert: 0x$($RegSecureBoot.AvailableUpdates.ToString("X"))"
	$RegValue = 0x0
	$RegValue += 0x0200 # replace boot manager

	Write-Host "Setze AvailableUpdates auf: 0x$($RegValue.ToString("X"))"
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot" -Name "AvailableUpdates" -Value $RegValue

	$StartTimeStamp = (Get-Date).AddSeconds(-1)
	Start-ScheduledTask -TaskName "\Microsoft\Windows\PI\Secure-Boot-Update"
	do {
		$task = Get-ScheduledTask -TaskName "Secure-Boot-Update"
		$task
		Start-Sleep -Seconds 20
	} while ( $task.State -eq "Running" )

	$events = @(Get-WinEvent -FilterHashtable @{LogName='System'; ID=$allEventIds; StartTime=$StartTimeStamp} -MaxEvents 200 -ErrorAction SilentlyContinue)
	$events | Format-Table -Wrap -AutoSize
	if (-Not $events -or @($events).Count -eq 0)
	{
		throw "No relevant events found in the System log after running the Secure Boot update task. This may indicate that the update process did not run successfully or that event logging is not working as expected."
	}
	if (@($events)[0].Message -notlike "*erfolgreich angewendet*")
	{
		throw "The most recent event in the System log after running the Secure Boot update task does not appear to be related to the Secure Boot update process. Please review the events above for any relevant information or errors."
	}

	$RegSecureBoot = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"
	Write-Host "AvailableUpdates hat nun den Wert: 0x$($RegSecureBoot.AvailableUpdates.ToString("X"))"

	Write-Warning "Please reboot now and rerun this script to check if the update process has completed successfully."
	pause
	
}

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIvCQYJKoZIhvcNAQcCoIIu+jCCLvYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCwb+dWGEdZD92a
# qgV/n7ITsjwRT8qTA8S7AwaSCOTeEqCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
# Qc9vAbjutKlUMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24g
# Um9vdCBDQSAtIFIzMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9i
# YWxTaWduMB4XDTIwMDcyODAwMDAwMFoXDTI5MDMxODAwMDAwMFowUzELMAkGA1UE
# BhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2Jh
# bFNpZ24gQ29kZSBTaWduaW5nIFJvb3QgUjQ1MIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAti3FMN166KuQPQNysDpLmRZhsuX/pWcdNxzlfuyTg6qE9aND
# m5hFirhjV12bAIgEJen4aJJLgthLyUoD86h/ao+KYSe9oUTQ/fU/IsKjT5GNswWy
# KIKRXftZiAULlwbCmPgspzMk7lA6QczwoLB7HU3SqFg4lunf+RuRu4sQLNLHQx2i
# CXShgK975jMKDFlrjrz0q1qXe3+uVfuE8ID+hEzX4rq9xHWhb71hEHREspgH4nSr
# /2jcbCY+6R/l4ASHrTDTDI0DfFW4FnBcJHggJetnZ4iruk40mGtwEd44ytS+ocCc
# 4d8eAgHYO+FnQ4S2z/x0ty+Eo7+6CTc9Z2yxRVwZYatBg/WsHet3DUZHc86/vZWV
# 7Z0riBD++ljop1fhs8+oWukHJZsSxJ6Acj2T3IyU3ztE5iaA/NLDA/CMDNJF1i7n
# j5ie5gTuQm5nfkIWcWLnBPlgxmShtpyBIU4rxm1olIbGmXRzZzF6kfLUjHlufKa7
# fkZvTcWFEivPmiJECKiFN84HYVcGFxIkwMQxc6GYNVdHfhA6RdktpFGQmKmgBzfE
# ZRqqHGsWd/enl+w/GTCZbzH76kCy59LE+snQ8FB2dFn6jW0XMr746X4D9OeHdZrU
# SpEshQMTAitCgPKJajbPyEygzp74y42tFqfT3tWbGKfGkjrxgmPxLg4kZN8CAwEA
# AaOCAXcwggFzMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzAP
# BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQfAL9GgAr8eDm3pbRD2VZQu86WOzAf
# BgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpjmove4t0bvDB6BggrBgEFBQcBAQRuMGww
# LQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL3Jvb3RyMzA7
# BggrBgEFBQcwAoYvaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# cm9vdC1yMy5jcnQwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxz
# aWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggrBgEF
# BQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJ
# KoZIhvcNAQEMBQADggEBAKz3zBWLMHmoHQsoiBkJ1xx//oa9e1ozbg1nDnti2eEY
# XLC9E10dI645UHY3qkT9XwEjWYZWTMytvGQTFDCkIKjgP+icctx+89gMI7qoLao8
# 9uyfhzEHZfU5p1GCdeHyL5f20eFlloNk/qEdUfu1JJv10ndpvIUsXPpYd9Gup7EL
# 4tZ3u6m0NEqpbz308w2VXeb5ekWwJRcxLtv3D2jmgx+p9+XUnZiM02FLL8Mofnre
# kw60faAKbZLEtGY/fadY7qz37MMIAas4/AocqcWXsojICQIZ9lyaGvFNbDDUswar
# AGBIDXirzxetkpNiIHd1bL3IMrTcTevZ38GQlim9wX8wggboMIIE0KADAgECAhB3
# vQ4Ft1kLth1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENv
# ZGUgU2lnbmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAw
# MDBaMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIw
# MAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAy
# MDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj
# /SBerjgSi8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlM
# g7BKRFAEeIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRV
# X5YLEeWatSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV
# 0xHK5s2zBZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEz
# IHXMsdXtHQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMk
# oog28vmfvpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq
# 7rfYrWGlr3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult
# 5a/dm2tjIF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNu
# twFsDeCXpxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYy
# AjIwfLWTyCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofn
# GrhO7izB36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
# FgQUJZ3Q/FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0
# Q9lWULvOljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8v
# b2NzcC5nbG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUH
# MAKGOmh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWdu
# aW5ncm9vdHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJ
# KwYBBAGgMgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24u
# Y29tL3JlcG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJ
# yTm6t6E5iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbV
# YQLFY4/UovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQt
# pFg6bBNJ+KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSX
# hndGKj0jfShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6
# bs+XYXvfcXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nO
# ZNm9/Lws80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOH
# X5OKSBoRHeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dq
# cYC/lt5yA9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0i
# xxnJpsoOqHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7
# qWPLd0jV+mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g6
# 04YfM/tV5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD
# 4ED6gVYDU/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S
# /gJXhZrh0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp
# 8nKmrVa46Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqt
# f2phU7+yR2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJ
# QWTEE/bP0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKX
# vYkPbEdx+QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4
# yMYgcMKb9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmY
# F8T4xO2k6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2
# mMIVpqWCZ1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7
# spNY6rQb3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd
# 2jANBgkqhkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy
# /fAHsVv1RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW
# 2H3Bh6zNXULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0
# MP6pBPKOL6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/
# pFL9zlcctWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcex
# U0bcV0hLQ4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf
# 6AMOGaM56A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzEC
# p9LnR+34c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9m
# UF5qE6YwQqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+Ku
# aJRsz+cnZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/Jl
# N6m6GM1jEhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutof
# dgNBzMUxghnUMIIZ0AIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIH72uPyC
# hT86I2UlxIDKdPFdZ5EwBBDLv9T2BHE2b9CrMA0GCSqGSIb3DQEBAQUABIICAD9F
# IEfzar4ZE9bzAV8535wB6yfuAe2kIxsYPwbTENJvy1gRoE9tpviHnQynH3L1JlUF
# QzzVpDIf0npHMPkyxanAGdxWZq9P4+sL7ea1F/OixWPsOrS3Bs+D03lmORgXP60O
# vj3PMEcxhvF+JAeG7T+evH3FoCs/OtcUSVQL3qjUmJfUA7/QhQRLE/yaiR3okyrY
# fwmufCMiMGFrQrqVufiEau1EktjvdJecJrPdswcx86qkuAf1WsqRKtOWd+hRLuGx
# REtJTd9i1Pi3evJ3mxJnU76A9kFqPNgMpaNi0tVGX4Kk9TJIKpDwTnG3HukLSD5H
# zm7bVHEzo15gu1dqiD3+bHmgI9ybWE3qmd5kYnHWLHGI9onbFYkhpjtzfQ7iREuG
# 4eTruz7/odKjc90xdm167HlISvEwIMkzmv266RzJa9qD/r6GA6S7lySxUp5MLZhP
# o24x4PyL9qi49ytXbc6o8+qX4d3GKLhwNfxNidmy/rKmmhPBGGqRyY34RI4TH+qn
# O6r0SOmrZuc14TSVwhysZWCsFLqLNiej7XExsEgEm1fAdxIJiI4W2jsNXdPp20oz
# vVWEw6wLAgg6Nd/lKKz8ltkL6SKUU2FrdvPN5uTTFj2mrEzn/PVbjtYwMa8U3RRG
# ouVCHLMc9zzg2bTnYmdoBHuhbFv0pj86qetY7gQsoYIWuzCCFrcGCisGAQQBgjcD
# AwExghanMIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEw
# gd8GCyqGSIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCAoLJijvqoXXgtzrDOSWgiqqpH0vzDSKU/PJ8wNEWDVYwIUfX29
# 8YgS/XGoO55AeBATnHnmFjgYDzIwMjYwNDE1MDYyODMyWjADAgEBoFikVjBUMQsw
# CQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEqMCgGA1UEAwwh
# R2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2oIISSzCCBmMwggRLoAMC
# AQICEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQEMBQAwWzELMAkGA1UEBhMC
# QkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNp
# Z24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjUwNDExMTQ0NzM5
# WhcNMzQxMjEwMDAwMDAwWjBUMQswCQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFs
# U2lnbiBudi1zYTEqMCgGA1UEAwwhR2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWdu
# MSAtIFI2MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAolvEqk1J5SN4
# PuCF6+aqCj7V8qyop0Rh94rLmY37Cn8er80SkfKzdJHJk3Tqa9QY4UwV6hedXfSb
# 5gk0Xydy3MNEj1qE+ZomPEcjC7uRtGdfB/PtnieWJzjtPVUlmEPrUMsoFU7woJSc
# RV1W6/6efi2BySHXshZ30V1EDZ2lKQ0DK3q3bI4sJE/5n/dQy8iL4hjTaS9v0YQy
# 5RJY+o1NWhxP/HsNum67Or4rFDsGIE85hg5r4g3CXFuiqWvlNmPbCBWgdxp/PCqY
# 0Lie04DuKbDwRd6nrm5AH5oIRJyFUjLvG4HO0L1UXYMuJ6J1JzO438RA0mJRvU2Z
# wbI6yiFHaS0x3SgFakvhELLn4tmwngYPj+FDX3LaWHnni/MGJXRxnN0pQdYJqEYh
# KUlrMH9+2Klndcz/9yXYGEywTt88d3y+TUFvZlAA0BMOYMMrYFQEptlRg2DYrx5s
# WtX1qvCzk6sEBLRVPEbE0i+J01ILlBzRpcJusZUQyGK2RVSOFfXPAgMBAAGjggGo
# MIIBpDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwHQYD
# VR0OBBYEFIBDTPy6bR0T0nUSiAl3b9vGT5VUMFYGA1UdIARPME0wCAYGZ4EMAQQC
# MEEGCSsGAQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxz
# aWduLmNvbS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8EAjAAMIGQBggrBgEFBQcBAQSB
# gzCBgDA5BggrBgEFBQcwAYYtaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vY2Ev
# Z3N0c2FjYXNoYTM4NGc0MEMGCCsGAQUFBzAChjdodHRwOi8vc2VjdXJlLmdsb2Jh
# bHNpZ24uY29tL2NhY2VydC9nc3RzYWNhc2hhMzg0ZzQuY3J0MB8GA1UdIwQYMBaA
# FOoWxmnn48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6MDgwNqA0oDKGMGh0dHA6Ly9j
# cmwuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0LmNybDANBgkqhkiG
# 9w0BAQwFAAOCAgEAt6bHSpl2dP0gYie9iXw3Bz5XzwsvmiYisEjboyRZin+jqH26
# IFq7fQMIrN5VdX8KGl5pEe21b8skPfUctiroo6QS5oWESl4kzZow2iJ/qJn76Tkv
# L+v2f4mHolGLBwyDm74fXr68W63xuiYSpnbf7NYPyBaHI7zJ/ErST4bA00TC+ftP
# ttS+G/MhNUaKg34yaJ8Z6AENnPdCB8VIrt/sqd6R1k89Ojx1jL36QBEPUr2dtIIl
# S3Ki74CU15YTvG+Xxt9cwE+0Gx/qRQv8YbF+UcsdgYU4jNRZB0kTV3Bsd3lyIWmt
# 8DT4RQj9LQ1ILOpqG/Czwd9q9GJL6jSJeSq1AC4ZocVMuqcYd/D9JpIML9BQ/wk5
# lgJkgXEc1gRgPsDsU9zz36JymN1+Yhvx0Vr67jr0Qfqk3V0z6/xVmEAJKafTeIfD
# 9hQchjiGkyw3EKNiyHyM37rdK/BsTSx0rB3MHdqE9/dHQX5NUOQCWUvhkWy10u71
# yzGKWnbAWQ6NNuq9ftcwYFTmcyo5YbFwzfkyS+Y78+O9utqgi6VoE2NzVJbucqGL
# ZtJFJzGJD7xe/rqULwYHeQ3HPSnNCagb6jqBeFSnXTx0GbuYuk3jA51dQNtsogVA
# GXCqHsh62QVAl/gadTfcRaMpIWAc3CPup3x19dDApspmRyOVzXBUtsiCWsIwggZZ
# MIIEQaADAgECAg0B7BySQN79LkBdfEd0MA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNV
# BAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWdu
# MRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE4MDYyMDAwMDAwMFoXDTM0MTIxMDAw
# MDAwMFowWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDwAuIwI/rgG+GadLOv
# dYNfqUdSx2E6Y3w5I3ltdPwx5HQSGZb6zidiW64HiifuV6PENe2zNMeswwzrgGZt
# 0ShKwSy7uXDycq6M95laXXauv0SofEEkjo+6xU//NkGrpy39eE5DiP6TGRfZ7jHP
# vIo7bmrEiPDul/bc8xigS5kcDoenJuGIyaDlmeKe9JxMP11b7Lbv0mXPRQtUPbFU
# UweLmW64VJmKqDGSO/J6ffwOWN+BauGwbB5lgirUIceU/kKWO/ELsX9/RpgOhz16
# ZevRVqkuvftYPbWF+lOZTVt07XJLog2CNxkM0KvqWsHvD9WZuT/0TzXxnA/TNxNS
# 2SU07Zbv+GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50xHAotIB7vSqbu4ThDqxvDbm1
# 9m1W/oodCT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU2EESwVX9bpHFu7FMCEue1EIG
# bxsY1TbqZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE6giunUlnEYuC5a1ahqdm/TMD
# Ad6ZJflxbumcXQJMYDzPAo8B/XLukvGnEt5CEk3sqSbldwKsDlcMCdFhniaI/Miy
# Tdtk8EWfusE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac0zd0hNkdZqs0c48efXxeltY9
# GbCX6oxQkW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCCASUwDgYDVR0PAQH/BAQDAgGG
# MBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOoWxmnn48tXRTkzpPBAvtDD
# vWWWMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMD4GCCsGAQUFBwEB
# BDIwMDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AyLmdsb2JhbHNpZ24uY29tL3Jv
# b3RyNjA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29t
# L3Jvb3QtcjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZo
# dHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0B
# AQwFAAOCAgEAf+KI2VdnK0JfgacJC7rEuygYVtZMv9sbB3DG+wsJrQA6YDMfOcYW
# axlASSUIHuSb99akDY8elvKGohfeQb9P4byrze7AI4zGhf5LFST5GETsH8KkrNCy
# z+zCVmUdvX/23oLIt59h07VGSJiXAmd6FpVK22LG0LMCzDRIRVXd7OlKn14U7XIQ
# cXZw0g+W8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0+X8q5+dIZGkv0pqhcvb3JEt0
# Wn1yhjWzAlcfi5z8u6xM3vreU0yD/RKxtklVT3WdrG9KyC5qucqIwxIwTrIIc59e
# odaZzul9S5YszBZrGM3kWTeGCSziRdayzW6CdaXajR63Wy+ILj198fKRMAWcznt8
# oMWsr1EG8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpIiScseeI85Zse46qEgok+wEr1
# If5iEO0dMPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ7YJQ5NF7qMnmvkiqK1XZjbcl
# IA4bUaDUY6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx773vFNgUQGwgHcIt6AvGjW2M
# tnHtUiH+PvafnzkarqzSL3ogsfSsqh3iLRSd+pZqHcY8yvPZHL9TTaRHWXyVxENB
# +SXiLBB+gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV5yBZtnjGpGqqIpswggWDMIID
# a6ADAgECAg5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQL
# ExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjET
# MBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAw
# MDBaMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQK
# EwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4
# QZIzFKRvf+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTe
# c5RO86eJf094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWy
# ZtWQmrcxBsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7tt
# U+JIfIwQBzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrK
# otudCd5dRC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKF
# t3OiuDWqRfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTfl
# puwhCHX85mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2Fm
# CWqxBjplllnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5
# paHYgw/R/98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4O
# hxlcVLFltr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwo
# TK8CAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYD
# VR0OBBYEFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki
# 5+LXHNbH8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnm
# XNCE3tytok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJE
# lrSVXsB7jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMp
# mY4w06wh4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6
# JV2NoTFR3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG
# 7cKTBYn6fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/
# gsge/lgbKCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324G
# abbeCglIWYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5
# MCMHTI8Qv4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO7
# 7oHl2l98i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4st
# Q1LrRgyU4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjx
# guhFPmzWAtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8wWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwCwYJ
# YIZIAWUDBAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwKwYJKoZI
# hvcNAQk0MR4wHDALBglghkgBZQMEAgGhDQYJKoZIhvcNAQELBQAwLwYJKoZIhvcN
# AQkEMSIEIDiVfwi58E3VJJ1c2M9u/wiF99xpukdxqWlGmWa3MIAdMIGwBgsqhkiG
# 9w0BCRACLzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1or
# d69gXP0wczBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24g
# bnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hB
# Mzg0IC0gRzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAK8AI
# ed6YaXklf1Z+Uw9fF3Ovh7XqR5WXthgHKGTYYlObdvUkL5HOcaKFAYQHsh3oX4ce
# QSrPy8udp8Mhjsh0i+RSTH9NjBUy8NSWgffD1xuASV9uL14oAhhECd7Du4ubZWJE
# I7Et1DskFuyPE6qw32aSdf35ekoxGAHHpQjm/pCFyXjP7n9eq06xG1PsHvFQlCnM
# ctMiA4xQK8r9j37Wo60mGABxmooxxIGjYkXQimRIYk2eQsIdOjKlFm8YryLoHT9R
# MoPL0VeUku+vN5cy/rtNj0XWSG9w3Zlg/3nyNUtgm9walCk5tS1vOKoyEO0Q9naT
# DhkE0L6aQcIImHGZg45zTtXxQ4J//NG4h/a0EB1/MInnRo4lIrGso61B/e1dWeEj
# d4vL5E0oSc80gcGfspq+uMLAAufd0OlbEEXjW7H5nY7MtKYZtlT0n6oLV81fMRoj
# OVMoIWken4HjyTZWfro4rDilfNc1kJ2jqYrEG2/tB3/oi2W1xkoaTniQ17+1
# SIG # End signature block
