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
    20.04.2026 Konrad Brunner       Several updates

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
$UefiPartitionSize = 0
foreach($disk in (Get-Disk))
{
	foreach($part in (Get-Partition -DiskNumber $disk.Number))
	{
		$output = @"
select disk $($part.DiskNumber)
select partition $($part.PartitionNumber)
detail partition
"@ | diskpart
		if ($output -like "*c12a7328-f81f-11d2-ba4b-00a0c93ec93b*")
		{
			$UefiPartitionSize = $part.Size  / 1MB
		}
	}
}

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
Write-Host "UefiPartitionSize: $UefiPartitionSize"
#Get-ComputerInfo

if ($UefiPartitionSize -lt 500MB)
{
	Write-Warning "`nZu kleine UEFI Partitionsgrösse"
	Write-Warning "==============================================="
	Write-Warning "Ihre UEFI-Partition hat nur $($UefiPartitionSize)MB. Empfohlen sind 500MB. Dies kann zu Problemen bei UEFI-Updates führen!"
	Write-Host "Tipp:"
	Write-Host "  Um Ihre UEFI-Partition zu vergrößern, starten Sie diskmgmt.msc und verkleinern Sie Ihre Hauptpartition um die benötigte Größe."
	Write-Host "  Deaktivieren Sie BitLocker auf der Hauptpartition."
	Write-Host "  Laden Sie ein Partitionswerkzeug wie https://www.resize-c.com/ herunter."
	Write-Host "  Verschieben Sie die Hauptpartition, um freien Speicherplatz direkt neben der UEFI-Partition zu schaffen."
	Write-Host "  Vergrößern Sie die UEFI-Partition."
	pause
}
if ($Manufacturer -like "*DELL*")
{
	Write-Warning "`nBekannte Hersteller-Ausnahmen"
	Write-Warning "==============================================="
	Write-Warning "DELL-System erkannt - bitte überprüfen Sie die DELL-Support-Website auf die neuesten UEFI-Firmware-Updates und wenden Sie diese bei Bedarf an. DELL ist dafür bekannt, dass es bei einigen Modellen Probleme mit dem Windows UEFI CA 2023-Update gibt, und möglicherweise ist ein Firmware-Update erforderlich, um Kompatibilitätsprobleme zu beheben. Es ist auch möglich, dass einige Einstellungen im BIOS konfiguriert werden müssen."
	pause
}
if ($Manufacturer -like "*LENOVO*")
{
	Write-Warning "`nBekannte Hersteller-Ausnahmen"
	Write-Warning "==============================================="
	Write-Warning "LENOVO-System erkannt - bitte überprüfen Sie die LENOVO-Support-Website auf die neuesten UEFI-Firmware-Updates und wenden Sie diese bei Bedarf an. LENOVO ist dafür bekannt, dass es bei einigen Modellen Probleme mit dem Windows UEFI CA 2023-Update gibt, und möglicherweise ist ein Firmware-Update erforderlich, um Kompatibilitätsprobleme zu beheben. Es ist auch möglich, dass einige Einstellungen im BIOS konfiguriert werden müssen."
	Write-Warning "Weitere Details: https://support.lenovo.com/bg/en/solutions/ht518129"
	pause
}
if ($Manufacturer -like "*HP*")
{
	Write-Warning "`nBekannte Hersteller-Ausnahmen"
	Write-Warning "==============================================="
	Write-Warning "HP-System erkannt - bitte überprüfen Sie die HP-Support-Website auf die neuesten UEFI-Firmware-Updates und wenden Sie diese bei Bedarf an. HP ist dafür bekannt, dass es bei einigen Modellen Probleme mit dem Windows UEFI CA 2023-Update gibt, und möglicherweise ist ein Firmware-Update erforderlich, um Kompatibilitätsprobleme zu beheben. Es ist auch möglich, dass einige Einstellungen im BIOS konfiguriert werden müssen."
	Write-Warning "Weitere Details: https://support.hp.com/ch-de/document/ish_13070353-13070429-16"
	pause
}
if ($OSArchitecture -like "*ARM64*")
{
	Write-Warning "`nBekannte Hersteller-Ausnahmen"
	Write-Warning "==============================================="
	Write-Warning "ARM64-System erkannt – bitte prüfen Sie die Support-Seite Ihres Geräteherstellers auf aktuelle UEFI-Firmware-Updates und installieren Sie diese, falls verfügbar. Bei ARM64-Geräten sind Probleme mit dem Windows UEFI CA 2023-Update bekannt. Möglicherweise ist ein Firmware-Update erforderlich, um Kompatibilitätsprobleme zu beheben. Es kann auch sein, dass bestimmte Einstellungen im BIOS konfiguriert werden müssen."
	Write-Warning "Führen Sie dieses Skript nicht auf Qualcomm-basierten Geräten aus!"
	pause
}

Write-Host "`nChecking system events"
Write-Host "==============================================="
$allEventIds = @(1801,1802,1803,1808,1037,1042)
$events = @(Get-WinEvent -FilterHashtable @{LogName='System'; ID=$allEventIds} -MaxEvents 200 -ErrorAction SilentlyContinue)

$latest_1801_Event = $events | Where-Object {$_. ID -eq 1801} | Sort-Object TimeCreated -Descending | Select-Object -First 1
$latest_1802_Event = $events | Where-Object {$_. ID -eq 1802} | Sort-Object TimeCreated -Descending | Select-Object -First 1
$latest_1803_Event = $events | Where-Object {$_. ID -eq 1803} | Sort-Object TimeCreated -Descending | Select-Object -First 1
$latest_1808_Event = $events | Where-Object {$_. ID -eq 1808} | Sort-Object TimeCreated -Descending | Select-Object -First 1
$latest_1037_Event = $events | Where-Object {$_. ID -eq 1037} | Sort-Object TimeCreated -Descending | Select-Object -First 1
$latest_1042_Event = $events | Where-Object {$_. ID -eq 1042} | Sort-Object TimeCreated -Descending | Select-Object -First 1

$bootLoaderPending = $false
$zertPending = $true
$zertRetry = $false

if ($latest_1801_Event -or $latest_1802_Event -or $latest_1803_Event) {
	#https://support.microsoft.com/en-us/topic/secure-boot-db-and-dbx-variable-update-events-37e47cf8-608b-4a87-8175-bdead630eb69
	Write-Warning "Folgende Ereignisse im System Log gefunden, die auf einen kürzlich durchgeführten Versuch hinweisen, die Secure Boot CA Zertifikate zu aktualisieren:"
	$latest_1801_Event | Format-List
	$latest_1802_Event | Format-List
	$latest_1803_Event | Format-List
	Write-Host ""
	if ($latest_1801_Event.Message -match 'BucketConfidenceLevel:\s*(.*)') { 
		$confidence = $matches[1]
		Write-Host "BucketConfidenceLevel: $confidence"
		if ($confidence -like "*Temporarily Paused*" -or `
			$confidence -like "*Under Observation*" -or `
			$confidence -like "*Vorübergehend angehalten*" -or `
			$confidence -like "*Unter Beobachtung*")
		{
			Write-Warning "Microsoft untersucht dieses Gerät auf mögliche Kompatibilitätsprobleme mit dem Windows UEFI CA 2023-Update. Bitte überprüfen Sie den Microsoft Update-Katalog und die Support-Seite Ihres Geräteherstellers auf Updates oder Hinweise zu diesem Problem."
			Write-Warning "Möglicherweise wird das Gerät später automatisch aktualisiert."
		} elseif ($confidence -like "*Not Supported*" -or `
				  $confidence -like "*No Data Observed*" -or `
				  $confidence -like "*Nicht unterstützt*" -or `
				  $confidence -like "*Keine Daten wurden beobachtet*")
		{
			Write-Warning "Das Zertifikatsupdate wird von Microsoft nicht unterstützt oder es wurden keine Daten beobachtet."
			Write-Warning "Bitte wenden Sie sich an den Microsoft-Support oder/und den Support des Geräteherstellers."
		}
	}
}

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
		$answer = "n"
		if ($bootLoaderPending)
		{
			Write-Warning ("`n" + $errorMsg)
			Write-Warning "Looks like the boot loader has not been updated yet."
			Write-Warning "Sometimes a secondy reboot is required."
			$answer = Read-Host -Prompt "Already rebooted twice? (y/n)"
		}
		if ($answer.ToLower() -eq "n")
		{
			Write-Error $errorMsg -ErrorAction Continue
			Write-Warning "Please reboot now a second time."
			exit 1
		}
		$answer = "n"
		if ($zertPending)
		{
			$zertRetry = $true
			Write-Warning ("`n" + $errorMsg)
			Write-Warning "Looks like the certificates have been installed once may removed afterwards."
			Write-Warning "This can happen on systems where the BIOS is blocking the update."
			Write-Warning "Please check your BIOS before you try again."
			$answer = Read-Host -Prompt "Try now again to update the certificates? (y/n)"
		} elseif ($bootLoaderPending)
		{
			$zertRetry = $true
			Write-Warning ("`n" + $errorMsg)
			Write-Warning "Looks like the boot loader has not been updated yet."
			Write-Warning "This can happen on systems where the BIOS is blocking the update."
			Write-Warning "Please check your BIOS before you try again."
			$answer = Read-Host -Prompt "Try now again to update the boot loader? (y/n)"
		}
		if ($answer.ToLower() -eq "n")
		{
		Write-Error $errorMsg -ErrorAction Continue
		exit 1
	}
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
		$answer = "n"
		if ($zertPending)
		{
			$zertRetry = $true
			Write-Warning ("`n" + $errorMsg)
			Write-Warning "Looks like the certificates have been installed once may removed afterwards."
			Write-Warning "This can happen on systems where the BIOS is blocking the update."
			Write-Warning "Please check your BIOS before you try again."
			$answer = Read-Host -Prompt "Try now again to update the certificates? (y/n)"
		}
		if ($answer.ToLower() -eq "n")
		{
		Write-Error $errorMsg -ErrorAction Continue
		exit 1
	}
	}

}

if ($zertPending) {

	Write-Warning "Kein Ereignis 1808 oder andere Probleme gefunden - Secure Boot CA Zertifikate sind noch nicht aktualisiert"
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
	if ($zertRetry -eq $false)
	{
	$RegValue += 0x4000 # apply update only if 2011 certificate is trusted
	}

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
	exit 0
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
	exit 0
}

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAWhixOZhtji0so
# eXAE6ObRju7aWwR/ox4cP0Ev7KPjGKCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# dgNBzMUxgiEGMIIhAgIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINXYu/sX
# I7MrFJcRD0e3VfcwZcigVw3VpuUy88iMuyEoMA0GCSqGSIb3DQEBAQUABIICAKoz
# nSvqbsOWtZylBOD55d+XMa7COFrwo3+z5zkLGXJR/uw2S+T11xpp3ZnL5AkWh/GC
# x+4pBuaUfb1cKqqZA4RLKgfwsE8TGGmYrIVmi0l0yCOsOPgV8ysogPSn5xDSTs2C
# DdGR+pPKFRVJliU3e5IbrYko6Q7nh5JcM8PYgzerTWSVqv584M4II8s9UFyi6rPx
# zXcc5DKfJWR9+ucmS9CgrJ36yaXyL/Az/+DRKzccJQnJSLnTxHGBGLPFVzPhHWw+
# aGfBwU3DQKD7bUl3/oMuiQPpnygT85VHdya6TF0z/CnNtr+VqZnuyYArike69kYX
# kyLbBVra5Dw+StKLQSaiqgmGWBc7E50knjXIQoBEQcTWlbEXGBw9OyPdYqLP+Vmt
# Fqyb5pzF6mu/bLJpXsMCgLA0IYSJCkWvGQn53hJrpPNoRGhcm9yIpld/IzD4Nt1X
# 224BXlWQ4IObjAKTKdjjDSdfFoOzTfGreE/FmwOrZvSDwhQ3W86PNIZNSWv2YFM8
# RqhZF1xNVnzjVMi3UgXeSoVZM2QKXmTDT2TaV1TLogLCNHCQVTwP01L3vZykENd8
# 7o4N/+r5TmjUlZmCP4JZvl6xRfQ/45tls//0SM8NT3HbBemvAueEE5+KLI9N8Tvu
# tSFFhMk/tIGZlAJFqa+igcPdIQNsMwPJpyj8hc2LoYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCAfW4u9U9+GkrgLd34lTsKn29QAyuW12U1GFrkJJKzP5wIUCEdf
# +wnc3IKM89mQqpX2IyVg180YDzIwMjYwNDIzMTQ0OTE4WjADAgEBoF2kWzBZMQsw
# CQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMm
# R2xvYmFsc2lnbiBSNDUgVFNBIGZvciBDb2RlU2lnbiAyMDI1MTCgghlgMIIGijCC
# BHKgAwIBAgIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcNAQEMBQAwXjELMAkG
# A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0ds
# b2JhbFNpZ24gT2ZmbGluZSBSNDUgVGltZXN0YW1waW5nIENBIDIwMjUwHhcNMjUx
# MDE1MDcyNTA0WhcNMzcwMTEwMDAwMDAwWjBZMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFsc2lnbiBSNDUgVFNB
# IGZvciBDb2RlU2lnbiAyMDI1MTAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQDRSo2hjYZASCijCQSc2RMQPPKojE/xf4Uija2JnsJ7Snl2gDoxKjQ9HcU6
# rVD8pgy1sBKdVxtLLFhY3gzY/PA2iwIs6ZzCnxshtjShsN1RyzRrzc4Fq+0xQx6q
# ADUMn96mqHE/0ok53DPbmpBkkUDytGM79nQfw9WVymYgA+TkbA0/QOmPNNJIZ6Cj
# X0t3wJfhL0caiXthBBMEWKxT5v2U7ZRbCq/DVDXA9oX1iFVBVaBpx57MLL00nyHu
# x0InYS7Rr54M3tNhm7+0maxpyTFa51uY1PHtTJMup/l3RGooQ5YweCH2hDoUNwKO
# C7QkFbklhPdq27EXkueg8qLOnRDmVO1r+B1yMAbl6QuV0L+OPB1SKBAPpmIFklmJ
# 0SoibbUqxsTzejjdI+ywQLUcXilogwKWsJ46h6wjlU5AVqT7FEBYzWCTt6hf7SLQ
# bPGs02Ba8oaaNfo0SL+aApN94luEB/wuE1lgptrckLzbQlCp56OgkAJYpqYuui+T
# fueCIU0CAwEAAaOCAcYwggHCMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAK
# BggrBgEFBQcDCDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQy+tPhB2gnkGsI0j8d
# PIxlNigGGTAfBgNVHSMEGDAWgBR3AjsBMQ8edHfDSMjDB2NViKU7ojCBpQYIKwYB
# BQUHAQEEgZgwgZUwQgYIKwYBBQUHMAGGNmh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24u
# Y29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNTBPBggrBgEFBQcwAoZDaHR0
# cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NvZmZsaW5lcjQ1dGlt
# ZXN0YW1wY2EyMDI1LmNydDBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLmds
# b2JhbHNpZ24uY29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNS5jcmwwVgYD
# VR0gBE8wTTAIBgZngQwBBAIwQQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0
# dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEB
# DAUAA4ICAQCOrnCmj0eGkYpuniz6/WFm91s6KjnhkMKYlbcftgpMBtlhysVniEOf
# BvhcvoFQw4AOHG9NRVvZpkBnag5Dt1HM3Jg21gRVCBwFyP1ET8IDxoflYx5OD4SC
# NLHs6vCg6rFkNT81v9Zy8u0xXy3WboN5iK/SbTmLGqCrAGJihLLrfIhvddwVrdBy
# iHteLxgjugT6JQogCSoBF2JqmH0ZBCl515btbTuWZLrQUs5vvl2o98Mdju9yyJRW
# LzPVcUkRk9d8xBBi638FBOAuo3fcyThGcne7wUOa+TghhwIHbZ3pxTYpgo5cCxEZ
# sH8EXwiTUTwHf0qesssg/2XdcGH7s0AR4TyOJ2QnAayYOAM/XOBxNzURQg4mhMdP
# L/F8VCMKj3koJaVcx2akh0B82le/aBU8q2Oa++OwOwiHF5e+f9m+yhyYbwGSogWI
# V3hgRl+VyKrch8gv35FHr/cVz8n0/CPGRXGiYJZ7P1wOOgYdkMD2iDKVYQby5Ix/
# xCB0/lSKLnqEoFezfmnCJbGgACVswMsxhJEUjtxEcQc9afalne+IOts0v/yCRikJ
# snmVbS0x50Dk2OH+VCiU9s/XyzgfC7WzrtQ5diIdc2Ksi3JMTJm4a0LiEIZWitD5
# +6PokOkQ8+35TsHOwUhs87I/yyJjlIZpAV4Of1/JN8bWVB3Edm4WzjCCBqAwggSI
# oAMCAQICEQCD2oY3t58MhAyUe4QKUngfMA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNV
# BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9i
# YWxTaWduIFRpbWVzdGFtcGluZyBSb290IFI0NTAeFw0yNTA3MTYwMzA1MDRaFw00
# MTA3MTYwMDAwMDBaMF4xCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTQwMgYDVQQDEytHbG9iYWxTaWduIE9mZmxpbmUgUjQ1IFRpbWVzdGFt
# cGluZyBDQSAyMDI1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApHcW
# +O19i+LdAoZFYzS+5X+WYvnWoFqXAfir1hynhUTdH4RW1Db+yOmrQ275jlsQ6bzo
# Z3nN0CMncZX4E0Qhpp6Qvx27+flpfzeMQacD7VciWUiF3TLiu7wT2bBCSENUn3hf
# GMG4PJvYFvO5o4DA1iNvHhG4oSzctodoJfb4c8EjVahCw/NLizB3ra+NWe2gZBSa
# ZKraMxFt676yqx7RcQnjbF4R0OLGovsZt23vU69A5BdoPxdA9zu9rM+qTBsPDVUJ
# exYwEVU0GY7BJ5mUWWniyAPHW0Wv4Azk5t7I0XUIjA3+2OGkr0dVBXVBDyEeGBVr
# YXEdhfVLwuh6HBGJFdIrEY5KoGlpoT+4BBQe4XCH5sv15Uo+M72VKWjPA5Ex3nfF
# JC4P5FW1SR6olCSaIrtnZzc+zgmpSyiD+GcE2udQRQHbDi74enXgazk0+ktpHZ1Z
# 8oTvSaSIREovXSLbH3KC8uFIkXucl7XPH7ZGIrmF9eF4zuoo5FIUnsvV60kLqFDz
# Pk+UbLmgZDUCPlFFBBehaaNvixEymx9ON2KXev+MfK6OZChqGbrOC2wvvAFHyKlT
# ZbVHdqNiu0u5a2T1C9dSTRny1/hxLwcxL9BWPzQLwhsiyXqUzM7uD0lD9+PYMaxU
# YgoVSxqb4xvPCiVqLNabI+WtjEzYfQ0P+6tBTFsCAwEAAaOCAWIwggFeMA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDASBgNVHRMBAf8ECDAGAQH/
# AgEAMB0GA1UdDgQWBBR3AjsBMQ8edHfDSMjDB2NViKU7ojAfBgNVHSMEGDAWgBRG
# shx34XsV8KU5oXDe0cQu6m2y3jCBjgYIKwYBBQUHAQEEgYEwfzA3BggrBgEFBQcw
# AYYraHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vdGltZXN0YW1wcm9vdHI0NTBE
# BggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# dGltZXN0YW1wcm9vdHI0NS5jcnQwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2Ny
# bC5nbG9iYWxzaWduLmNvbS90aW1lc3RhbXByb290cjQ1LmNybDARBgNVHSAECjAI
# MAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggIBADKj7n7RbuRmMZZYXqlMPRJoR6X1
# n//quXGLVfOpFoR9Ya05L94w0ywBjelyGGf+nAB+CZFQ7gUOd2a2bpfpW8Xw5ArM
# +YjPEf8AtC4E6Yr105U1YNjlTSERoWJKc1hkSN5m4dpsYteFykzFQVwX50hYKH3y
# Z6Vcu6Ha0EA5ofzLpi2jK2jbRDCXbFNLi5mO1xKRdB2AzAF0f5C00b4H3d5sCOB8
# njTvAwaTMGEMeTkLWM4Z9Y+3UOtOpo1QuxXbDpXVkLXraG25iL1VtvjxEAy4534n
# UINB9whORicJJSTLba6fOK2f/1QGWEdewWLHAzE+N5oH0QoNRALpJ5JjIfeInvO+
# sQdBidnPuLKJ95HTj7XyMvJhFZjtbHJGlEWx4UgKcuNKLDLXWALfwQDN2Dey3kTf
# d4yw4nQdk1PctLLK3F4L2nnLv94BMkpY+Rfl53oOEN4yTvtwCYP+VDuZrktc7Nac
# oTVxZnKGkv8a1akckdOwQZC+i8Ay1VyzMAX/Tb4+r3c65B7cpAtq3OoUijXUJgvZ
# xci6TX78smL2TYy2tWn+8G4krnXvy2ELR2XYnKEOS4MVmrSCsjM5nxSrghE10VDX
# QbEfa93lhikfFoIuINKzWDLqvu8ZucmxEufxpHjNnnRVXX/Zv5KQq8pu/MQoOz6D
# C74n5+O5bSwvT5sgMIIGozCCBIugAwIBAgIQeEqqgXNmnJAJVOQhyUfrwDANBgkq
# hkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjET
# MBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMDEy
# MDkwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIFRpbWVzdGFt
# cGluZyBSb290IFI0NTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALp0
# M+wn3BI4IRvF02Eo1lq8T9+LzJGEQyRXvGQhvDscHz1PjK0Ht/PF1wLpERSCmqq0
# lHI7cQ0a72hrhXmOr2bqWJgNusF8edL/zbNvMUXQBXQEAHJqJ364Nz86iO2Xg/Wr
# NU0Pn1k79S/fWcV8pTJ2YJbI7e74BH4ZUXKov0RBerx7HjsAm7y64Ja/kP6Nm8Ny
# iwAS+CA6YDj3wcyFivuHeS6hKyDmy6CFkSO2xCgHVCje7BAxT4ryzRQfHt1VHOoo
# MUz5IWqozfOWZ/oBQZvNDwtof7ve8UPqF+Ww3HAis2k2WXRrxuWJKnzlC4Fdqz+P
# uNF2cvN8oqnil0G/zIxF/mHJ9mwHCwAE6BUjT4IqLfbvw/oRNkih0f16OTo0XaMs
# Dpt3UCA0QN2xAzGtX+lih3OWA2H3lLDZXGxP5xTF4fF7DSOczXCMHWreSi2LKrvb
# QhQFB6r7FNwx0/YfbMu+aGZEcE1tF/lx6wVzjpGSdetoXB72RGEYKWLdF2aI7Ci6
# SW/bPnf+uTEfdRwYoqZHvdjuSIU7/bPiDz8qmMaa+oJvsaWlhh1aOvqkbHQPd1Jh
# an+HKd45m4vus0VgMCSXFRIqhTCTJqyWpi3ocG0LqTKtLJsoCnZC8lVhUZiU3u32
# xRdvPBUQsA6tsN7FFvRl0cwvWlYIz5nE8FWRwix5AgMBAAGjggF4MIIBdDAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDwYDVR0TAQH/BAUwAwEB
# /zAdBgNVHQ4EFgQURrIcd+F7FfClOaFw3tHELuptst4wHwYDVR0jBBgwFoAUrmwF
# o5MT4qLn4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEEbzBtMC4GCCsGAQUFBzABhiJo
# dHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsGAQUFBzAChi9o
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAi0i6Nlc8csXadfnvMvWGvdwSKOOILk82XyaZ7A8BIRCWkjjGcGtt867UDr0l
# 74Z/4omNlaV+KUQDTaqYqPG33OopYyHc7c2ICssQaWF5KUIMI7zpxe9SHi8zN9VP
# ZnpmqUdUM7HdFvLYZHGjMZTlb/ZNS+KEbNDJJWdPyEvQzksF1j37fUH6irHAIeB+
# CLDZZCv56vLHCvTPLgw0YO5su5LwP/F7UhJod1mB9RwupDqMOQMN7eXMr2ZIeWPV
# Sbj/S9IlT0hOkzuTd7CaSGy2oB2zdJ5fvSIEO3w3DYW1w5q73ZxaA420DZ9MdjTV
# ha1Fe7Wfuy6Ju6zIv5JjSMY/yheqDbwAEV+L6ONDhIpDNM39O8Cie9sfuGfIjBXe
# P6Z/xyjvoW9vskHPAiLrAfhLyNJ2byXfXtpoaD17RATCQW5JO6eYVgTt0SYrBJTb
# 5O1mjj2AnaSkVXlQXuP4Gh/AFm+QFTyKpkihDHu6KuCxqYcFRpvtJVU9N2mY7UaZ
# mIVHCh5i2/2c5cFDQo69z2/2jJH9guSf7K3jlVUF80kvbTT3/2fumUC705qAQkDa
# I4lgH4NxkrXp5soK+d3HbLJYQZxmjZsqbx9vVwRDXINdO2mc3jn6hE0183sbbYvx
# bwPBKVLilL97VIvfQHoLcAJ3Py+IBwIAddKvxtYiMhmjO+gwggWDMIIDa6ADAgEC
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
# AtcKZ4MFWsmkEDGCA2EwggNdAgEBMHMwXjELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNpZ24gT2ZmbGluZSBS
# NDUgVGltZXN0YW1waW5nIENBIDIwMjUCEQCEcj/BlcwW8dsrovZg3yvkMAsGCWCG
# SAFlAwQCAqCCAUEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMCsGCSqGSIb3
# DQEJNDEeMBwwCwYJYIZIAWUDBAICoQ0GCSqGSIb3DQEBDAUAMD8GCSqGSIb3DQEJ
# BDEyBDANRqC/WJG4HYQumAoVsQHYQii4lSsm12s8MuDVBm3tHFKqApRyO16SHZwi
# sVXw3AAwgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGAFLc2cE/kwES/AP3wlkmVAXGFJeKctPMny5Jt9cq41wZ4
# ReX9UHURH81gK5SD9y+nXSxaS0pKTAuesg3OEPlHG1WZjhg4O6jJu6E4HUl2ar1H
# Vwx5UioEqMWdQjF9hGUiIQHaorLZrm1YTerpE1JYW+kb+g6sKFOV77KJ6/8XYyqz
# BE+4iSrGsGyOiy6PJLDLXCsxP0Gscs+7rc0Ljx93DjSirmx4NKK5GeS11HTWroSc
# XsZIxOlkIcxqUJr9SxCwZwXt9nl0wIgy+j/VPoW+4pXWQvwiGEH8ryTQ9a3kaMlR
# p7TwjbwvvbxRr+y0yA6mjG6jGRnWiSRG6AJgBQDF0w1MlShRW/qQ28H4tfyn1EkR
# FZJCvQwnLFNDyQFoBWFVF3UnJOUUCeIGyF3fPzcB/dftgD9mvgGA49Wrc2MsxQir
# KA0eBH+xTYWJdup3cnvqfih/aBOGs8NjSyVG8nsSDvAhLLgP3gBr9Juj+QNCEXlt
# XzspNcr2Mpj/NvTHbIbS
# SIG # End signature block
