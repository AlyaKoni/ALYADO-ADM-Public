#Requires -Version 5.1
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
    12.11.2026 Konrad Brunner       Initial Version
    12.11.2026 Konrad Brunner       Standalone version, customer agnostic DevOps upload parameters
    12.11.2026 Konrad Brunner       Device code wait feedback, HTTP error body diagnostics, BitLocker namespace handling
    12.11.2026 Konrad Brunner       Fixed OAuth error body extraction (ErrorDetails lives on the ErrorRecord, not on the Exception)
    12.11.2026 Konrad Brunner       Upload via Git Pushes API instead of items POST (items POST returns 405, verified against alyaconsulting)
    12.11.2026 Konrad Brunner       Added Hyper-V section (host, VMs, switches, event log) and USB/license-dongle section
    12.11.2026 Konrad Brunner       Hardened Hyper-V event log collection (per-log/per-entry guards, no FilterHashtable)
    12.11.2026 Konrad Brunner       SQL sizes via per-database sys.database_files, local admins via WinNT ADSI, UDP ephemeral port reduction

#>

<#
.SYNOPSIS
Collects a local inventory of a Windows client or server, writes the result as a JSON report and optionally
uploads it to an Azure DevOps repository.

.DESCRIPTION
The Get-ComputerInventoryStandalone.ps1 script collects inventory data from the local machine only (no remote
support) and is self-contained: it does not dot-source any repository configuration. It gathers hardware
information (type, manufacturer, CPU, memory, disks with fill levels, TPM), operating
system details (version, build, install date, boot time, installed and pending updates, Windows Update policy,
licensing, Entra/domain join state), network configuration (adapters, IPs, DNS, DHCP, firewall, RDP), security
information (antivirus/Defender status, BitLocker, local administrators, listening ports), installed programs
(registry uninstall keys), services and Windows roles/features, Azure related agents (Azure Arc, Azure Monitor
Agent, Microsoft Defender, Azure VM instance metadata), Hyper-V (only when the role is active: host
configuration, virtual machines with state/uptime/CPU/memory, virtual switches and Hyper-V event log errors,
warnings and recent activities), USB devices (present PnP devices, USB storage, license dongles with related
services, license port listeners/connections and installed license software) and SQL Server details
(instances, editions, databases
with data/log sizes, recovery model, compatibility level, last backups).

The result is written as a single JSON file, by default {temp}\{hostname}_{yyyyMMdd}.json. If Upload is enabled,
the script signs in to Microsoft Entra ID using inline native OAuth 2.0 flows against the Microsoft identity
platform (device code flow, or authorization code flow with PKCE via the local browser and a temporary local
HTTP listener, selectable through the AuthMode parameter; no external PowerShell modules required) and uploads
the JSON file directly through the
Azure DevOps Git REST API (Pushes endpoint: determines the branch HEAD, detects whether the file already exists
and commits it as add or edit) into the configured repository (DevOpsOrganization, DevOpsProject, DevOpsRepository),
path {DevOpsRepoDirectory}/{hostname}_yyyyMMdd.json, committing directly onto the configured branch
(DevOpsBranch). An already existing file of the same day is overwritten by the commit. The upload target
parameters have no customer specific defaults; they must be provided when Upload is true.

The script requires elevation (run as administrator) for a complete inventory; without elevation, single
sections may report errors and are skipped gracefully. Best-effort: every section is wrapped in error handling,
failed sections are listed in the errors property of the JSON report.

.PARAMETER OutputPath
Optional path of the local JSON file. Defaults to {temp}\{hostname}_{yyyyMMdd}.json.

.PARAMETER Upload
Enables or disables the upload of the JSON report to Azure DevOps. Default is true. Requires
DevOpsOrganization, DevOpsProject and DevOpsRepository to be set; otherwise the upload is skipped with a warning.

.PARAMETER AuthMode
Entra ID login mode used for the upload. DeviceCode shows a code and URL to sign in on any device,
Interactive opens the local browser. Default is DeviceCode.

.PARAMETER TenantId
Optional Entra ID tenant id or domain used for the login. Defaults to the tenant of the signed in user.

.PARAMETER DevOpsOrganization
Azure DevOps organization name. No default (customer agnostic), mandatory when Upload is true.

.PARAMETER DevOpsProject
Azure DevOps project name. No default (customer agnostic), mandatory when Upload is true.

.PARAMETER DevOpsRepository
Azure DevOps Git repository name. No default (customer agnostic), mandatory when Upload is true.

.PARAMETER DevOpsBranch
Target branch for the commit. Default is master.

.PARAMETER DevOpsRepoDirectory
Repository directory for the JSON report. Default is data/client/inventory.

.PARAMETER IncludeSql
Enables or disables the SQL Server inventory section. Default is true.

.PARAMETER IncludePendingUpdates
Enables or disables the scan for pending Windows updates via the Windows Update COM API. This scan can take
several minutes. Default is true.

.INPUTS
None. The script does not require input objects.

.OUTPUTS
System.Object. Returns a summary object with host name, local JSON path, upload state and collected errors.

.EXAMPLE
PS> .\Get-ComputerInventoryStandalone.ps1 -Upload $false
Collects the inventory and writes the JSON report to the temp directory without uploading.

.EXAMPLE
PS> .\Get-ComputerInventoryStandalone.ps1 -DevOpsOrganization "contoso" -DevOpsProject "IT" -DevOpsRepository "IT-Configuration"
Collects the inventory and uploads the JSON report to the given Azure DevOps repository using the device code flow.

.EXAMPLE
PS> .\Get-ComputerInventoryStandalone.ps1 -AuthMode Interactive -DevOpsOrganization "contoso" -DevOpsProject "IT" -DevOpsRepository "IT-Configuration"
Collects the inventory and uploads the JSON report using an interactive browser login.

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [string]$OutputPath = "",
    [bool]$Upload = $true,
    [Parameter(Mandatory=$true)]
    [ValidateSet("DeviceCode", "Interactive")]
    [string]$AuthMode = "DeviceCode",
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$DevOpsOrganization, # z. B. "contoso" — Org-Name aus der URL https://dev.azure.com/contoso
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$DevOpsProject, # z. B. "IT" — Projekt aus https://dev.azure.com/contoso/IT
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$DevOpsRepository, # z. B. "IT-Configuration" — Git-Repo-Name im Projekt
    [ValidateNotNullOrEmpty()]
    [string]$DevOpsBranch = "master", # Ziel-Branch für den Commit, z. B. "main" oder "master"
    [ValidateNotNullOrEmpty()]
    [string]$DevOpsRepoDirectory = "data/client/inventory", # z. B. "data/client/inventory" — Repo-Verzeichnis relativ zum Repo-Root
    [bool]$IncludeSql = $true,
    [bool]$IncludePendingUpdates = $true
)

$ProgressPreference = "SilentlyContinue"

if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    throw "Get-ComputerInventoryStandalone.ps1 requires Windows (WMI/CIM based inventory). Current platform: $([System.Environment]::OSVersion.Platform)"
}

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    Write-Verbose "TLS 1.2 enum member not available on this runtime, skipping."
}

$scriptName = "Get-ComputerInventoryStandalone"
$hostName = $env:COMPUTERNAME
$dateStamp = Get-Date -Format "yyyyMMdd"
$inventoryErrors = New-Object System.Collections.Generic.List[string]

Write-Host ""
Write-Host "====================================================="
Write-Host "System | $($scriptName) | Local inventory"
Write-Host "====================================================="
Write-Host ""

# =============================================================
# Helper functions
# =============================================================

function Write-Section {
    param(
        [string]$Name
    )
    Write-Host "Collecting: $($Name)"
}

function Add-InventoryError {
    param(
        [string]$Section,
        [System.Exception]$Exception
    )
    $message = "$($Section): $($Exception.Message)"
    $inventoryErrors.Add($message)
    Write-Warning $message
}

function Format-ByteSize {
    param(
        [double]$Bytes
    )
    if ($Bytes -ge 1TB) {
        return "{0:N1} TB" -f ($Bytes / 1TB)
    } elseif ($Bytes -ge 1GB) {
        return "{0:N1} GB" -f ($Bytes / 1GB)
    } elseif ($Bytes -ge 1MB) {
        return "{0:N1} MB" -f ($Bytes / 1MB)
    } else {
        return "{0:N1} KB" -f ($Bytes / 1KB)
    }
}

function Get-RegistryValue {
    param(
        [string]$Path,
        [string]$Name
    )
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch {
        return $null
    }
}

function ConvertTo-PlainValue {
    param(
        [object]$Value
    )
    if ($null -eq $Value -or [DBNull]::Value.Equals($Value)) {
        return $null
    }
    if ($Value -is [DateTime]) {
        return $Value.ToString("o")
    }
    return $Value
}

function Convert-DataTableToList {
    param(
        [System.Data.DataTable]$Table
    )
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($row in $Table.Rows) {
        $entry = [ordered]@{}
        foreach ($column in $Table.Columns) {
            $entry[$column.ColumnName] = ConvertTo-PlainValue -Value $row[$column.ColumnName]
        }
        $rows.Add([PSCustomObject]$entry)
    }
    return $rows
}

function Get-DateValue {
    param(
        [object]$Value
    )
    if ($null -eq $Value) {
        return $null
    }
    try {
        return ([datetime]$Value).ToString("o")
    } catch {
        return $null
    }
}

# =============================================================
# Hardware
# =============================================================

function Get-HardwareInventory {
    $chassisMap = @{
        3 = "Desktop"; 4 = "Low Profile Desktop"; 6 = "Mini Tower"; 7 = "Tower"
        8 = "Portable"; 9 = "Laptop"; 10 = "Notebook"; 12 = "Docking Station"
        13 = "All in One"; 15 = "Space Saving"; 23 = "Rack Mount Chassis"
        30 = "Tablet"; 31 = "Convertible"; 32 = "Detachable"
    }

    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    $csProduct = Get-CimInstance -ClassName Win32_ComputerSystemProduct
    $bios = Get-CimInstance -ClassName Win32_BIOS
    $baseboard = Get-CimInstance -ClassName Win32_BaseBoard
    $enclosure = @(Get-CimInstance -ClassName Win32_SystemEnclosure)
    $memoryArray = Get-CimInstance -ClassName Win32_PhysicalMemoryArray

    $chassisTypes = @()
    if ($enclosure.Count -gt 0) {
        foreach ($type in $enclosure[0].ChassisTypes) {
            $typeKey = [int]$type
            if ($chassisMap.ContainsKey($typeKey)) {
                $chassisTypes += $chassisMap[$typeKey]
            } else {
                $chassisTypes += "Unknown ($($typeKey))"
            }
        }
    }

    $processors = @(Get-CimInstance -ClassName Win32_Processor | ForEach-Object {
        [PSCustomObject]@{
            name                = $_.Name
            manufacturer        = $_.Manufacturer
            numberOfCores       = $_.NumberOfCores
            numberOfLogicalCpus = $_.NumberOfLogicalProcessors
            maxClockSpeedMhz    = $_.MaxClockSpeed
            socket              = $_.SocketDesignation
        }
    })

    $memoryModules = @(Get-CimInstance -ClassName Win32_PhysicalMemory | ForEach-Object {
        [PSCustomObject]@{
            deviceLocator = $_.DeviceLocator
            manufacturer  = $_.Manufacturer
            partNumber    = ($_.PartNumber).Trim()
            capacityBytes = $_.Capacity
            capacity      = Format-ByteSize -Bytes $_.Capacity
            speedMhz      = $_.Speed
            formFactor    = $_.FormFactor
        }
    })

    $physicalDisks = @()
    try {
        $physicalDisks = @(Get-CimInstance -Namespace "root/Microsoft/Windows/Storage" -ClassName MSFT_PhysicalDisk | ForEach-Object {
            $mediaType = "Unknown"
            if ($_.MediaType -eq 3) { $mediaType = "HDD" }
            elseif ($_.MediaType -eq 4) { $mediaType = "SSD" }
            elseif ($_.MediaType -eq 5) { $mediaType = "SCM" }
            [PSCustomObject]@{
                deviceId       = $_.DeviceId
                friendlyName   = $_.FriendlyName
                serialNumber   = ($_.SerialNumber).Trim()
                busType        = $_.BusType
                mediaType      = $mediaType
                healthStatus   = $_.HealthStatus
                operationalStatus = $_.OperationalStatus
                sizeBytes      = $_.Size
                size           = Format-ByteSize -Bytes $_.Size
            }
        })
    } catch {
        Add-InventoryError -Section "Hardware.PhysicalDisks" -Exception $_.Exception
    }

    $logicalDisks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
        $usedPercent = $null
        if ($_.Size -gt 0) {
            $usedPercent = [math]::Round((($_.Size - $_.FreeSpace) / $_.Size) * 100, 1)
        }
        [PSCustomObject]@{
            driveLetter    = $_.DeviceID
            fileSystem     = $_.FileSystem
            volumeName     = $_.VolumeName
            sizeBytes      = $_.Size
            size           = Format-ByteSize -Bytes $_.Size
            freeBytes      = $_.FreeSpace
            free           = Format-ByteSize -Bytes $_.FreeSpace
            usedPercent    = $usedPercent
        }
    })

    $tpm = $null
    try {
        $tpmRaw = Get-CimInstance -Namespace "root/CIMV2/Security/MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction Stop
        if ($null -ne $tpmRaw) {
            $tpm = [PSCustomObject]@{
                present     = $true
                specVersion = $tpmRaw.SpecVersion
                isEnabled   = $tpmRaw.IsEnabled_InitialValue
                isActivated = $tpmRaw.IsActivated_InitialValue
            }
        } else {
            $tpm = [PSCustomObject]@{ present = $false }
        }
    } catch {
        $tpm = [PSCustomObject]@{ present = $false; note = $_.Exception.Message }
    }

    return [PSCustomObject]@{
        type             = $chassisTypes
        isVirtualMachine = ($cs.Model -match "Virtual|VMware|VirtualBox|KVM|HVM" -or $csProduct.Name -match "Virtual Machine")
        manufacturer     = $cs.Manufacturer
        model            = $cs.Model
        systemFamily     = $cs.SystemFamily
        serialNumber     = $bios.SerialNumber
        uuid             = $csProduct.UUID
        biosVersion      = $bios.SMBIOSBIOSVersion
        biosReleaseDate  = Get-DateValue -Value $bios.ReleaseDate
        smbiosVersion    = if ($null -ne $bios.SMBIOSMajorVersion) { "$($bios.SMBIOSMajorVersion).$($bios.SMBIOSMinorVersion)" } else { $null }
        baseboardProduct = $baseboard.Product
        baseboardSerial  = $baseboard.SerialNumber
        processors       = $processors
        memory           = [PSCustomObject]@{
            totalBytes      = $cs.TotalPhysicalMemory
            total           = Format-ByteSize -Bytes $cs.TotalPhysicalMemory
            modules         = $memoryModules
            installedSlots  = @($memoryModules).Count
            maxSlots        = if (@($memoryArray).Count -gt 0) { @($memoryArray)[0].MemoryDevices } else { $null }
        }
        physicalDisks    = $physicalDisks
        logicalDisks     = $logicalDisks
        tpm              = $tpm
    }
}

# =============================================================
# Operating system
# =============================================================

function Get-OperatingSystemInventory {
    param(
        [bool]$ScanPendingUpdates
    )

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $osType = "Client"
    if ($os.ProductType -eq 2) { $osType = "Domain Controller" }
    elseif ($os.ProductType -eq 3) { $osType = "Server" }

    $hotfixes = @(Get-HotFix | Sort-Object -Property InstalledOn -Descending | Select-Object -First 50 | ForEach-Object {
        [PSCustomObject]@{
            hotFixId    = $_.HotFixID
            description = $_.Description
            installedOn = Get-DateValue -Value $_.InstalledOn
        }
    })

    $pendingUpdates = $null
    if ($ScanPendingUpdates) {
        try {
            Write-Host "  Scanning pending Windows updates (can take a few minutes)..."
            $updateSession = New-Object -ComObject Microsoft.Update.Session
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $searchResult = $updateSearcher.Search("IsInstalled=0")
            $titles = New-Object System.Collections.Generic.List[string]
            foreach ($update in $searchResult.Updates) {
                $titles.Add($update.Title)
            }
            $pendingUpdates = [PSCustomObject]@{
                count  = $searchResult.Updates.Count
                titles = $titles
            }
        } catch {
            Add-InventoryError -Section "OperatingSystem.PendingUpdates" -Exception $_.Exception
            $pendingUpdates = [PSCustomObject]@{ error = $_.Exception.Message }
        }
    }

    $updatePolicy = [PSCustomObject]@{
        wsusServer          = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer"
        wsusStatusServer    = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUStatusServer"
        useWUServer         = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "UseWUServer"
        noAutoUpdate        = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate"
        auOptions           = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions"
        activeHoursStart    = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursStart"
        activeHoursEnd      = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "ActiveHoursEnd"
    }

    $licensing = @(Get-CimInstance -ClassName SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" | ForEach-Object {
        $statusMap = @{ 0 = "Unlicensed"; 1 = "Licensed"; 2 = "OOBGrace"; 3 = "OOTGrace"; 5 = "Notification"; 6 = "ExtendedGrace" }
        $statusKey = [int]$_.LicenseStatus
        $statusText = "Unknown ($($statusKey))"
        if ($statusMap.ContainsKey($statusKey)) { $statusText = $statusMap[$statusKey] }
        [PSCustomObject]@{
            name           = $_.Name
            description    = $_.Description
            licenseStatus  = $statusText
            gracePeriodMin = $_.GracePeriodRemaining
        }
    })

    $joinState = $null
    try {
        $dsregOutput = (& dsregcmd /status) -join "`n"
        $joinState = [PSCustomObject]@{}
        foreach ($key in @("AzureAdJoined", "DomainJoined", "EnterpriseJoined", "WorkplaceJoined", "MDMUrl", "TenantName", "TenantId")) {
            $pattern = [regex]::Escape($key) + "\s*:\s*(\S+)"
            $matchResult = [regex]::Match($dsregOutput, $pattern)
            if ($matchResult.Success) {
                $joinState | Add-Member -MemberType NoteProperty -Name $key -Value $matchResult.Groups[1].Value
            } else {
                $joinState | Add-Member -MemberType NoteProperty -Name $key -Value $null
            }
        }
    } catch {
        Add-InventoryError -Section "OperatingSystem.JoinState" -Exception $_.Exception
    }

    return [PSCustomObject]@{
        caption             = $os.Caption
        productType         = $osType
        version             = $os.Version
        buildNumber         = $os.BuildNumber
        displayVersion      = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "DisplayVersion"
        releaseId           = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "ReleaseId"
        ubr                 = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "UBR"
        architecture        = $os.OSArchitecture
        installDate         = Get-DateValue -Value $os.InstallDate
        lastBootUpTime      = Get-DateValue -Value $os.LastBootUpTime
        locale              = $os.Locale
        countryCode         = $os.CountryCode
        registeredUser      = $os.RegisteredUser
        organization        = $os.Organization
        domain              = $csDomain
        hotfixes            = $hotfixes
        pendingUpdates      = $pendingUpdates
        updatePolicy        = $updatePolicy
        licensing           = $licensing
        joinState           = $joinState
    }
}

# =============================================================
# Network
# =============================================================

function Get-NetworkInventory {
    $adapters = @()
    try {
        $netConfigs = @(Get-NetIPConfiguration)
        foreach ($config in $netConfigs) {
            $wmiAdapter = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "Index=$($config.InterfaceIndex)"
            $adapters += [PSCustomObject]@{
                interfaceAlias = $config.InterfaceAlias
                interfaceIndex = $config.InterfaceIndex
                status         = $config.NetAdapter.Status
                macAddress     = $config.NetAdapter.MacAddress
                linkSpeed      = $config.NetAdapter.LinkSpeed
                ipv4Addresses  = @($config.IPv4Address | ForEach-Object { $_.IPAddress })
                ipv6Addresses  = @($config.IPv6Address | ForEach-Object { $_.IPAddress })
                ipv4Gateway    = @($config.IPv4DefaultGateway | ForEach-Object { $_.NextHop })
                dnsServers     = @($config.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses })
                dhcpEnabled    = $wmiAdapter.DHCPEnabled
                dhcpServer     = $wmiAdapter.DHCPServer
            }
        }
    } catch {
        Add-InventoryError -Section "Network.Adapters" -Exception $_.Exception
    }

    $firewallProfiles = @()
    try {
        $firewallProfiles = @(Get-NetFirewallProfile | ForEach-Object {
            [PSCustomObject]@{
                name    = $_.Name
                enabled = $_.Enabled
            }
        })
    } catch {
        Add-InventoryError -Section "Network.Firewall" -Exception $_.Exception
    }

    $rdp = $null
    try {
        $fDeny = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections"
        $rdpService = Get-Service -Name TermService -ErrorAction Stop
        $rdp = [PSCustomObject]@{
            enabled     = ($fDeny -eq 0)
            serviceState = $rdpService.Status.ToString()
            port        = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber"
        }
    } catch {
        Add-InventoryError -Section "Network.Rdp" -Exception $_.Exception
    }

    return [PSCustomObject]@{
        adapters         = $adapters
        firewallProfiles = $firewallProfiles
        rdp              = $rdp
    }
}

# =============================================================
# Security
# =============================================================

function Get-SecurityInventory {
    $antivirus = @()
    try {
        $antivirus = @(Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                displayName      = $_.displayName
                productState     = $_.productState
                pathToSignedExe  = $_.pathToSignedProductExe
            }
        })
    } catch {
        Write-Verbose "SecurityCenter2 namespace is not available on server SKUs, using Defender status fallback below."
    }

    $defender = $null
    try {
        $mpStatus = Get-MpComputerStatus -ErrorAction Stop
        $defender = [PSCustomObject]@{
            antivirusEnabled              = $mpStatus.AntivirusEnabled
            antivirusMode                 = $mpStatus.AMRunningMode.ToString()
            realTimeProtectionEnabled     = $mpStatus.RealTimeProtectionEnabled
            antivirusSignatureLastUpdated = Get-DateValue -Value $mpStatus.AntivirusSignatureLastUpdated
            antivirusSignatureVersion     = $mpStatus.AntivirusSignatureVersion
            engineVersion                 = $mpStatus.AMEngineVersion
            productVersion                = $mpStatus.AMProductVersion
            isTamperProtected             = $mpStatus.IsTamperProtected
        }
    } catch {
        Add-InventoryError -Section "Security.Defender" -Exception $_.Exception
    }

    $bitlocker = @()
    $bitlockerNote = $null
    try {
        $bitlocker = @(Get-CimInstance -Namespace "root/CIMV2/Security/MicrosoftVolumeEncryption" -ClassName Win32_EncryptableVolume -ErrorAction Stop | ForEach-Object {
            $protectionMap = @{ 0 = "Off"; 1 = "On"; 2 = "Unknown" }
            $protectionKey = [int]$_.ProtectionStatus
            $protectionText = "Unknown ($($protectionKey))"
            if ($protectionMap.ContainsKey($protectionKey)) { $protectionText = $protectionMap[$protectionKey] }
            [PSCustomObject]@{
                driveLetter      = $_.DriveLetter
                protectionStatus = $protectionText
            }
        })
    } catch {
        if ($_.Exception.Message -match "Namespace|0x8004100E") {
            $bitlockerNote = "BitLocker is not available on this machine (WMI namespace root/CIMV2/Security/MicrosoftVolumeEncryption not found)."
            Write-Host "  BitLocker not available on this machine, skipping."
        } else {
            Add-InventoryError -Section "Security.BitLocker" -Exception $_.Exception
        }
    }

    $localAdmins = @()
    try {
        # SID-basierte Aufloesung + WinNT-ADSI: sprachunabhaengig und ohne WQL-Associator-Fallen
        $adminSid = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $adminAccount = $adminSid.Translate([System.Security.Principal.NTAccount]).Value
        $groupLeaf = ($adminAccount -split "\\")[1]
        $group = [ADSI]"WinNT://$($env:COMPUTERNAME)/$($groupLeaf),group"
        foreach ($member in @($group.Members())) {
            try {
                $memberName = $member.GetType().InvokeMember("Name", "GetProperty", $null, $member, $null)
                $memberPath = $member.GetType().InvokeMember("AdsPath", "GetProperty", $null, $member, $null)
                $memberClass = $member.GetType().InvokeMember("Class", "GetProperty", $null, $member, $null)
                $memberSid = $null
                try {
                    $sidBytes = $member.GetType().InvokeMember("objectSid", "GetProperty", $null, $member, $null)
                    if ($null -ne $sidBytes) {
                        $memberSid = (New-Object System.Security.Principal.SecurityIdentifier($sidBytes, 0)).Value
                    }
                } catch {
                    Write-Verbose "SID for member '$($memberName)' is not available."
                }
                $memberSource = ($memberPath -replace "^WinNT://", "")
                $memberSource = ($memberSource -split "/")[0..($memberSource.Split("/").Count - 2)] -join "/"
                $localAdmins += [PSCustomObject]@{
                    name        = $memberName
                    source      = $memberSource
                    sid         = $memberSid
                    accountType = $memberClass
                }
            } catch {
                Write-Verbose "A member of the local administrators group could not be resolved."
            }
        }
    } catch {
        Add-InventoryError -Section "Security.LocalAdmins" -Exception $_.Exception
    }

    $listeningPorts = @()
    $ephemeralUdpEndpointsOmitted = 0
    try {
        $processMap = @{}
        foreach ($proc in (Get-Process)) {
            if (-not $processMap.ContainsKey($proc.Id)) {
                $processMap[$proc.Id] = $proc.ProcessName
            }
        }
        $tcpListeners = @(Get-NetTCPConnection -State Listen | Sort-Object -Property LocalPort | ForEach-Object {
            $procName = $null
            if ($processMap.ContainsKey($_.OwningProcess)) {
                $procName = $processMap[$_.OwningProcess]
            }
            [PSCustomObject]@{
                localAddress = $_.LocalAddress
                localPort    = $_.LocalPort
                protocol     = "TCP"
                processId    = $_.OwningProcess
                processName  = $procName
            }
        })
        # UDP: nur feste Ports (< 49152). Dynamische RPC-Ports blaehen den Report massiv auf ohne Inventur-Mehrwert.
        $udpAll = @(Get-NetUDPEndpoint)
        $udpListeners = @($udpAll | Where-Object { $_.LocalPort -lt 49152 } | Sort-Object -Property LocalPort | ForEach-Object {
            $procName = $null
            if ($processMap.ContainsKey($_.OwningProcess)) {
                $procName = $processMap[$_.OwningProcess]
            }
            [PSCustomObject]@{
                localAddress = $_.LocalAddress
                localPort    = $_.LocalPort
                protocol     = "UDP"
                processId    = $_.OwningProcess
                processName  = $procName
            }
        })
        $ephemeralUdpEndpointsOmitted = @($udpAll).Count - @($udpListeners).Count
        $listeningPorts = @($tcpListeners + $udpListeners)
    } catch {
        Add-InventoryError -Section "Security.ListeningPorts" -Exception $_.Exception
    }

    return [PSCustomObject]@{
        antivirusProducts = $antivirus
        defender          = $defender
        bitlockerVolumes  = $bitlocker
        bitlockerNote     = $bitlockerNote
        localAdministrators = $localAdmins
        listeningPorts    = $listeningPorts
        ephemeralUdpEndpointsOmitted = $ephemeralUdpEndpointsOmitted
    }
}

# =============================================================
# Software (installed programs, roles/features, IIS)
# =============================================================

function Get-SoftwareInventory {
    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $programs = @()
    try {
        $programs = @(Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue |
            Where-Object {
                $null -ne $_.DisplayName -and
                $_.DisplayName.Trim() -ne "" -and
                (-not $_.PSObject.Properties["SystemComponent"] -or $_.SystemComponent -ne 1) -and
                (-not $_.PSObject.Properties["ParentKeyName"])
            } |
            Sort-Object -Property DisplayName -Unique |
            ForEach-Object {
                [PSCustomObject]@{
                    displayName     = $_.DisplayName
                    displayVersion  = $_.DisplayVersion
                    publisher       = $_.Publisher
                    installDate     = $_.InstallDate
                    installLocation = $_.InstallLocation
                }
            })
    } catch {
        Add-InventoryError -Section "Software.Programs" -Exception $_.Exception
    }

    $rolesAndFeatures = $null
    try {
        if ($null -ne (Get-Command -Name Get-WindowsFeature -ErrorAction SilentlyContinue)) {
            Import-Module ServerManager -ErrorAction SilentlyContinue
            $rolesAndFeatures = @(Get-WindowsFeature | Where-Object { $_.InstallState -eq "Installed" } | ForEach-Object {
                [PSCustomObject]@{
                    name         = $_.Name
                    displayName  = $_.DisplayName
                    featureType  = $_.FeatureType
                }
            })
        } else {
            $rolesAndFeatures = @(Get-WindowsOptionalFeature -Online | Where-Object { $_.State -eq "Enabled" } | ForEach-Object {
                [PSCustomObject]@{
                    name         = $_.FeatureName
                    displayName  = $_.FeatureName
                    featureType  = "OptionalFeature"
                }
            })
        }
    } catch {
        Add-InventoryError -Section "Software.RolesAndFeatures" -Exception $_.Exception
    }

    $iis = $null
    try {
        $w3svc = Get-Service -Name W3SVC -ErrorAction SilentlyContinue
        if ($null -ne $w3svc) {
            $sites = @()
            $appPools = @()
            if ($null -ne (Get-Command -Name Get-Website -ErrorAction SilentlyContinue)) {
                $sites = @(Get-Website | ForEach-Object {
                    [PSCustomObject]@{
                        name     = $_.Name
                        state    = $_.State
                        physicalPath = $_.PhysicalPath
                        bindings = @($_.Bindings.Collection | ForEach-Object { $_.protocol + " " + $_.bindingInformation })
                    }
                })
                $appPools = @(Get-ChildItem -Path "IIS:\AppPools" | ForEach-Object {
                    [PSCustomObject]@{
                        name                = $_.Name
                        state               = $_.State
                        managedRuntimeVersion = $_.ManagedRuntimeVersion
                    }
                })
            }
            $iis = [PSCustomObject]@{
                installed    = $true
                serviceState = $w3svc.Status.ToString()
                sites        = $sites
                appPools     = $appPools
            }
        } else {
            $iis = [PSCustomObject]@{ installed = $false }
        }
    } catch {
        Add-InventoryError -Section "Software.Iis" -Exception $_.Exception
    }

    return [PSCustomObject]@{
        installedProgramsCount = @($programs).Count
        installedPrograms      = $programs
        rolesAndFeatures       = $rolesAndFeatures
        iis                    = $iis
    }
}

# =============================================================
# Services and Azure agents
# =============================================================

function Get-ServicesInventory {
    $autoServices = @()
    try {
        $autoServices = @(Get-CimInstance -ClassName Win32_Service -Filter "StartMode='Auto'" | Sort-Object -Property Name | ForEach-Object {
            [PSCustomObject]@{
                name        = $_.Name
                displayName = $_.DisplayName
                state       = $_.State
                startName   = $_.StartName
                pathName    = $_.PathName
            }
        })
    } catch {
        Add-InventoryError -Section "Services.AutoStart" -Exception $_.Exception
    }

    $interestingServiceNames = @(
        "himds", "AzureMonitorAgent", "HealthService", "WinDefend", "Sense",
        "W3SVC", "MSSQLSERVER", "SQLSERVERAGENT", "wuauserv", "BITS", "Spooler"
    )
    $agentServices = @()
    try {
        foreach ($serviceName in $interestingServiceNames) {
            $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($serviceName)'" -ErrorAction SilentlyContinue
            if ($null -ne $svc) {
                $agentServices += [PSCustomObject]@{
                    name  = $svc.Name
                    state = $svc.State
                    startMode = $svc.StartMode
                }
            }
        }
    } catch {
        Add-InventoryError -Section "Services.Agents" -Exception $_.Exception
    }

    return [PSCustomObject]@{
        autoStartCount     = @($autoServices).Count
        autoStartServices  = $autoServices
        agentServices      = $agentServices
    }
}

function Get-AzureInventory {
    $arc = [PSCustomObject]@{ installed = $false }
    try {
        $arcProgramData = Join-Path $env:ProgramData "AzureConnectedMachineAgent"
        $azcmagentExe = Join-Path $env:ProgramFiles "AzureConnectedMachineAgent\azcmagent.exe"
        if ((Test-Path -Path $arcProgramData) -or (Test-Path -Path $azcmagentExe)) {
            $version = $null
            if (Test-Path -Path $azcmagentExe) {
                $version = (Get-Item -Path $azcmagentExe).VersionInfo.ProductVersion
            }
            $himdsService = Get-Service -Name himds -ErrorAction SilentlyContinue
            $arc = [PSCustomObject]@{
                installed        = $true
                azcmagentVersion = $version
                serviceState     = if ($null -ne $himdsService) { $himdsService.Status.ToString() } else { "NotInstalled" }
            }
        }
    } catch {
        Add-InventoryError -Section "Azure.Arc" -Exception $_.Exception
    }

    $azureMonitorAgent = [PSCustomObject]@{ installed = $false }
    try {
        $amaService = Get-Service -Name AzureMonitorAgent -ErrorAction SilentlyContinue
        $mmaService = Get-Service -Name HealthService -ErrorAction SilentlyContinue
        if ($null -ne $amaService) {
            $azureMonitorAgent = [PSCustomObject]@{
                installed    = $true
                variant      = "AzureMonitorAgent (AMA)"
                serviceState = $amaService.Status.ToString()
            }
        } elseif ($null -ne $mmaService) {
            $azureMonitorAgent = [PSCustomObject]@{
                installed    = $true
                variant      = "Microsoft Monitoring Agent (MMA)"
                serviceState = $mmaService.Status.ToString()
            }
        }
    } catch {
        Add-InventoryError -Section "Azure.AzureMonitorAgent" -Exception $_.Exception
    }

    $imds = $null
    try {
        $imds = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/instance?api-version=2021-02-01" -Headers @{ Metadata = "true" } -Method Get -TimeoutSec 3
        $imds = [PSCustomObject]@{
            isAzureVm     = $true
            vmId          = $imds.compute.vmId
            vmName        = $imds.compute.name
            vmSize        = $imds.compute.vmSize
            location      = $imds.compute.location
            zone          = $imds.compute.zone
            imagePublisher = $imds.compute.imagePublisher
            imageOffer    = $imds.compute.imageOffer
            osType        = $imds.compute.osType
        }
    } catch {
        $imds = [PSCustomObject]@{ isAzureVm = $false }
    }

    return [PSCustomObject]@{
        arc               = $arc
        azureMonitorAgent = $azureMonitorAgent
        azureVmMetadata   = $imds
    }
}

# =============================================================
# Hyper-V (only when the role is active)
# =============================================================

function Get-HyperVInventory {
    $vmmsService = Get-Service -Name vmms -ErrorAction SilentlyContinue
    $hasHyperVModule = $null -ne (Get-Command -Name Get-VM -ErrorAction SilentlyContinue)
    if ($null -eq $vmmsService -or -not $hasHyperVModule) {
        return [PSCustomObject]@{ enabled = $false }
    }

    $hostInfo = $null
    try {
        $vmHost = Get-VMHost
        $hostInfo = [PSCustomObject]@{
            vmmsServiceState      = $vmmsService.Status.ToString()
            logicalProcessorCount = $vmHost.LogicalProcessorCount
            memoryCapacityBytes   = $vmHost.MemoryCapacity
            memoryCapacity        = Format-ByteSize -Bytes $vmHost.MemoryCapacity
            virtualHardDiskPath   = $vmHost.VirtualHardDiskPath
            virtualMachinePath    = $vmHost.VirtualMachinePath
            supportedVmVersions   = @(Get-VMHostSupportedVersion | ForEach-Object { $_.Version })
        }
    } catch {
        Add-InventoryError -Section "HyperV.Host" -Exception $_.Exception
    }

    $virtualMachines = @()
    try {
        $virtualMachines = @(Get-VM | ForEach-Object {
            $vm = $_
            [PSCustomObject]@{
                name                 = $vm.Name
                state                = $vm.State.ToString()
                status               = $vm.Status.ToString()
                uptime               = $vm.Uptime.ToString()
                uptimeDays           = [math]::Round($vm.Uptime.TotalDays, 2)
                processorCount       = $vm.ProcessorCount
                processorLoadPercent = $vm.ProcessorLoad
                memoryStartupBytes   = $vm.MemoryStartup
                memoryStartup        = Format-ByteSize -Bytes $vm.MemoryStartup
                memoryAssignedBytes  = $vm.MemoryAssigned
                memoryAssigned       = Format-ByteSize -Bytes $vm.MemoryAssigned
                dynamicMemoryEnabled = $vm.DynamicMemoryEnabled
                generation           = $vm.Generation
                version              = $vm.Version
                path                 = $vm.Path
                creationTime         = Get-DateValue -Value $vm.CreationTime
                networkAdapters      = @($vm.NetworkAdapters | ForEach-Object {
                    [PSCustomObject]@{
                        name       = $_.Name
                        switchName = $_.SwitchName
                        macAddress = $_.MacAddress
                        ipAddresses = @($_.IPAddresses)
                    }
                })
                hardDrives           = @($vm.HardDrives | ForEach-Object { $_.Path })
            }
        })
    } catch {
        Add-InventoryError -Section "HyperV.VirtualMachines" -Exception $_.Exception
    }

    $switches = @()
    try {
        $switches = @(Get-VMSwitch | ForEach-Object {
            [PSCustomObject]@{
                name                       = $_.Name
                switchType                 = [string]$_.SwitchType
                netAdapterInterfaceDescription = $_.NetAdapterInterfaceDescription
                allowManagementOS          = $_.AllowManagementOS
                extensions                 = @($_.Extensions | ForEach-Object { $_.Name })
            }
        })
    } catch {
        Add-InventoryError -Section "HyperV.Switches" -Exception $_.Exception
    }

    $eventLog = $null
    try {
        $since = (Get-Date).AddDays(-14)

        # Verfuegbare Hyper-V-Logs einzeln ermitteln (RecordCount/IsEnabled koennen pro Log werfen)
        $logNames = @()
        foreach ($log in @(Get-WinEvent -ListLog "Microsoft-Windows-Hyper-V-*" -ErrorAction SilentlyContinue)) {
            try {
                if ($log.IsEnabled -and $log.RecordCount -gt 0) {
                    $logNames += $log.LogName
                }
            } catch {
                Write-Verbose "Log-Status fuer '$($log.LogName)' konnte nicht gelesen werden."
            }
        }

        # Errors/Warnings der letzten 14 Tage (max. 100 Eintraege)
        $errorsWarnings = @()
        foreach ($logName in $logNames) {
            if (@($errorsWarnings).Count -ge 100) { break }
            $entries = @()
            try {
                $entries = @(Get-WinEvent -LogName $logName -MaxEvents 100 -ErrorAction Stop)
            } catch {
                Write-Verbose "Log '$($logName)' konnte nicht gelesen werden."
                continue
            }
            foreach ($entry in $entries) {
                try {
                    if (@($errorsWarnings).Count -ge 100) { break }
                    if ($entry.TimeCreated -lt $since) { break }
                    if ($entry.Level -notin @(1, 2, 3)) { continue }
                    $levelText = switch ([int]$entry.Level) {
                        1 { "Critical" }
                        2 { "Error" }
                        3 { "Warning" }
                        default { [string]$entry.Level }
                    }
                    $messageText = $null
                    try {
                        $messageText = ($entry.Message -split "`n")[0]
                    } catch {
                        Write-Verbose "Message fuer Event $($entry.Id) in '$($logName)' ist nicht verfuegbar."
                    }
                    $errorsWarnings += [PSCustomObject]@{
                        logName     = $logName
                        timeCreated = Get-DateValue -Value $entry.TimeCreated
                        level       = $levelText
                        eventId     = $entry.Id
                        provider    = $entry.ProviderName
                        message     = $messageText
                    }
                } catch {
                    Write-Verbose "Ein Event-Eintrag in '$($logName)' konnte nicht verarbeitet werden."
                }
            }
        }

        # Letzte Aktivitaeten aus VMMS-Admin
        $lastActivities = @()
        try {
            $vmmsEntries = @(Get-WinEvent -LogName "Microsoft-Windows-Hyper-V-VMMS-Admin" -MaxEvents 25 -ErrorAction Stop)
            foreach ($entry in $vmmsEntries) {
                try {
                    if ($entry.TimeCreated -lt $since) { break }
                    $messageText = $null
                    try {
                        $messageText = ($entry.Message -split "`n")[0]
                    } catch {
                        Write-Verbose "Message fuer VMMS-Event $($entry.Id) ist nicht verfuegbar."
                    }
                    $lastActivities += [PSCustomObject]@{
                        timeCreated = Get-DateValue -Value $entry.TimeCreated
                        level       = $entry.Level
                        eventId     = $entry.Id
                        message     = $messageText
                    }
                } catch {
                    Write-Verbose "Ein VMMS-Event-Eintrag konnte nicht verarbeitet werden."
                }
            }
        } catch {
            Write-Verbose "Hyper-V VMMS-Admin-Log ist nicht verfuegbar."
        }

        $eventLog = [PSCustomObject]@{
            windowDays          = 14
            enabledLogs         = $logNames
            errorsWarningsCount = @($errorsWarnings).Count
            errorsWarnings      = $errorsWarnings
            lastActivities      = $lastActivities
        }
    } catch {
        Add-InventoryError -Section "HyperV.EventLog" -Exception $_.Exception
    }

    return [PSCustomObject]@{
        enabled         = $true
        host            = $hostInfo
        virtualMachines = $virtualMachines
        switches        = $switches
        eventLog        = $eventLog
    }
}

# =============================================================
# USB devices and license dongles
# =============================================================

function Get-UsbInventory {
    $devices = @()
    try {
        $devices = @(Get-PnpDevice -PresentOnly -Class USB -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                status       = $_.Status
                friendlyName = $_.FriendlyName
                manufacturer = $_.Manufacturer
                instanceId   = $_.InstanceId
            }
        })
    } catch {
        Add-InventoryError -Section "Usb.Devices" -Exception $_.Exception
    }

    $usbStorage = @()
    try {
        $usbStorage = @(Get-PnpDevice -PresentOnly -ErrorAction Stop |
            Where-Object { $_.InstanceId -like "USBSTOR*" } |
            ForEach-Object {
                [PSCustomObject]@{
                    status       = $_.Status
                    class        = $_.Class
                    friendlyName = $_.FriendlyName
                    instanceId   = $_.InstanceId
                }
            })
    } catch {
        Add-InventoryError -Section "Usb.Storage" -Exception $_.Exception
    }

    # Lizenz-Dongles: VID_0529 = SafeNet/Thales Sentinel, VID_10C4 = Silicon Labs (div. Dongle-Hersteller)
    $dongleDevices = @()
    try {
        $dongleDevices = @(Get-PnpDevice -PresentOnly -ErrorAction Stop |
            Where-Object {
                ($_.InstanceId -match "VID_0529|VID_10C4") -or
                ($_.FriendlyName -match "(?i)(hasp|sentinel|safenet|dongle|silex|wibukey|codemeter|aladdin)")
            } |
            ForEach-Object {
                [PSCustomObject]@{
                    status       = $_.Status
                    class        = $_.Class
                    friendlyName = $_.FriendlyName
                    instanceId   = $_.InstanceId
                }
            })
    } catch {
        Add-InventoryError -Section "Usb.DongleDevices" -Exception $_.Exception
    }

    $licenseServices = @()
    try {
        $licenseServices = @(Get-CimInstance -ClassName Win32_Service |
            Where-Object {
                $_.Name -match "(?i)(hasp|sentinel|silex|codemeter|wibu|flexnet|flexlm|licens)" -or
                $_.DisplayName -match "(?i)(hasp|sentinel|silex|codemeter|wibu|flexnet|flexlm|licens)"
            } |
            ForEach-Object {
                [PSCustomObject]@{
                    name        = $_.Name
                    displayName = $_.DisplayName
                    state       = $_.State
                    startMode   = $_.StartMode
                    startName   = $_.StartName
                }
            })
    } catch {
        Add-InventoryError -Section "Usb.LicenseServices" -Exception $_.Exception
    }

    # Bekannte Lizenz-Ports: 1947 = Sentinel LDK/HASP, 5093 = Sentinel RMS
    $licensePorts = @(1947, 5093)
    $licenseListeners = @()
    $licenseRemoteConnections = @()
    try {
        $processMap = @{}
        foreach ($proc in (Get-Process)) {
            if (-not $processMap.ContainsKey($proc.Id)) {
                $processMap[$proc.Id] = $proc.ProcessName
            }
        }
        $licenseListeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Where-Object { $licensePorts -contains $_.LocalPort } |
            ForEach-Object {
                $procName = $null
                if ($processMap.ContainsKey($_.OwningProcess)) { $procName = $processMap[$_.OwningProcess] }
                [PSCustomObject]@{
                    localAddress = $_.LocalAddress
                    localPort    = $_.LocalPort
                    processId    = $_.OwningProcess
                    processName  = $procName
                }
            })
        $licenseRemoteConnections = @(Get-NetTCPConnection -ErrorAction Stop |
            Where-Object { $_.State -ne "Listen" -and ($licensePorts -contains $_.RemotePort) } |
            ForEach-Object {
                $procName = $null
                if ($processMap.ContainsKey($_.OwningProcess)) { $procName = $processMap[$_.OwningProcess] }
                [PSCustomObject]@{
                    localPort     = $_.LocalPort
                    remoteAddress = $_.RemoteAddress
                    remotePort    = $_.RemotePort
                    state         = [string]$_.State
                    processId     = $_.OwningProcess
                    processName   = $procName
                }
            })
    } catch {
        Add-InventoryError -Section "Usb.LicensePorts" -Exception $_.Exception
    }

    $licenseSoftware = @()
    try {
        $uninstallPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        $licenseSoftware = @(Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue |
            Where-Object {
                $null -ne $_.DisplayName -and
                $_.DisplayName -match "(?i)(sentinel|hasp|silex|codemeter|wibu|flexnet|flexlm|dongle|licens)"
            } |
            Sort-Object -Property DisplayName -Unique |
            ForEach-Object {
                [PSCustomObject]@{
                    displayName    = $_.DisplayName
                    displayVersion = $_.DisplayVersion
                    publisher      = $_.Publisher
                }
            })
    } catch {
        Add-InventoryError -Section "Usb.LicenseSoftware" -Exception $_.Exception
    }

    return [PSCustomObject]@{
        devices        = $devices
        storageDevices = $usbStorage
        licenseDongles = [PSCustomObject]@{
            pnpDevices        = $dongleDevices
            services          = $licenseServices
            listeningPorts    = $licenseListeners
            remoteConnections = $licenseRemoteConnections
            installedSoftware = $licenseSoftware
        }
    }
}

# =============================================================
# SQL Server
# =============================================================

function Invoke-SqlInventoryQuery {
    param(
        [System.Data.SqlClient.SqlConnection]$Connection,
        [string]$Query
    )
    $command = $Connection.CreateCommand()
    $command.CommandText = $Query
    $command.CommandTimeout = 60
    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $command
    $table = New-Object System.Data.DataTable
    $null = $adapter.Fill($table)
    return Convert-DataTableToList -Table $table
}

function Get-SqlServerInventory {
    $instances = New-Object System.Collections.Generic.List[object]
    $instanceNamesPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"

    if (-not (Test-Path -Path $instanceNamesPath)) {
        return [PSCustomObject]@{ installed = $false; instances = @() }
    }

    $instanceRegistry = Get-ItemProperty -Path $instanceNamesPath
    foreach ($property in $instanceRegistry.PSObject.Properties) {
        if ($property.Name -match "^PS") { continue }
        $instanceName = $property.Name
        $instanceId = $property.Value

        $serviceNames = @()
        if ($instanceName -eq "MSSQLSERVER") {
            $serviceNames += "MSSQLSERVER"
            $serviceNames += "SQLSERVERAGENT"
        } else {
            $serviceNames += "MSSQL`$$($instanceName)"
            $serviceNames += "SQLAgent`$$($instanceName)"
        }
        $services = @()
        foreach ($serviceName in $serviceNames) {
            $serviceFilter = "Name='" + $serviceName + "'"
            $svc = Get-CimInstance -ClassName Win32_Service -Filter $serviceFilter -ErrorAction SilentlyContinue
            if ($null -ne $svc) {
                $services += [PSCustomObject]@{
                    name      = $svc.Name
                    state     = $svc.State
                    startName = $svc.StartName
                }
            }
        }

        $tcpPort = $null
        $tcpPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$($instanceId)\MSSQLServer\SuperSocketNetLib\Tcp\IPAll"
        $staticPort = Get-RegistryValue -Path $tcpPath -Name "TcpPort"
        $dynamicPort = Get-RegistryValue -Path $tcpPath -Name "TcpDynamicPorts"
        if (-not [string]::IsNullOrWhiteSpace($staticPort)) {
            $tcpPort = $staticPort
        } elseif (-not [string]::IsNullOrWhiteSpace($dynamicPort)) {
            $tcpPort = "dynamic:$($dynamicPort)"
        }

        $instanceInfo = [ordered]@{
            instanceName = $instanceName
            instanceId   = $instanceId
            tcpPort      = $tcpPort
            services     = $services
            serverInfo   = $null
            databases    = @()
            lastBackups  = @()
            connectError = $null
        }

        $sqlTarget = $hostName
        if ($instanceName -ne "MSSQLSERVER") {
            $sqlTarget = "$($hostName)\$($instanceName)"
        }

        $sqlServiceRunning = $false
        foreach ($svc in $services) {
            if ($svc.name -like "MSSQL*" -and $svc.state -eq "Running") {
                $sqlServiceRunning = $true
            }
        }

        if ($sqlServiceRunning) {
            try {
                $connectionString = "Data Source=$($sqlTarget);Integrated Security=SSPI;Connect Timeout=15"
                $connection = New-Object System.Data.SqlClient.SqlConnection $connectionString
                $connection.Open()
                try {
                    $serverInfo = Invoke-SqlInventoryQuery -Connection $connection -Query "SELECT SERVERPROPERTY('ProductVersion') AS productVersion, SERVERPROPERTY('ProductLevel') AS productLevel, SERVERPROPERTY('Edition') AS edition, SERVERPROPERTY('Collation') AS collation, SERVERPROPERTY('IsClustered') AS isClustered, SERVERPROPERTY('IsHadrEnabled') AS isHadrEnabled"
                    $instanceInfo["serverInfo"] = @($serverInfo)[0]

                    $databases = Invoke-SqlInventoryQuery -Connection $connection -Query @"
DECLARE @sizeResults TABLE (
    databaseName sysname,
    dataSizeMb bigint,
    logSizeMb bigint
)
DECLARE @dbName sysname
DECLARE @sql nvarchar(max)
DECLARE dbCursor CURSOR LOCAL FAST_FORWARD FOR
    SELECT name FROM sys.databases WHERE state = 0
OPEN dbCursor
FETCH NEXT FROM dbCursor INTO @dbName
WHILE @@FETCH_STATUS = 0
BEGIN
    BEGIN TRY
        SET @sql = N'SELECT ''' + REPLACE(@dbName, '''', '''''') + ''' AS databaseName, '
            + N'ISNULL(SUM(CASE WHEN type = 0 THEN CONVERT(bigint, size) END) * 8 / 1024, 0) AS dataSizeMb, '
            + N'ISNULL(SUM(CASE WHEN type = 1 THEN CONVERT(bigint, size) END) * 8 / 1024, 0) AS logSizeMb '
            + N'FROM ' + QUOTENAME(@dbName) + N'.sys.database_files'
        INSERT INTO @sizeResults EXEC (@sql)
    END TRY
    BEGIN CATCH
        INSERT INTO @sizeResults (databaseName, dataSizeMb, logSizeMb) VALUES (@dbName, NULL, NULL)
    END CATCH
    FETCH NEXT FROM dbCursor INTO @dbName
END
CLOSE dbCursor
DEALLOCATE dbCursor
SELECT
    d.name AS databaseName,
    d.state_desc AS state,
    d.recovery_model_desc AS recoveryModel,
    d.compatibility_level AS compatibilityLevel,
    s.dataSizeMb AS dataSizeMb,
    s.logSizeMb AS logSizeMb
FROM sys.databases d
LEFT JOIN @sizeResults s ON s.databaseName = d.name
ORDER BY d.name
"@
                    $instanceInfo["databases"] = $databases

                    $lastBackups = Invoke-SqlInventoryQuery -Connection $connection -Query @"
SELECT
    database_name AS databaseName,
    type AS backupType,
    MAX(backup_finish_date) AS lastBackupFinishDate
FROM msdb.dbo.backupset
GROUP BY database_name, type
ORDER BY database_name, type
"@
                    $instanceInfo["lastBackups"] = $lastBackups
                } finally {
                    $connection.Close()
                    $connection.Dispose()
                }
            } catch {
                $instanceInfo["connectError"] = $_.Exception.Message
                Add-InventoryError -Section "SqlServer.$($instanceName)" -Exception $_.Exception
            }
        } else {
            $instanceInfo["connectError"] = "SQL Server service is not running"
        }

        $instances.Add([PSCustomObject]$instanceInfo)
    }

    $analysisInstances = @()
    $olapPath = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\OLAP"
    if (Test-Path -Path $olapPath) {
        $olapRegistry = Get-ItemProperty -Path $olapPath
        foreach ($property in $olapRegistry.PSObject.Properties) {
            if ($property.Name -match "^PS") { continue }
            $analysisInstances += $property.Name
        }
    }

    return [PSCustomObject]@{
        installed               = $true
        instances               = $instances
        analysisServicesInstances = $analysisInstances
    }
}

# =============================================================
# Entra ID login (inline OAuth 2.0, no external modules)
# =============================================================

function ConvertTo-Base64Url {
    param(
        [byte[]]$Bytes
    )
    return [Convert]::ToBase64String($Bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function Get-HttpErrorBody {
    param(
        $ErrorRecord
    )
    # WICHTIG: ErrorDetails haengt am ErrorRecord ($_), NICHT an $_.Exception (PowerShell 5.1 + 7)
    $body = $null
    try {
        if ($null -ne $ErrorRecord -and $null -ne $ErrorRecord.ErrorDetails -and -not [string]::IsNullOrWhiteSpace($ErrorRecord.ErrorDetails.Message)) {
            $body = $ErrorRecord.ErrorDetails.Message
        }
    } catch {
        Write-Verbose "ErrorDetails are not available."
    }
    if ([string]::IsNullOrWhiteSpace($body)) {
        try {
            $response = $null
            if ($null -ne $ErrorRecord -and $null -ne $ErrorRecord.Exception) {
                $response = $ErrorRecord.Exception.Response
            }
            if ($null -ne $response) {
                if ($response -is [System.Net.HttpWebResponse]) {
                    $stream = $response.GetResponseStream()
                    try { $stream.Position = 0 } catch { Write-Verbose "Response stream is not seekable." }
                    $reader = New-Object System.IO.StreamReader($stream, [Text.Encoding]::UTF8)
                    $body = $reader.ReadToEnd()
                    $reader.Close()
                } elseif ($response -is [System.Net.Http.HttpResponseMessage]) {
                    $body = $response.Content.ReadAsStringAsync().Result
                }
            }
        } catch {
            Write-Verbose "Could not read the HTTP error response body."
        }
    }
    return $body
}

function Get-InlineOAuthError {
    param(
        $ErrorRecord
    )
    $errorBody = Get-HttpErrorBody -ErrorRecord $ErrorRecord
    $errorObject = $null
    if (-not [string]::IsNullOrWhiteSpace($errorBody)) {
        try {
            $errorObject = $errorBody | ConvertFrom-Json
        } catch {
            Write-Verbose "Could not parse the OAuth error response body as JSON."
        }
    }
    return $errorObject
}

function Get-DeviceCodeToken {
    param(
        [string]$Tenant,
        [string]$ClientId,
        [string]$Scope
    )
    $deviceCodeUri = "https://login.microsoftonline.com/$($Tenant)/oauth2/v2.0/devicecode"
    $tokenUri = "https://login.microsoftonline.com/$($Tenant)/oauth2/v2.0/token"

    $deviceCodeResponse = Invoke-RestMethod -Method Post -Uri $deviceCodeUri -Body @{
        client_id = $ClientId
        scope     = $Scope
    }

    Write-Host ""
    Write-Host $deviceCodeResponse.message
    Write-Host ""

    $interval = 5
    if ($null -ne $deviceCodeResponse.interval) {
        $interval = [int]$deviceCodeResponse.interval
        if ($interval -lt 1) { $interval = 5 }
    }
    $expiresIn = 900
    if ($null -ne $deviceCodeResponse.expires_in) {
        $expiresIn = [int]$deviceCodeResponse.expires_in
    }
    $deadline = (Get-Date).AddSeconds($expiresIn)

    $waitCount = 0
    while ($true) {
        Start-Sleep -Seconds $interval
        if ((Get-Date) -gt $deadline) {
            throw "Device code expired before the login was completed."
        }
        try {
            $tokenResponse = Invoke-RestMethod -Method Post -Uri $tokenUri -Body @{
                grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
                device_code = $deviceCodeResponse.device_code
                client_id   = $ClientId
            }
            return $tokenResponse.access_token
        } catch {
            $oauthError = Get-InlineOAuthError -ErrorRecord $_
            $oauthErrorCode = $null
            if ($null -ne $oauthError -and $null -ne $oauthError.error) {
                $oauthErrorCode = [string]$oauthError.error
            }
            if ($oauthErrorCode -eq "authorization_pending") {
                $waitCount++
                if (($waitCount % 3) -eq 1) {
                    Write-Host ("  [{0:HH:mm:ss}] Waiting for authentication... Please open {1} and enter the code '{2}'." -f (Get-Date), $deviceCodeResponse.verification_uri, $deviceCodeResponse.user_code)
                }
                continue
            } elseif ($oauthErrorCode -eq "slow_down") {
                $interval += 5
                continue
            } else {
                $detail = ""
                if ($null -ne $oauthError) {
                    $detail = "OAuth error: $($oauthErrorCode) - $($oauthError.error_description)"
                } else {
                    $rawBody = Get-HttpErrorBody -ErrorRecord $_
                    if (-not [string]::IsNullOrWhiteSpace($rawBody)) {
                        $detail = "Response body: $($rawBody)"
                    }
                }
                throw "Entra ID device code login failed. $($_.Exception.Message) $($detail)"
            }
        }
    }
}

function Get-InteractiveBrowserToken {
    param(
        [string]$Tenant,
        [string]$ClientId,
        [string]$Scope
    )
    $tokenUri = "https://login.microsoftonline.com/$($Tenant)/oauth2/v2.0/token"

    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $verifierBytes = New-Object byte[] 32
    $rng.GetBytes($verifierBytes)
    $codeVerifier = ConvertTo-Base64Url -Bytes $verifierBytes
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $codeChallenge = ConvertTo-Base64Url -Bytes ($sha256.ComputeHash([Text.Encoding]::ASCII.GetBytes($codeVerifier)))
    $state = [Guid]::NewGuid().ToString("N")

    $listenerPort = Get-Random -Minimum 50000 -Maximum 60000
    $redirectUri = "http://localhost:$($listenerPort)/"
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($redirectUri)
    try {
        $listener.Start()
    } catch {
        throw "Could not start the local HTTP listener on port $($listenerPort) for the interactive login (may require administrator privileges). Use -AuthMode DeviceCode instead. Inner error: $($_.Exception.Message)"
    }

    try {
        $authorizeUri = "https://login.microsoftonline.com/$($Tenant)/oauth2/v2.0/authorize" +
            "?client_id=" + [uri]::EscapeDataString($ClientId) +
            "&response_type=code" +
            "&redirect_uri=" + [uri]::EscapeDataString($redirectUri) +
            "&scope=" + [uri]::EscapeDataString($Scope) +
            "&state=" + $state +
            "&code_challenge=" + $codeChallenge +
            "&code_challenge_method=S256" +
            "&prompt=select_account"

        Write-Host "Opening the browser for the Entra ID login. If the browser does not open, navigate to:"
        Write-Host $authorizeUri
        Start-Process $authorizeUri

        $contextTask = $listener.GetContextAsync()
        if (-not $contextTask.Wait([TimeSpan]::FromMinutes(10))) {
            throw "Interactive login timed out after 10 minutes."
        }
        $context = $contextTask.Result

        $authCode = $null
        $returnedState = $null
        $authError = $null
        $query = $context.Request.Url.Query.TrimStart("?")
        foreach ($pair in ($query -split "&")) {
            $kv = $pair -split "=", 2
            if ($kv.Count -lt 2) {
                continue
            }
            if ($kv[0] -eq "code") { $authCode = [uri]::UnescapeDataString($kv[1]) }
            elseif ($kv[0] -eq "state") { $returnedState = $kv[1] }
            elseif ($kv[0] -eq "error") { $authError = [uri]::UnescapeDataString($kv[1]) }
        }

        $html = "<html><body><h3>Login abgeschlossen. Dieses Fenster kann geschlossen werden.</h3></body></html>"
        $buffer = [Text.Encoding]::UTF8.GetBytes($html)
        $context.Response.StatusCode = 200
        $context.Response.ContentType = "text/html; charset=utf-8"
        $context.Response.ContentLength64 = $buffer.Length
        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
        $context.Response.OutputStream.Close()

        if (-not [string]::IsNullOrWhiteSpace($authError)) {
            throw "Interactive login failed: $($authError)"
        }
        if ($returnedState -ne $state) {
            throw "Interactive login failed: state mismatch."
        }
        if ([string]::IsNullOrWhiteSpace($authCode)) {
            throw "Interactive login failed: no authorization code received."
        }

        try {
            $tokenResponse = Invoke-RestMethod -Method Post -Uri $tokenUri -Body @{
                grant_type    = "authorization_code"
                code          = $authCode
                redirect_uri  = $redirectUri
                client_id     = $ClientId
                code_verifier = $codeVerifier
            }
        } catch {
            $oauthError = Get-InlineOAuthError -ErrorRecord $_
            if ($null -ne $oauthError -and $null -ne $oauthError.error) {
                throw "Entra ID interactive login failed: $($oauthError.error) - $($oauthError.error_description)"
            }
            $rawBody = Get-HttpErrorBody -ErrorRecord $_
            if (-not [string]::IsNullOrWhiteSpace($rawBody)) {
                throw "Entra ID interactive login failed. $($_.Exception.Message) Response body: $($rawBody)"
            }
            throw
        }
        return $tokenResponse.access_token
    } finally {
        if ($listener.IsListening) {
            $listener.Stop()
        }
        $listener.Close()
    }
}

function Get-InlineEntraToken {
    param(
        [string]$Mode,
        [string]$Tenant
    )
    # First-Party Public Client (Microsoft Azure CLI), unterstuetzt Device-Code- und Authorization-Code-Flow mit PKCE
    $clientId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
    # Azure DevOps Ressource
    $scope = "499b84ac-1321-427f-aa17-267ca6975798/.default"
    $tenantValue = "common"
    if (-not [string]::IsNullOrWhiteSpace($Tenant)) {
        $tenantValue = $Tenant
    }
    if ($Mode -eq "DeviceCode") {
        Write-Host "Signing in to Entra ID using the device code flow..."
        return Get-DeviceCodeToken -Tenant $tenantValue -ClientId $clientId -Scope $scope
    } else {
        Write-Host "Signing in to Entra ID using the interactive browser login..."
        return Get-InteractiveBrowserToken -Tenant $tenantValue -ClientId $clientId -Scope $scope
    }
}

# =============================================================
# Upload to Azure DevOps
# =============================================================

function Invoke-DevOpsRest {
    param(
        [string]$Method,
        [string]$Uri,
        [hashtable]$Headers,
        [string]$Body
    )
    try {
        if (-not [string]::IsNullOrWhiteSpace($Body)) {
            $bodyBytes = [Text.Encoding]::UTF8.GetBytes($Body)
            return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers -Body $bodyBytes -ContentType "application/json; charset=utf-8"
        } else {
            return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers -ContentType "application/json; charset=utf-8"
        }
    } catch {
        $detail = ""
        $rawBody = Get-HttpErrorBody -ErrorRecord $_
        if (-not [string]::IsNullOrWhiteSpace($rawBody)) {
            $detail = " Response body: $($rawBody)"
        }
        throw "Azure DevOps REST call failed ($($Method)). $($_.Exception.Message)$($detail)"
    }
}

function Invoke-DevOpsUpload {
    param(
        [string]$JsonContent,
        [string]$RepoFilePath,
        [string]$CommitMessage
    )

    $accessToken = Get-InlineEntraToken -Mode $AuthMode -Tenant $TenantId
    $headers = @{
        Authorization = "Bearer " + $accessToken
    }

    $repoBase = "https://dev.azure.com/$($DevOpsOrganization)/$($DevOpsProject)/_apis/git/repositories/$($DevOpsRepository)"
    $branchRefName = "refs/heads/$($DevOpsBranch)"

    # 1) Aktuellen HEAD des Ziel-Branches ermitteln
    Write-Host "Determining HEAD of branch '$($DevOpsBranch)'..."
    $refsUri = "$($repoBase)/refs?filter=" + [uri]::EscapeDataString("heads/$($DevOpsBranch)") + "&api-version=7.1"
    $refsResponse = Invoke-DevOpsRest -Method "Get" -Uri $refsUri -Headers $headers
    $branchHead = $null
    foreach ($ref in @($refsResponse.value)) {
        if ($ref.name -eq $branchRefName) {
            $branchHead = $ref.objectId
        }
    }
    if ([string]::IsNullOrWhiteSpace($branchHead)) {
        throw "Branch '$($DevOpsBranch)' was not found in repository '$($DevOpsRepository)'."
    }

    # 2) Pruefen, ob die Datei auf dem Branch bereits existiert (add oder edit)
    $changeType = "add"
    try {
        $itemsUri = "$($repoBase)/items?path=" + [uri]::EscapeDataString($RepoFilePath) + "&versionDescriptor.version=" + [uri]::EscapeDataString($DevOpsBranch) + "&versionDescriptor.versionType=branch&api-version=7.1"
        $null = Invoke-RestMethod -Method Get -Uri $itemsUri -Headers $headers
        $changeType = "edit"
    } catch {
        $changeType = "add"
    }

    # 3) Commit ueber die Pushes-API (erzeugt oder ueberschreibt die Datei)
    Write-Host "Uploading $($RepoFilePath) to branch '$($DevOpsBranch)' (changeType: $($changeType))..."
    $pushPayload = @{
        refUpdates = @(@{
            name        = $branchRefName
            oldObjectId = $branchHead
        })
        commits    = @(@{
            comment = $CommitMessage
            changes = @(@{
                changeType = $changeType
                item       = @{ path = $RepoFilePath }
                newContent = @{ content = $JsonContent; contentType = "rawtext" }
            })
        })
    } | ConvertTo-Json -Depth 10

    $pushesUri = "$($repoBase)/pushes?api-version=7.1"
    return Invoke-DevOpsRest -Method "Post" -Uri $pushesUri -Headers $headers -Body $pushPayload
}

# =============================================================
# Main flow
# =============================================================

$csDomain = (Get-CimInstance -ClassName Win32_ComputerSystem).Domain

Write-Section "Hardware"
$hardware = $null
try {
    $hardware = Get-HardwareInventory
} catch {
    Add-InventoryError -Section "Hardware" -Exception $_.Exception
}

Write-Section "Operating System"
$operatingSystem = $null
try {
    $operatingSystem = Get-OperatingSystemInventory -ScanPendingUpdates $IncludePendingUpdates
} catch {
    Add-InventoryError -Section "OperatingSystem" -Exception $_.Exception
}

Write-Section "Network"
$network = $null
try {
    $network = Get-NetworkInventory
} catch {
    Add-InventoryError -Section "Network" -Exception $_.Exception
}

Write-Section "Security"
$security = $null
try {
    $security = Get-SecurityInventory
} catch {
    Add-InventoryError -Section "Security" -Exception $_.Exception
}

Write-Section "Software"
$software = $null
try {
    $software = Get-SoftwareInventory
} catch {
    Add-InventoryError -Section "Software" -Exception $_.Exception
}

Write-Section "Services and Roles"
$services = $null
try {
    $services = Get-ServicesInventory
} catch {
    Add-InventoryError -Section "Services" -Exception $_.Exception
}

Write-Section "Azure Agents"
$azure = $null
try {
    $azure = Get-AzureInventory
} catch {
    Add-InventoryError -Section "Azure" -Exception $_.Exception
}

Write-Section "Hyper-V"
$hyperV = $null
try {
    $hyperV = Get-HyperVInventory
    if ($hyperV.enabled) {
        Write-Host "  Hyper-V role active: $(@($hyperV.virtualMachines).Count) VM(s) found."
    } else {
        Write-Host "  Hyper-V role not active, skipping."
    }
} catch {
    Add-InventoryError -Section "HyperV" -Exception $_.Exception
}

Write-Section "USB Devices and License Dongles"
$usb = $null
try {
    $usb = Get-UsbInventory
} catch {
    Add-InventoryError -Section "Usb" -Exception $_.Exception
}

$sqlServer = [PSCustomObject]@{ installed = $false; instances = @() }
if ($IncludeSql) {
    Write-Section "SQL Server"
    try {
        $sqlServer = Get-SqlServerInventory
    } catch {
        Add-InventoryError -Section "SqlServer" -Exception $_.Exception
    }
}

$inventory = [ordered]@{
    schemaVersion     = "1.1"
    collector         = "$($scriptName) v1.1"
    collectedAtLocal  = (Get-Date).ToString("o")
    collectedAtUtc    = (Get-Date).ToUniversalTime().ToString("o")
    hostName          = $hostName
    hardware          = $hardware
    operatingSystem   = $operatingSystem
    network           = $network
    security          = $security
    software          = $software
    servicesAndRoles  = $services
    azure             = $azure
    hyperV            = $hyperV
    usb               = $usb
    sqlServer         = $sqlServer
    errors            = @($inventoryErrors)
}

$jsonContent = ConvertTo-Json -InputObject $inventory -Depth 20

$fileName = "$($hostName)_$($dateStamp).json"
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath $fileName
}
$null = New-Item -Path (Split-Path -Path $OutputPath -Parent) -ItemType Directory -Force -ErrorAction SilentlyContinue
[System.IO.File]::WriteAllText($OutputPath, $jsonContent, (New-Object System.Text.UTF8Encoding($true)))
Write-Host "Inventory JSON written to: $($OutputPath)"

$uploaded = $false
$uploadError = $null
$commitId = $null
$repoFilePath = $null
if ($Upload) {
    if ([string]::IsNullOrWhiteSpace($DevOpsOrganization) -or [string]::IsNullOrWhiteSpace($DevOpsProject) -or [string]::IsNullOrWhiteSpace($DevOpsRepository)) {
        $uploadError = "Upload skipped: DevOpsOrganization, DevOpsProject and DevOpsRepository must be set when Upload is true."
        Write-Warning $uploadError
        $inventoryErrors.Add($uploadError)
    } else {
        $repoDirectory = $DevOpsRepoDirectory.Trim("/")
        $repoFilePath = "/$($repoDirectory)/$($fileName)"
        $commitMessage = "chore(inventory): $($hostName) $($dateStamp)"
        try {
            $uploadResponse = Invoke-DevOpsUpload -JsonContent $jsonContent -RepoFilePath $repoFilePath -CommitMessage $commitMessage
            $uploaded = $true
            if ($null -ne $uploadResponse -and @($uploadResponse.commits).Count -gt 0) {
                $commitId = @($uploadResponse.commits)[0].commitId
            }
            Write-Host "Upload successful: $($repoFilePath) (branch '$($DevOpsBranch)')"
            if (-not [string]::IsNullOrWhiteSpace($commitId)) {
                Write-Host "Commit: $($commitId)"
            }
        } catch {
            $uploadError = $_.Exception.Message
            Add-InventoryError -Section "Upload" -Exception $_.Exception
        }
    }
} else {
    Write-Host "Upload skipped (Upload is false)."
}

$result = [PSCustomObject]@{
    hostName      = $hostName
    jsonFile      = $OutputPath
    uploaded      = $uploaded
    repoFilePath  = $repoFilePath
    commitId      = $commitId
    uploadError   = $uploadError
    sectionErrors = @($inventoryErrors)
}

$result
