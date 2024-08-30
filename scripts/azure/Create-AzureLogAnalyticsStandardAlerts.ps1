#Requires -Version 2.0

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


    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    10.11.2023 Konrad Brunner       Initial Version
    14.03.2024 Konrad Brunner       Fixes, general rework, added new workspaces
    09.04.2024 Konrad Brunner       Added Linux definitions

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\data\azure\Create-AzureLogAnalyticsStandardAlerts-$($AlyaTimeString).log" | Out-Null

# Constants
$AlertResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
$WrkspcResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
$WrkspcName = "$($AlyaNamingPrefix)loga$($AlyaResIdLogAnalytics)"
$ActionGroupResourceGroupName = "$($AlyaNamingPrefix)resg$($AlyaResIdAuditing)"
$ActionGroupName = "AlertSupportByMail"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.OperationalInsights"
Install-ModuleIfNotInstalled "Az.Monitor"
Install-ModuleIfNotInstalled "Az.Resources"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "LogAnalytics | Create-AzureLogAnalyticsStandardAlerts | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Definitions
$windowsWorkSpaceConfigJson = @"
{
  "Events": [
    {
      "EventLogName": "Application",
      "Error": true,
      "Warning": true,
      "Information": true
    },
    {
      "EventLogName": "Microsoft-Windows-ClusterAwareUpdating/Admin",
      "Error": true,
      "Warning": true,
      "Information": true
    },
    {
      "EventLogName": "Microsoft-Windows-Desired State Configuration/Operational",
      "Error": true,
      "Warning": true,
      "Information": true
    },
    {
      "EventLogName": "Microsoft-Windows-FailoverClustering-CsvFs/Operational",
      "Error": true,
      "Warning": true,
      "Information": true
    },
    {
      "EventLogName": "Microsoft-Windows-FailoverClustering/Operational",
      "Error": true,
      "Warning": true,
      "Information": true
    },
    {
      "EventLogName": "Microsoft-Windows-GroupPolicy/Operational",
      "Error": true,
      "Warning": true,
      "Information": true
    },
    {
      "EventLogName": "Microsoft-Windows-Hyper-V-Config/Admin",
      "Error": true,
      "Warning": true,
      "Information": true
    },
    {
      "EventLogName": "Microsoft-Windows-Hyper-V-High-Availability/Admin",
      "Error": true,
      "Warning": true,
      "Information": true
    },
    {
      "EventLogName": "Microsoft-Windows-Hyper-V-Integration/Admin",
      "Error": true,
      "Warning": true,
      "Information": true
    },
    {
      "EventLogName": "Microsoft-Windows-Hyper-V-Shared-VHDX/Operational",
      "Error": true,
      "Warning": true,
      "Information": false
    },
    {
      "EventLogName": "Microsoft-Windows-Hyper-V-SynthNic/Admin",
      "Error": true,
      "Warning": true,
      "Information": false
    },
    {
      "EventLogName": "Microsoft-Windows-Hyper-V-VMMS/Admin",
      "Error": true,
      "Warning": true,
      "Information": true
    },
    {
      "EventLogName": "Microsoft-Windows-Hyper-V-VMMS/Networking",
      "Error": true,
      "Warning": true,
      "Information": false
    },
    {
      "EventLogName": "Microsoft-Windows-Hyper-V-VMMS/Storage",
      "Error": true,
      "Warning": true,
      "Information": false
    },
    {
      "EventLogName": "Microsoft-Windows-Hyper-V-Worker-Admin",
      "Error": true,
      "Warning": true,
      "Information": true
    },
    {
      "EventLogName": "Microsoft-Windows-NetworkProfile/Operational",
      "Error": true,
      "Warning": true,
      "Information": true
    },
    {
      "EventLogName": "Microsoft-Windows-SMBServer/Operational",
      "Error": true,
      "Warning": true,
      "Information": false
    },
    {
      "EventLogName": "Microsoft-Windows-TaskScheduler/Operational",
      "Error": true,
      "Warning": true,
      "Information": true
    },
    {
      "EventLogName": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
      "Error": true,
      "Warning": true,
      "Information": true
    },
    {
      "EventLogName": "Microsoft-Windows-VHDMP/Operational",
      "Error": true,
      "Warning": true,
      "Information": true
    },
    {
      "EventLogName": "MSNIPAK",
      "Error": true,
      "Warning": true,
      "Information": true
    },
    {
      "EventLogName": "Operations Manager",
      "Error": true,
      "Warning": true,
      "Information": true
    },
    {
      "EventLogName": "Setup",
      "Error": true,
      "Warning": true,
      "Information": true
    },
    {
      "EventLogName": "System",
      "Error": true,
      "Warning": true,
      "Information": true
    }
  ],
  "PerformanceCounters": [
    {
      "ObjectName": "Cluster CSV File System",
      "CounterName": "IO Read Bytes/sec",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "Cluster CSV File System",
      "CounterName": "IO Read Latency",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "Cluster CSV File System",
      "CounterName": "IO Reads/sec",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "Cluster CSV File System",
      "CounterName": "IO Write Bytes/sec",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "Cluster CSV File System",
      "CounterName": "IO Write Latency",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "Cluster CSV File System",
      "CounterName": "IO Writes/sec",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "Hyper-V Dynamic Memory VM",
      "CounterName": "Guest Visible Physical Memory",
      "InstanceName": "*",
      "intervalSeconds": 1800
    },
    {
      "ObjectName": "Hyper-V Dynamic Memory VM",
      "CounterName": "Physical Memory",
      "InstanceName": "*",
      "intervalSeconds": 1800
    },
    {
      "ObjectName": "Hyper-V Hypervisor Logical Processor",
      "CounterName": "% Total Run Time",
      "InstanceName": "*",
      "intervalSeconds": 60
    },
    {
      "ObjectName": "Hyper-V Hypervisor Virtual Processor",
      "CounterName": "% Total Run Time",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "Hyper-V Virtual Storage Device",
      "CounterName": "Read Bytes/sec",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "Hyper-V Virtual Storage Device",
      "CounterName": "Read Operations/Sec",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "Hyper-V Virtual Storage Device",
      "CounterName": "Write Bytes/sec",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "Hyper-V Virtual Storage Device",
      "CounterName": "Write Operations/Sec",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "LogicalDisk",
      "CounterName": "% Free Space",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "LogicalDisk",
      "CounterName": "Avg. Disk sec/Read",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "LogicalDisk",
      "CounterName": "Avg. Disk sec/Transfer",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "LogicalDisk",
      "CounterName": "Avg. Disk sec/Write",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "LogicalDisk",
      "CounterName": "Current Disk Queue Length",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "LogicalDisk",
      "CounterName": "Disk Bytes/sec",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "LogicalDisk",
      "CounterName": "Disk Read Bytes/sec",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "LogicalDisk",
      "CounterName": "Disk Reads/sec",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "LogicalDisk",
      "CounterName": "Disk Transfers/sec",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "LogicalDisk",
      "CounterName": "Disk Write Bytes/sec",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "LogicalDisk",
      "CounterName": "Disk Writes/sec",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "LogicalDisk",
      "CounterName": "Free Megabytes",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "Memory",
      "CounterName": "% Committed Bytes In Use",
      "InstanceName": "*",
      "intervalSeconds": 1800
    },
    {
      "ObjectName": "Memory",
      "CounterName": "Available MBytes",
      "InstanceName": "*",
      "intervalSeconds": 1800
    },
    {
      "ObjectName": "Memory",
      "CounterName": "Commit Limit",
      "InstanceName": "*",
      "intervalSeconds": 1800
    },
    {
      "ObjectName": "Memory",
      "CounterName": "Committed Bytes",
      "InstanceName": "*",
      "intervalSeconds": 1800
    },
    {
      "ObjectName": "Network Adapter",
      "CounterName": "Bytes Received/sec",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "Network Adapter",
      "CounterName": "Bytes Sent/sec",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "Network Interface",
      "CounterName": "Bytes Total/sec",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "NUMA Node Memory",
      "CounterName": "Available MBytes",
      "InstanceName": "_Total",
      "intervalSeconds": 1800
    },
    {
      "ObjectName": "NUMA Node Memory",
      "CounterName": "Total MBytes",
      "InstanceName": "_Total",
      "intervalSeconds": 1800
    },
    {
      "ObjectName": "Processor",
      "CounterName": "% Processor Time",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "Processor",
      "CounterName": "% Processor Time",
      "InstanceName": "_Total",
      "intervalSeconds": 60
    },
    {
      "ObjectName": "System",
      "CounterName": "Processor Queue Length",
      "InstanceName": "*",
      "intervalSeconds": 300
    },
    {
      "ObjectName": "TCPv4",
      "CounterName": "Connections Established",
      "InstanceName": "*",
      "intervalSeconds": 300
    }
  ]
}
"@
$windowsWorkSpaceConfig = $windowsWorkSpaceConfigJson | ConvertFrom-Json

$linuxWorkSpaceConfigJson = @"
{
  "Syslogs": [
    {
      "Facility": "kern",
      "Emergency": true,
      "Alert": true,
      "Critical": true,
      "Error": true,
      "Warning": true,
      "Notice": false,
      "Info": false,
      "Debug": false
    },
    {
      "Facility": "user",
      "Emergency": true,
      "Alert": true,
      "Critical": true,
      "Error": true,
      "Warning": true,
      "Notice": false,
      "Info": false,
      "Debug": false
    },
    {
      "Facility": "daemon",
      "Emergency": true,
      "Alert": true,
      "Critical": true,
      "Error": true,
      "Warning": true,
      "Notice": false,
      "Info": false,
      "Debug": false
    },
    {
      "Facility": "auth",
      "Emergency": true,
      "Alert": true,
      "Critical": true,
      "Error": true,
      "Warning": true,
      "Notice": false,
      "Info": false,
      "Debug": false
    },
    {
      "Facility": "syslog",
      "Emergency": true,
      "Alert": true,
      "Critical": true,
      "Error": true,
      "Warning": true,
      "Notice": false,
      "Info": false,
      "Debug": false
    },
    {
      "Facility": "uucp",
      "Emergency": true,
      "Alert": true,
      "Critical": true,
      "Error": true,
      "Warning": true,
      "Notice": false,
      "Info": false,
      "Debug": false
    },
    {
      "Facility": "authpriv",
      "Emergency": true,
      "Alert": true,
      "Critical": true,
      "Error": true,
      "Warning": true,
      "Notice": false,
      "Info": false,
      "Debug": false
    },
    {
      "Facility": "ftp",
      "Emergency": true,
      "Alert": true,
      "Critical": true,
      "Error": true,
      "Warning": true,
      "Notice": false,
      "Info": false,
      "Debug": false
    },
    {
      "Facility": "cron",
      "Emergency": true,
      "Alert": true,
      "Critical": true,
      "Error": true,
      "Warning": true,
      "Notice": false,
      "Info": false,
      "Debug": false
    },
    {
      "Facility": "local0",
      "Emergency": true,
      "Alert": true,
      "Critical": true,
      "Error": true,
      "Warning": true,
      "Notice": false,
      "Info": false,
      "Debug": false
    },
    {
      "Facility": "local1",
      "Emergency": true,
      "Alert": true,
      "Critical": true,
      "Error": true,
      "Warning": true,
      "Notice": false,
      "Info": false,
      "Debug": false
    },
    {
      "Facility": "local2",
      "Emergency": true,
      "Alert": true,
      "Critical": true,
      "Error": true,
      "Warning": true,
      "Notice": false,
      "Info": false,
      "Debug": false
    },
    {
      "Facility": "local3",
      "Emergency": true,
      "Alert": true,
      "Critical": true,
      "Error": true,
      "Warning": true,
      "Notice": false,
      "Info": false,
      "Debug": false
    },
    {
      "Facility": "local4",
      "Emergency": true,
      "Alert": true,
      "Critical": true,
      "Error": true,
      "Warning": true,
      "Notice": false,
      "Info": false,
      "Debug": false
    },
    {
      "Facility": "local5",
      "Emergency": true,
      "Alert": true,
      "Critical": true,
      "Error": true,
      "Warning": true,
      "Notice": false,
      "Info": false,
      "Debug": false
    },
    {
      "Facility": "local6",
      "Emergency": true,
      "Alert": true,
      "Critical": true,
      "Error": true,
      "Warning": true,
      "Notice": false,
      "Info": false,
      "Debug": false
    },
    {
      "Facility": "local7",
      "Emergency": true,
      "Alert": true,
      "Critical": true,
      "Error": true,
      "Warning": true,
      "Notice": false,
      "Info": false,
      "Debug": false
    },
    {
      "Facility": "lpr",
      "Emergency": true,
      "Alert": true,
      "Critical": true,
      "Error": true,
      "Warning": true,
      "Notice": false,
      "Info": false,
      "Debug": false
    },
    {
      "Facility": "mail",
      "Emergency": true,
      "Alert": true,
      "Critical": true,
      "Error": true,
      "Warning": true,
      "Notice": false,
      "Info": false,
      "Debug": false
    },
    {
      "Facility": "news",
      "Emergency": true,
      "Alert": true,
      "Critical": true,
      "Error": true,
      "Warning": true,
      "Notice": false,
      "Info": false,
      "Debug": false
    }
  ],
  "PerformanceCounters": [
    {
        "CounterNames": ["% Free Inodes","% Free Space","% Used Inodes","% Used Space","Disk Read Bytes/sec","Disk Reads/sec","Disk Transfers/sec","Disk Write Bytes/sec","Disk Writes/sec","Free Megabytes","Logical Disk Bytes/sec"],
        "InstanceName": "*",
        "intervalSeconds": 300,
        "ObjectName": "Logical Disk"
    },
    {
        "CounterNames": ["% Available Memory","% Available Swap Space","% Used Memory","% Used Swap Space","Available MBytes Memory","Available MBytes Swap","Page Reads/sec","Page Writes/sec","Pages/sec","Used MBytes Swap Space","Used Memory MBytes"],
        "InstanceName": "*",
        "intervalSeconds": 300,
        "ObjectName": "Memory"
    },
    {
        "CounterNames": ["Total Bytes Transmitted","Total Bytes Received","Total Bytes","Total Packets Transmitted","Total Packets Received","Total Rx Errors","Total Tx Errors","Total Collisions"],
        "InstanceName": "*",
        "intervalSeconds": 300,
        "ObjectName": "Network"
    },
    {
        "CounterNames": ["Avg. Disk sec/Read","Avg. Disk sec/Transfer","Avg. Disk sec/Write","Physical Disk Bytes/sec"],
        "InstanceName": "*",
        "intervalSeconds": 300,
        "ObjectName": "Physical Disk"
    },
    {
        "CounterNames": ["Pct Privileged Time","Pct User Time","Used Memory kBytes","Virtual Shared Memory"],
        "InstanceName": "*",
        "intervalSeconds": 300,
        "ObjectName": "Process"
    },
    {
        "CounterNames": ["% DPC Time","% Idle Time","% Interrupt Time","% IO Wait Time","% Nice Time","% Privileged Time","% Processor Time","% User Time"],
        "InstanceName": "*",
        "intervalSeconds": 300,
        "ObjectName": "Processor"
    },
    {
        "CounterNames": ["Free Physical Memory","Free Space in Paging Files","Free Virtual Memory","Processes","Size Stored In Paging Files","Uptime","Users"],
        "InstanceName": "*",
        "intervalSeconds": 300,
        "ObjectName": "System"
    }
  ]
}
"@
$linuxWorkSpaceConfig = $linuxWorkSpaceConfigJson | ConvertFrom-Json

function Update-WindowsWorkspaceEventCollection($Workspace, [PSCustomObject]$EventLogConfig)
{
	Write-Host "Getting current windows event collection configuration from workspace"
	$CurrentWindowsEventConfig = Get-AzOperationalInsightsDataSource -WorkspaceName $Workspace.Name -ResourceGroupName $Workspace.ResourceGroupName -Kind WindowsEvent | Select-Object `
		Name, `
		@{n='EventLogName'; e={ $_.Properties.EventLogName }}, `
		@{n='CollectErrors'; e={$_.Properties.EventTypes.EventType -contains 'Error' }}, `
		@{n='CollectWarnings'; e={$_.Properties.EventTypes.EventType -contains 'Warning' }}, `
		@{n='CollectInformation'; e={$_.Properties.EventTypes.EventType -contains 'Information' }}

	Write-Host "Looping through events from even log configuration"
	foreach ($EventLogItem in $EventLogConfig)
	{
		Write-Host "Processing event '$($EventLogItem.EventLogName)'"

		$ThisEvent = $CurrentWindowsEventConfig | Where-Object { $_.EventLogName -eq $EventLogItem.EventLogName }

		if ( -not $ThisEvent )
		{
			Write-Host "Event log not configured";

      $EventArguments = @{}

      $EventArguments.Add('EventLogName', $EventLogItem.EventLogName)
  
      if ( $EventLogItem.Error )
      {
        $EventArguments.Add('CollectErrors', $null)
      }
      if ( $EventLogItem.Warning )
      {
        $EventArguments.Add('CollectWarnings', $null)
      }
      if ( $EventLogItem.Information )
      {
        $EventArguments.Add('CollectInformation', $null)
      }
  
      $NewDataSourceName = "DataSource_WindowsEvent_$(  (New-Guid).ToString() )"

			Write-Host $NewDataSourceName

			New-AzOperationalInsightsWindowsEventDataSource -WorkspaceName $Workspace.Name -ResourceGroupName $Workspace.ResourceGroupName -Name $NewDataSourceName @EventArguments | Out-Null
		}
		else
		{
			Write-Host "Event log collection already configured"
		}
	}
}

function Update-LinuxWorkspaceSyslogCollection($Workspace, [PSCustomObject]$EventLogConfig)
{
	Write-Host "Getting current linux syslog collection configuration from workspace"
	$CurrentWindowsEventConfig = Get-AzOperationalInsightsDataSource -WorkspaceName $Workspace.Name -ResourceGroupName $Workspace.ResourceGroupName -Kind LinuxSyslog | Select-Object `
		Name, `
		@{n='Facility'; e={ $_.Properties.syslogName }}, `
		@{n='CollectEmergency'; e={$_.Properties.SyslogSeverities.Severity -contains 'emerg' }}, `
		@{n='CollectAlert'; e={$_.Properties.SyslogSeverities.Severity -contains 'alert' }}, `
		@{n='CollectCritical'; e={$_.Properties.SyslogSeverities.Severity -contains 'crit' }}, `
		@{n='CollectError'; e={$_.Properties.SyslogSeverities.Severity -contains 'err' }}, `
		@{n='CollectWarning'; e={$_.Properties.SyslogSeverities.Severity -contains 'warning' }}, `
		@{n='CollectInformational'; e={$_.Properties.SyslogSeverities.Severity -contains 'info' }}, `
		@{n='CollectDebug'; e={$_.Properties.SyslogSeverities.Severity -contains 'debug' }}, `
		@{n='CollectNotice'; e={$_.Properties.SyslogSeverities.Severity -contains 'notice' }}

	Write-Host "Looping through events from even log configuration"
	foreach ($EventLogItem in $EventLogConfig)
	{
		Write-Host "Processing event '$($EventLogItem.Facility)'"

		$ThisEvent = $CurrentWindowsEventConfig | Where-Object { $_.Facility -eq $EventLogItem.Facility }

		if ( -not $ThisEvent )
		{
			Write-Host "Event log not configured";

      $EventArguments = @{}

      $EventArguments.Add('Facility', $EventLogItem.Facility)
  
      if ( $EventLogItem.Emergency )
      {
        $EventArguments.Add('CollectEmergency', $null)
      }
      if ( $EventLogItem.Alert )
      {
        $EventArguments.Add('CollectAlert', $null)
      }
      if ( $EventLogItem.Critical )
      {
        $EventArguments.Add('CollectCritical', $null)
      }
      if ( $EventLogItem.Error )
      {
        $EventArguments.Add('CollectError', $null)
      }
      if ( $EventLogItem.Warning )
      {
        $EventArguments.Add('CollectWarning', $null)
      }
      if ( $EventLogItem.Info )
      {
        $EventArguments.Add('CollectInformational', $null)
      }
      if ( $EventLogItem.Notice )
      {
        $EventArguments.Add('CollectNotice', $null)
      }
      if ( $EventLogItem.Debug )
      {
        $EventArguments.Add('CollectDebug', $null)
      }

      $NewDataSourceName = "DataSource_LinuxSyslog_$(  (New-Guid).ToString() )"

			Write-Host $NewDataSourceName

			New-AzOperationalInsightsLinuxSyslogDataSource -WorkspaceName $Workspace.Name -ResourceGroupName $Workspace.ResourceGroupName -Name $NewDataSourceName @EventArguments | Out-Null
		}
		else
		{
			Write-Host "Event log collection already configured"
		}
	}
}

function Update-WindowsWorkspacePerfCollection($Workspace, [PSCustomObject]$PerfCollectionConfig)
{
	Write-Host "Getting current windows performance collection configuration from workspace"
	$CurrentWindowsPerfConfig = Get-AzOperationalInsightsDataSource -Workspace $Workspace -Kind WindowsPerformanceCounter | Select-Object `
		Name, `
		@{n='ObjectName'; e={ $_.Properties.ObjectName }}, `
		@{n='InstanceName'; e={$_.Properties.InstanceName }}, `
		@{n='IntervalSeconds'; e={$_.Properties.IntervalSeconds }}, `
		@{n='CounterName'; e={$_.Properties.CounterName }}, `
		@{n='CollectorType'; e={$_.Properties.CollectorType }}

	Write-Host "Looping through events from even log configuration"
	foreach ( $PerfCollectionItem in $PerfCollectionConfig )
	{
		Write-Host "Processing performance collector '$($PerfCollectionItem.ObjectName)($($PerfCollectionItem.InstanceName))\$($PerfCollectionItem.CounterName)'"

		$ThisPerfCollector = $CurrentWindowsPerfConfig | Where-Object {  ($_.ObjectName -eq $PerfCollectionItem.ObjectName ) -and ($_.CounterName -eq $PerfCollectionItem.CounterName ) }

		if ( -not $ThisPerfCollector )
		{
			Write-Host "Perf collector not configured";

      $EventArguments = @{}
      $EventArguments.Add('ObjectName', $PerfCollectionItem.ObjectName)
      $EventArguments.Add('InstanceName', $PerfCollectionItem.InstanceName)
      $EventArguments.Add('IntervalSeconds', $PerfCollectionItem.IntervalSeconds)
      $EventArguments.Add('CounterName', $PerfCollectionItem.CounterName)
  
      $NewDataSourceName = "DataSource_WindowsPerformanceCounter_$(  (New-Guid).ToString() )"

      Write-Host $NewDataSourceName

			New-AzOperationalInsightsWindowsPerformanceCounterDataSource -Workspace $Workspace -Name $NewDataSourceName @EventArguments | Out-Null
		}
		else
		{
			Write-Host "Perf counter collection already configured"
		}
	}
}

function Update-LinuxWorkspacePerfCollection($Workspace, [PSCustomObject]$PerfCollectionConfig)
{
	Write-Host "Getting current linux performance collection configuration from workspace"
	$CurrentWindowsPerfConfig = Get-AzOperationalInsightsDataSource -Workspace $Workspace -Kind LinuxPerformanceObject | Select-Object `
		Name, `
		@{n='ObjectName'; e={ $_.Properties.ObjectName }}, `
		@{n='InstanceName'; e={$_.Properties.InstanceName }}, `
		@{n='IntervalSeconds'; e={$_.Properties.IntervalSeconds }}, `
		@{n='CounterNames'; e={$_.Properties.CounterNames }}

	Write-Host "Looping through events from even log configuration"
	foreach ( $PerfCollectionItem in $PerfCollectionConfig )
	{
		Write-Host "Processing performance collector '$($PerfCollectionItem.ObjectName)($($PerfCollectionItem.InstanceName))\$($PerfCollectionItem.CounterNames)'"

		$ThisPerfCollector = $CurrentWindowsPerfConfig | Where-Object {  ($_.ObjectName -eq $PerfCollectionItem.ObjectName ) }

		if ( -not $ThisPerfCollector )
		{
			Write-Host "Perf collector not configured";

      $EventArguments = @{}
      $EventArguments.Add('ObjectName', $PerfCollectionItem.ObjectName)
      $EventArguments.Add('InstanceName', $PerfCollectionItem.InstanceName)
      $EventArguments.Add('IntervalSeconds', $PerfCollectionItem.IntervalSeconds)
      $EventArguments.Add('CounterNames', $PerfCollectionItem.CounterNames)
  
      $NewDataSourceName = "DataSource_LinuxPerformanceObject_$(  (New-Guid).ToString() )"

			Write-Host $NewDataSourceName

			New-AzOperationalInsightsLinuxPerformanceObjectDataSource -Workspace $Workspace -Name $NewDataSourceName @EventArguments | Out-Null
		}
		else
		{
			Write-Host "Perf counter collection already configured"
		}
	}
}

function Create-Alert($Subscription, $AlertText,$AlertResourceGroupName,$LogAnaWrkspc,$ScheduledLogs,$ActionGroupId,$Severity,$QueryType,$ThresholdOperator,$Threshold,$FrequencyInMinutes,$TimeWindowInMinutes,$Query)
{
    # Checking alert
    $AlertName = "$($LogAnaWrkspc.Name) - $AlertText"
    Write-Host "Checking alert '$AlertName'" -ForegroundColor $CommandInfo
    $alertRule = Get-AzScheduledQueryRule -ResourceGroupName $AlertResourceGroupName -Name $AlertName -ErrorAction SilentlyContinue
    $isAzureDiagnostics = $false
    $SubscriptionId = $Subscription.id

    if ($ScheduledLogs)
    {

      if (-not $alertRule)
      {
        Write-Host "    Creating new rule" -ForegroundColor $CommandWarning

        $queryStr = $Query
        if ($Query.StartsWith("arg("))
        {
          $queryStr = "AzureDiagnostics"
          $isAzureDiagnostics = $true
        }
        $alertCondition = New-AzScheduledQueryRuleConditionObject `
          -Query $queryStr `
          -TimeAggregation $QueryType `
          -Operator $ThresholdOperator `
          -Threshold $Threshold `
          -FailingPeriodNumberOfEvaluationPeriod 1 `
          -FailingPeriodMinFailingPeriodsToAlert 1

        $alertRule = New-AzScheduledQueryRule `
          -Name $AlertName `
          -DisplayName $AlertName `
          -Description "Triggers an alert for the condition: $AlertText" `
          -ResourceGroupName $AlertResourceGroupName `
          -ActionGroupResourceId $ActionGroupId `
          -Location $AlyaLocation `
          -Enabled:$true `
          -Scope $LogAnaWrkspc.ResourceId `
          -Severity $Severity `
          -WindowSize ([System.TimeSpan]::FromMinutes($TimeWindowInMinutes)) `
          -EvaluationFrequency ([System.TimeSpan]::FromMinutes($FrequencyInMinutes)) `
          -CriterionAllOf $alertCondition

      }

      Write-Host "    Updating rule" -ForegroundColor $CommandWarning

      $json = @"
{
  "type": "Microsoft.Insights/scheduledQueryRules",
  "name": "$AlertName",
  "location": "$AlyaLocation",
  "identity": {
    "type": "SystemAssigned"
  },
  "properties": {
    "displayName": "$AlertName",
    "description": "Triggers an alert for the condition: $AlertText",
    "severity": $Severity,
    "enabled": true,
    "evaluationFrequency": "PT$($FrequencyInMinutes)M",
    "scopes": [
        "/subscriptions/$($SubscriptionId)/resourcegroups/$WrkspcResourceGroupName/providers/microsoft.operationalinsights/workspaces/$WrkspcName"
    ],
    "windowSize": "PT$($TimeWindowInMinutes)M",
    "criteria": {
        "allOf": [
            {
                "query": $($Query | ConvertTo-Json),
                "timeAggregation": "$QueryType",
                "operator": "$ThresholdOperator",
                "threshold": $Threshold,
                "failingPeriods": {
                    "numberOfEvaluationPeriods": 1,
                    "minFailingPeriodsToAlert": 1
                }
            }
        ]
    },
    "actions": {
        "actionGroups": [
            "$ActionGroupId"
        ]
    }
  }
}
"@
      Invoke-AzRestMethod -Path "/subscriptions/$($SubscriptionId)/resourcegroups/$WrkspcResourceGroupName/providers/Microsoft.Insights/scheduledQueryRules/$($AlertName)?api-version=2023-03-15-preview" -Method "Patch" -Payload $json
        
      $retries = 12
      do {
        $rulePrincipal = Get-AzADServicePrincipal -Filter "DisplayName eq '$AlertName'" -ErrorAction SilentlyContinue
        if ($rulePrincipal) {
          break
        } else {
          Start-Sleep -Seconds 10
        }
        $retries--
      } while ($retries -ge 0)

      if (-Not $rulePrincipal)
      {
        Write-Warning "We don't have actually a possibility to set the identity by PowerShell. Please:"
        Write-Warning " - Go to: 'https://portal.azure.com/#/resource/$($alertRule.Id)/overview'"
        Write-Warning " - Edit the rule and enable system assigned identity"
        Write-Warning " - Rerun this script"
        exit
      }
      else
      {
          $ruleRole = Get-AzRoleAssignment -Scope $LogAnaWrkspc.ResourceId -RoleDefinitionName "Reader" | Where-Object { $_.ObjectType -eq "ServicePrincipal" -and  $_.DisplayName -eq $AlertName }
          if (-Not $ruleRole)
          {
            $RoleAssignment = $null;
            $Retries = 0;
            While ($null -eq $RoleAssignment -and $Retries -le 6)
            {
                $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName "Reader" -ServicePrincipalName $rulePrincipal.AppId -Scope $LogAnaWrkspc.ResourceId -ErrorAction SilentlyContinue
                Start-Sleep -s 10
                $RoleAssignment = Get-AzRoleAssignment -Scope $LogAnaWrkspc.ResourceId -RoleDefinitionName "Reader" | Where-Object { $_.ObjectType -eq "ServicePrincipal" -and  $_.DisplayName -eq $AlertName }
                $Retries++;
            }
            if ($Retries -gt 6)
            {
                Write-Warning "We are not able to set the role assigment on workspace. insufficient access rights?"
                Write-Host " - Give the identity '$AlertName' read rights to the workspace"
                pause
            }
          }
          if ($isAzureDiagnostics)
          {
            $ruleRole = Get-AzRoleAssignment -Scope "/subscriptions/$($Subscription.id)" -RoleDefinitionName "Reader" | Where-Object { $_.ObjectType -eq "ServicePrincipal" -and  $_.DisplayName -eq $AlertName }
            if (-Not $ruleRole)
            {
              $RoleAssignment = $null;
              $Retries = 0;
              While ($null -eq $RoleAssignment -and $Retries -le 6)
              {
                  $RoleAssignment = New-AzRoleAssignment -RoleDefinitionName "Reader" -ServicePrincipalName $rulePrincipal.AppId -Scope "/subscriptions/$($Subscription.id)" -ErrorAction SilentlyContinue
                  Start-Sleep -s 10
                  $RoleAssignment = Get-AzRoleAssignment -Scope "/subscriptions/$($Subscription.id)" -RoleDefinitionName "Reader" | Where-Object { $_.ObjectType -eq "ServicePrincipal" -and  $_.DisplayName -eq $AlertName }
                  $Retries++;
              }
              if ($Retries -gt 6)
              {
                  Write-Warning "We are not able to set the role assigment on workspace. insufficient access rights?"
                  Write-Host " - Give the identity '$AlertName' read rights to the workspace"
                  pause
              }
            }
          }
      }

    }
    else
    {
        if ($alertRule)
        {
            Write-Host "    Already exists. Deleting it first" -ForegroundColor $CommandWarning
            Remove-AzScheduledQueryRule -ResourceGroupName $AlertResourceGroupName -Name $AlertName
        }
        Write-Host "    Creating new rule" -ForegroundColor $CommandWarning
  
        $source = New-AzScheduledQueryRuleSource `
          -Query $Query `
          -DataSourceId $LogAnaWrkspc.ResourceId `
          -QueryType $QueryType
        
        $schedule = New-AzScheduledQueryRuleSchedule `
          -FrequencyInMinutes $FrequencyInMinutes `
          -TimeWindowInMinutes $TimeWindowInMinutes

        $triggerCondition = New-AzScheduledQueryRuleTriggerCondition `
          -ThresholdOperator $ThresholdOperator `
          -Threshold $Threshold

        $aznsActionGroup = New-AzScheduledQueryRuleAznsActionGroup `
          -ActionGroup $ActionGroupId `
          -EmailSubject "$WrkspcName Alert - $AlertText"

        $alertingAction = New-AzScheduledQueryRuleAlertingAction `
          -AznsAction $aznsActionGroup `
          -Severity $Severity `
          -Trigger $triggerCondition

        $null = New-AzScheduledQueryRule `
          -ResourceGroupName $AlertResourceGroupName `
          -Location $AlyaLocation `
          -Action $alertingAction `
          -Enabled $true `
          -Description "Triggers an alert for a $AlertText condition" `
          -Schedule $schedule `
          -Source $source `
          -Name $AlertName

    }
}

function Prepare-StandardAlerts ($AlertSubscriptionName, $AlertResourceGroupName, $WrkspcResourceGroupName, $ActionGroupResourceGroupName, $ActionGroupName, $WrkspcName)
{
    # Switching subscription
    $sub = Get-AzSubscription -SubscriptionName $AlertSubscriptionName
    $null = Set-AzContext -Subscription $sub.Id

    # Checking ressource group
    Write-Host "Checking ressource group $WrkspcResourceGroupName" -ForegroundColor $CommandInfo
    $ResGrpParent = Get-AzResourceGroup -Name $WrkspcResourceGroupName -ErrorAction SilentlyContinue
    if (-Not $ResGrpParent)
    {
        throw "Does not exist. Please create it first"
    }

    # Checking log analytics workspace
    Write-Host "Checking log analytics workspace $WrkspcName" -ForegroundColor $CommandInfo
    $LogAnaWrkspc = Get-AzOperationalInsightsWorkspace -ResourceGroupName $WrkspcResourceGroupName -Name $WrkspcName -ErrorAction SilentlyContinue
    if (-Not $LogAnaWrkspc)
    {
        throw "Does not exist. Please create it first"
    }
    $LogAnaWrkspcLogVersResp = Invoke-AzRestMethod -Path "/subscriptions/$($sub.Id)/resourcegroups/$WrkspcResourceGroupName/providers/microsoft.operationalinsights/workspaces/$WrkspcName/alertsversion?api-version=2017-04-26-preview" -Method "Get"
    $LogAnaWrkspcLogVers = $LogAnaWrkspcLogVersResp.Content | ConvertFrom-Json

    # Checking action group
    Write-Host "Checking action group $ActionGroupName" -ForegroundColor $CommandInfo
    $actionGroup = Get-AzActionGroup -ResourceGroupName $ActionGroupResourceGroupName -Name $ActionGroupName -ErrorAction SilentlyContinue
    if (-Not $actionGroup)
    {
        throw "Does not exist. Please create it first with Create-AzureLogAnalyticsAlertActionGroups.ps1"
    }
    $actionGroupId = $actionGroup.Id

    # Checking windows log analytics workspace event log collections
    Write-Host "Checking windows log analytics workspace event log collections" -ForegroundColor $CommandInfo
    Update-WindowsWorkspaceEventCollection `
	    -Workspace $LogAnaWrkspc `
	    -EventLogConfig $windowsWorkSpaceConfig.Events

    # Checking linux log analytics workspace syslog log collections
    Write-Host "Checking linux log analytics workspace syslog log collections" -ForegroundColor $CommandInfo
    Update-LinuxWorkspaceSyslogCollection `
	    -Workspace $LogAnaWrkspc `
	    -EventLogConfig $linuxWorkSpaceConfig.Syslogs

    # Checking windows log analytics workspace performance counter collections
    Write-Host "Checking windows log analytics workspace performance counter collections" -ForegroundColor $CommandInfo
    Update-WindowsWorkspacePerfCollection `
	    -Workspace $LogAnaWrkspc `
	    -PerfCollectionConfig $windowsWorkSpaceConfig.PerformanceCounters

    # Checking windows log analytics workspace performance counter collections
    Write-Host "Checking linux log analytics workspace performance counter collections" -ForegroundColor $CommandInfo
    Update-LinuxWorkspacePerfCollection `
	    -Workspace $LogAnaWrkspc `
	    -PerfCollectionConfig $linuxWorkSpaceConfig.PerformanceCounters

    # Alert rule examples from: https://github.com/microsoft/manageability-toolkits/blob/master/Alert%20Toolkit/DefaultAlertConfig.json

    # Checking Low Disk Space alert
    Create-Alert `
        -Subscription $sub `
        -AlertText "Windows Low Disk Space" `
        -AlertResourceGroupName $AlertResourceGroupName `
        -LogAnaWrkspc $LogAnaWrkspc `
        -ScheduledLogs ($LogAnaWrkspcLogVers.version -eq 2 -and $LogAnaWrkspcLogVers.scheduledQueryRulesEnabled -eq $true) `
        -ActionGroupId $actionGroupId `
        -Severity "2" `
        -QueryType "Count" `
        -ThresholdOperator "GreaterThan" `
        -Threshold 0 `
        -FrequencyInMinutes 30 `
        -TimeWindowInMinutes 30 `
        -Query "let _minValue = 10; Perf | where TimeGenerated >= ago(1h) | where CounterValue <= _minValue | where CounterName == `"% Free Space`" and InstanceName in (`"C:`", `"D:`", `"E:`", `"F:`", `"G:`")  | summarize mtgPerf=max(TimeGenerated), CounterValue=max(CounterValue) by Computer, InstanceName, CounterName, ObjectName, DriveLetter=replace(@`"(\\w).`",@`"\\1`", InstanceName) | join kind=inner ( Heartbeat | where OSType == `"Windows`" and ComputerEnvironment == `"Azure`" | summarize max(TimeGenerated) by Computer) on Computer | project Computer, ObjectName, CounterName, InstanceName, TimeGenerated=mtgPerf, round(CounterValue), DriveLetter, AlertType_s = `"Windows Low Disk Space`", Severity = 3, SeverityName_s = `"WARNING`", AffectedCI_s = strcat(Computer, `"/`", DriveLetter), AlertTitle_s = strcat(Computer, `": Low Disk Space on Drive `", DriveLetter), AlertDetails_s = strcat(`"Computer: `", Computer, `"\\r\\nDrive Letter: `", DriveLetter, `"\\r\\nPercent Free Space: `", round(CounterValue), `"%\\r\\nAlert Threshold: <= `", _minValue, `"%`")"

    # Checking High CPU Usage alert
    Create-Alert `
        -Subscription $sub `
        -AlertText "High CPU Usage" `
        -AlertResourceGroupName $AlertResourceGroupName `
        -LogAnaWrkspc $LogAnaWrkspc `
        -ScheduledLogs ($LogAnaWrkspcLogVers.version -eq 2 -and $LogAnaWrkspcLogVers.scheduledQueryRulesEnabled -eq $true) `
        -ActionGroupId $actionGroupId `
        -Severity "2" `
        -QueryType "Count" `
        -ThresholdOperator "GreaterThan" `
        -Threshold 0 `
        -FrequencyInMinutes 30 `
        -TimeWindowInMinutes 240 `
        -Query "let _maxValue = 85; let _timeWindow = 4h; let _AvgCpu = Perf | where TimeGenerated >= ago(_timeWindow) | where ObjectName == `"Processor`" and CounterName == `"% Processor Time`" and InstanceName =~ `"_Total`" | summarize mtgPerf=max(TimeGenerated), CounterValue=round(avg(CounterValue)), SampleCount=count(CounterValue) by Computer, InstanceName, CounterName, ObjectName; _AvgCpu | where CounterValue > _maxValue | join kind=inner ( Heartbeat | where ComputerEnvironment == `"Azure`" | summarize max(TimeGenerated) by Computer) on Computer | project Computer, ObjectName, CounterName, InstanceName, TimeGenerated=mtgPerf, CounterValue, AlertType_s = `"Sustained High CPU Utilization`", Severity = 4, SeverityName_s = `"WARNING`", AffectedCI_s = strcat(Computer, `"/CPUPercent/`", InstanceName), AlertTitle_s = strcat(Computer, `": Sustained High CPU Utilization`"), AlertDetails_s = strcat(`"Computer: `", Computer, `"\\r\\nAverage CPU Utilization: `", CounterValue, `"%\\r\\nSample Period: Last `", _timeWindow, `"\\r\\nSample Count: `", SampleCount, `"\\r\\nAlert Threshold: > `", _maxValue, `"%`")"

    # Checking Low Memory alert
    Create-Alert `
        -Subscription $sub `
        -AlertText "Low Memory" `
        -AlertResourceGroupName $AlertResourceGroupName `
        -LogAnaWrkspc $LogAnaWrkspc `
        -ScheduledLogs ($LogAnaWrkspcLogVers.version -eq 2 -and $LogAnaWrkspcLogVers.scheduledQueryRulesEnabled -eq $true) `
        -ActionGroupId $actionGroupId `
        -Severity "2" `
        -QueryType "Count" `
        -ThresholdOperator "GreaterThan" `
        -Threshold 0 `
        -FrequencyInMinutes 30 `
        -TimeWindowInMinutes 240 `
        -Query "let _minAvailableMB = 1024; let _sampleInterval = 4h; let _linuxMem = Perf | where TimeGenerated >= ago(_sampleInterval) | where CounterName == `"Available MBytes Memory`" | summarize mtgPerf=max(TimeGenerated), CounterValue=avg(CounterValue), SampleCount=count(CounterValue) by Computer | join kind=inner ( Heartbeat     | where OSType == `"Linux`" and ComputerEnvironment == `"Azure`"     | summarize max(TimeGenerated) by Computer ) on Computer | project Computer, mtgPerf, AvailableMBytes=round(CounterValue), SampleCount; let _windowsMem = Perf | where TimeGenerated >= ago(_sampleInterval) | where CounterName == `"Available MBytes`" | summarize mtgPerf=max(TimeGenerated), CounterValue=avg(CounterValue), SampleCount=count(CounterValue) by Computer | join kind=inner ( Heartbeat     | where OSType == `"Windows`" and ComputerEnvironment == `"Azure`"    | summarize max(TimeGenerated) by Computer ) on Computer | project Computer, mtgPerf, AvailableMBytes=round(CounterValue), SampleCount; _linuxMem | union _windowsMem | where AvailableMBytes < _minAvailableMB | project Computer, TimeGenerated=mtgPerf, CounterValue=AvailableMBytes, AlertType_s = `"Low Available Memory`", Severity = 4, SeverityName_s = `"WARNING`", AffectedCI_s = strcat(Computer, `"/FreeMemoryMB/`"), AlertTitle_s = strcat(Computer, `": Low Available Memory`"), AlertDetails_s = strcat(`"Computer: `", Computer, `"\\r\\nAverage Free Memory: `", AvailableMBytes, `" MB\\r\\nSample Period: Last `", _sampleInterval, `"\\r\\nSample Count: `", SampleCount, `"\\r\\nAlert Threshold: < `", _minAvailableMB, `" MB`")"

    # Checking File System Corrupt alert
    Create-Alert `
        -Subscription $sub `
        -AlertText "File System Corrupt" `
        -AlertResourceGroupName $AlertResourceGroupName `
        -LogAnaWrkspc $LogAnaWrkspc `
        -ScheduledLogs ($LogAnaWrkspcLogVers.version -eq 2 -and $LogAnaWrkspcLogVers.scheduledQueryRulesEnabled -eq $true) `
        -ActionGroupId $actionGroupId `
        -Severity "2" `
        -QueryType "Count" `
        -ThresholdOperator "GreaterThan" `
        -Threshold 0 `
        -FrequencyInMinutes 30 `
        -TimeWindowInMinutes 30 `
        -Query "Event | where EventLog == `"System`" and Source == `"DISK`" or Source == `"Ntfs`" and EventID == 55 | join kind=inner ( Heartbeat     | where ComputerEnvironment == `"Azure`"    | summarize max(TimeGenerated) by Computer ) on Computer | project Computer, TimeGenerated, AlertType_s = `"NTFS - File System Corrupt`", Severity = 4, SeverityName_s = `"WARNING`", AffectedCI_s = Computer, AlertTitle_s = strcat(Computer, `": NTFS - File System Corrupt`"), AlertDetails_s = strcat(`"Event Description:\\r\\n`", RenderedDescription)"

    # Checking Unexpected Shutdown alert
    Create-Alert `
        -Subscription $sub `
        -AlertText "Unexpected Shutdown" `
        -AlertResourceGroupName $AlertResourceGroupName `
        -LogAnaWrkspc $LogAnaWrkspc `
        -ScheduledLogs ($LogAnaWrkspcLogVers.version -eq 2 -and $LogAnaWrkspcLogVers.scheduledQueryRulesEnabled -eq $true) `
        -ActionGroupId $actionGroupId `
        -Severity "2" `
        -QueryType "Count" `
        -ThresholdOperator "GreaterThan" `
        -Threshold 0 `
        -FrequencyInMinutes 1440 `
        -TimeWindowInMinutes 1440 `
        -Query "Event | where EventLog == `"System`" and Source == `"DISK`" or Source == `"Ntfs`" and EventID == 55 | join kind=inner ( Heartbeat     | where ComputerEnvironment == `"Azure`"    | summarize max(TimeGenerated) by Computer ) on Computer | project Computer, TimeGenerated, AlertType_s = `"NTFS - Unexpected Shutdown`", Severity = 4, SeverityName_s = `"WARNING`", AffectedCI_s = Computer, AlertTitle_s = strcat(Computer, `": NTFS - Unexpected Shutdown`"), AlertDetails_s = strcat(`"Event Description:\\r\\n`", RenderedDescription)"

    # Checking Runbook alert
    Create-Alert `
        -Subscription $sub `
        -AlertText "Runbook Job Failed" `
        -AlertResourceGroupName $AlertResourceGroupName `
        -LogAnaWrkspc $LogAnaWrkspc `
        -ScheduledLogs ($LogAnaWrkspcLogVers.version -eq 2 -and $LogAnaWrkspcLogVers.scheduledQueryRulesEnabled -eq $true) `
        -ActionGroupId $actionGroupId `
        -Severity "2" `
        -QueryType "Count" `
        -ThresholdOperator "GreaterThan" `
        -Threshold 0 `
        -FrequencyInMinutes 1440 `
        -TimeWindowInMinutes 1440 `
        -Query "AzureDiagnostics | where ResourceProvider == `"MICROSOFT.AUTOMATION`" and Category == `"JobLogs`" and (ResultType == `"Failed`" or ResultType == `"Suspended`") | summarize AggregatedValue = count() by RunbookName_s"

    # Checking VM Update Installation Error
    Create-Alert `
        -Subscription $sub `
        -AlertText "VM Update Installation Error" `
        -AlertResourceGroupName $AlertResourceGroupName `
        -LogAnaWrkspc $LogAnaWrkspc `
        -ScheduledLogs ($LogAnaWrkspcLogVers.version -eq 2 -and $LogAnaWrkspcLogVers.scheduledQueryRulesEnabled -eq $true) `
        -ActionGroupId $actionGroupId `
        -Severity "1" `
        -QueryType "Count" `
        -ThresholdOperator "GreaterThan" `
        -Threshold 0 `
        -FrequencyInMinutes 60 `
        -TimeWindowInMinutes 60 `
        -Query "arg(`"`").patchinstallationresources | where type !has `"softwarepatches`" | extend machineName = tostring(split(id, `"/`", 8)), resourceType = tostring(split(type, `"/`", 0)), tostring(rgName = split(id, `"/`", 4)), tostring(RunID = split(id, `"/`", 10)) | extend prop = parse_json(properties) | where prop.installedPatchCount > 0 or prop.failedPatchCount > 0 | extend lastTime = todatetime(prop.lastModifiedDateTime), OS = tostring(prop.osType), maintenanceWindowExceeded = tostring(prop.maintenanceWindowExceeded), status = tostring(prop.status), installedPatchCount = tostring(prop.installedPatchCount), failedPatchCount = tostring(prop.failedPatchCount), pendingPatchCount = tostring(prop.pendingPatchCount), excludedPatchCount = tostring(prop.excludedPatchCount), notSelectedPatchCount = tostring(prop.notSelectedPatchCount) | project lastTime, RunID, machineName, rgName, resourceType, OS, status, maintenanceWindowExceeded, installedPatchCount, failedPatchCount, pendingPatchCount, excludedPatchCount, notSelectedPatchCount, prop | where lastTime > ago(1h) and status == `"Failed`""

    # Checking VM Update Installation Succeeded
    Create-Alert `
        -Subscription $sub `
        -AlertText "VM Update Installation Succeeded" `
        -AlertResourceGroupName $AlertResourceGroupName `
        -LogAnaWrkspc $LogAnaWrkspc `
        -ScheduledLogs ($LogAnaWrkspcLogVers.version -eq 2 -and $LogAnaWrkspcLogVers.scheduledQueryRulesEnabled -eq $true) `
        -ActionGroupId $actionGroupId `
        -Severity "4" `
        -QueryType "Count" `
        -ThresholdOperator "GreaterThan" `
        -Threshold 0 `
        -FrequencyInMinutes 1440 `
        -TimeWindowInMinutes 1440 `
        -Query "arg(`"`").patchinstallationresources | where type !has `"softwarepatches`" | extend machineName = tostring(split(id, `"/`", 8)), resourceType = tostring(split(type, `"/`", 0)), tostring(rgName = split(id, `"/`", 4)), tostring(RunID = split(id, `"/`", 10)) | extend prop = parse_json(properties) | where prop.installedPatchCount > 0 or prop.failedPatchCount > 0 | extend lastTime = todatetime(prop.lastModifiedDateTime), OS = tostring(prop.osType), maintenanceWindowExceeded = tostring(prop.maintenanceWindowExceeded), status = tostring(prop.status), installedPatchCount = tostring(prop.installedPatchCount), failedPatchCount = tostring(prop.failedPatchCount), pendingPatchCount = tostring(prop.pendingPatchCount), excludedPatchCount = tostring(prop.excludedPatchCount), notSelectedPatchCount = tostring(prop.notSelectedPatchCount) | project lastTime, RunID, machineName, rgName, resourceType, OS, status, maintenanceWindowExceeded, installedPatchCount, failedPatchCount, pendingPatchCount, excludedPatchCount, notSelectedPatchCount, prop | where lastTime > ago(1d) and status == `"Succeeded`""

}

Prepare-StandardAlerts `
    -AlertSubscriptionName $AlyaSubscriptionName `
    -AlertResourceGroupName $AlertResourceGroupName `
    -WrkspcResourceGroupName $WrkspcResourceGroupName `
    -WrkspcName $WrkspcName `
    -ActionGroupResourceGroupName $ActionGroupResourceGroupName `
    -ActionGroupName $ActionGroupName

#Stopping Transscript
Stop-Transcript
