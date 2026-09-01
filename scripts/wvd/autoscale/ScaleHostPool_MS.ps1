#Requires -Version 2.0

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
    21.04.2020 Konrad Brunner       Initial Version
    06.02.2026 Konrad Brunner       Added powershell documentation

#>

<#
.SYNOPSIS
Scales an Azure Virtual Desktop (WVD) host pool based on configuration settings and usage patterns.

.DESCRIPTION
The ScaleHostPool_MS.ps1 script automates the scaling of Windows Virtual Desktop host pools using Azure and WVD PowerShell modules. It reads a configuration JSON file defining peak and off-peak hours, scaling thresholds, and session limits. The script verifies and loads the configuration, authenticates to Azure and WVD tenants, and adjusts virtual machines (VMs) in the host pool according to the current demand, balancing session hosts using DepthFirst or BreadthFirst strategies. It also manages session host startup and shutdown, enforces maximum session limits, adjusts load balancing settings, and logs scaling activities for auditing and monitoring.

.PARAMETER ConfigFile
Specifies the JSON configuration file that contains scaling settings. The default value is 'Autoscaling_Config.json'. This parameter is mandatory for running the scaling process.

.INPUTS
None. The script reads configuration data from a JSON file and interacts with Azure and WVD services.

.OUTPUTS
The script outputs log files in the configured log directory detailing scaling operations, session host activities, and errors encountered. It also generates usage logs recording host pool scaling actions.

.EXAMPLE
PS> .\ScaleHostPool_MS.ps1 -ConfigFile "MyHostPoolConfig.json"

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = "Autoscaling_Config.json"
)

if ($ConfigFile -eq "Autoscaling_Config.json")
{
    throw "Autoscaling_Config.json is only a template. Please provide correct config file"
}

$RootDir = Split-Path $script:MyInvocation.MyCommand.Path

# Reading configuration
. $RootDir\..\..\..\01_ConfigureEnv.ps1

# Starting Transcript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\autoscale\ScaleHostPool_MS-$($AlyaTimeString).log" | Out-Null

# Constants
$ActualDate = Get-Date

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Compute"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Microsoft.RDInfra.RDPowershell"

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD Autoscaling | ScaleHostPool_MS | WVD" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# =============================================================
# Functions
# =============================================================

Write-Host "Defining functions" -ForegroundColor $CommandInfo

#Get PWD Function
Function Get-StoredCredential {
    param(
        [Parameter(Mandatory=$false, ParameterSetName="Get")]
        [string]$UserName,
        [Parameter(Mandatory=$false, ParameterSetName="List")]
        [switch]$List
        )

    if ($List) {
        try {
            $CredentialList = @(Get-ChildItem -Path "$($AlyaData)\wvd\autoscale\Creds" -Filter *.cred -ErrorAction STOP)
            foreach ($Cred in $CredentialList) {
                Write-Output $Cred.BaseName
            }
        }
        catch {
            Write-Warning $_.Exception.Message
        }
    }
    if ($UserName) {
        if (Test-Path "$($AlyaData)\wvd\autoscale\Creds\$($Username).cred") {
            $PwdSecureString = Get-Content "$($AlyaData)\wvd\autoscale\Creds\$($Username).cred" | ConvertTo-SecureString
            $Credential = New-Object System.Management.Automation.PSCredential -ArgumentList $UserName, $PwdSecureString
        }
        else {
            throw "Unable to locate a credential for $($Username)"
        }
        return $Credential
    }
}

#Function for convert from UTC to Local time
function ConvertUTCtoLocal {
  if ([string]::IsNullOrEmpty($TimeZone)) { return (Get-Date) }
  return [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($(Get-Date), [System.TimeZoneInfo]::Local.Id, $TimeZone)
}

#Function for writing the usage log
function Write-UsageLog {
  param(
    [string]$HostpoolName,
    [int]$Corecount,
    [int]$VMCount,
    [bool]$DepthBool = $True,
    [string]$LogFileName = $WVDTenantUsagelog
  )
  $Time = ConvertUTCtoLocal
  if ($DepthBool) {
    Add-Content $LogFileName -Value ("{0}, {1}, {2}" -f $Time,$HostpoolName,$VMCount)
  }
  else {

    Add-Content $LogFileName -Value ("{0}, {1}, {2}, {3}" -f $Time,$HostpoolName,$Corecount,$VMCount)
  }
}

#Function for creating a variable from JSON
function Set-ScriptVariable ($Name,$Value) {
  Invoke-Expression ("`$Script:" + $Name + " = `"" + $Value + "`"")
}

#Function to correctly exit
function DoExit($exitCode) {
  $context = Get-AzContext -Name "ServicePrincipal ($($AADTenantId))"
  if ($context)
  {
    Remove-AzContext -InputObject $context -Force
  }
  Exit $exitCode
}

# =============================================================
# Checking configuration
# =============================================================

# Json path
$JsonPath = "$($AlyaData)\wvd\autoscale\$ConfigFile"

# Log path
$WVDTenantUsagelog = "$($AlyaData)\wvd\autoscale\WVDTenantUsage_$($ConfigFile).log"

# Verify Json file
Write-Host "Verifying config file" -ForegroundColor $CommandInfo
if (Test-Path $JsonPath) {
  Write-Verbose "Found $JsonPath"
  Write-Verbose "Validating file..."
  try {
    $Variable = Get-Content $JsonPath | Out-String | ConvertFrom-Json
  }
  catch {
    #$Validate = $false
    Write-Error  "$JsonPath is invalid. Check Json syntax - Unable to proceed"
    Write-Host "$JsonPath is invalid. Check Json syntax - Unable to proceed"
    DoExit -exitCode 1
  }
}
else {
  #$Validate = $false
  Write-Error  "Missing $JsonPath - Unable to proceed"
  Write-Host "Missing $JsonPath - Unable to proceed"
  DoExit -exitCode 2
}

# Load Json Configuration values as variables
Write-Host "Loading values from configuration file" -ForegroundColor $CommandInfo
$Variable = Get-Content $JsonPath | Out-String | ConvertFrom-Json
$Variable.WVDScale.Azure | ForEach-Object { $_.Variables } | Where-Object { $_.Name -ne $null } | ForEach-Object { Set-ScriptVariable -Name $_.Name -Value $_.Value }
$Variable.WVDScale.WVDScaleSettings | ForEach-Object { $_.Variables } | Where-Object { $_.Name -ne $null } | ForEach-Object { Set-ScriptVariable -Name $_.Name -Value $_.Value }
$Variable.WVDScale.Deployment | ForEach-Object { $_.Variables } | Where-Object { $_.Name -ne $null } | ForEach-Object { Set-ScriptVariable -Name $_.Name -Value $_.Value }
# Construct Begin time and End time for the Peak period from utc to local time
$TimeDifference = [string]$TimeDifferenceInHours
$CurrentDateTime = ConvertUTCtoLocal

# Getting secrets
Write-Host "Getting secrets" -ForegroundColor $CommandInfo
$sCreds = Get-StoredCredential -List
$aadAuthentication = $null
$wvdAuthentication = $null
if ($sCreds -contains $AADApplicationId)
{
    $netCred = Get-StoredCredential -UserName $AADApplicationId
    $azureCreds = New-Object System.Management.Automation.PSCredential($AADApplicationId, $netCred.Password)
    # Authenticating to Azure
    Write-Host "Authenticating to Azure" -ForegroundColor $CommandInfo
    try {
		Disable-AzContextAutosave -Scope Process -ErrorAction SilentlyContinue | Out-Null
        $aadAuthentication = Add-AzAccount -ContextName "ServicePrincipal ($($AADTenantId))" -SubscriptionId $currentAzureSubscriptionId -TenantId $AADTenantId -Credential $azureCreds -ServicePrincipal -Force
        $Obj = $aadAuthentication | Out-String
        Write-Host "Authenticating as service principal account for AD. Result: `n$obj"
    } catch {$aadAuthentication = $null}
}
if ($sCreds -contains $UserName)
{
    $netCred = Get-StoredCredential -UserName $UserName
    $wvdCreds = New-Object System.Management.Automation.PSCredential($UserName, $netCred.Password)
    # Login into WVD tenant
    Write-Host "Login into WVD tenant" -ForegroundColor $CommandInfo
    try {
        $wvdAuthentication = Add-RdsAccount -DeploymentUrl $RDBroker -TenantId $AADTenantId -Credential $wvdCreds -ServicePrincipal
        $Obj = $wvdAuthentication | Out-String
        Write-Host "Authenticating as service principal account for WVD. Result: `n$obj"
    } catch {$wvdAuthentication = $null}
}

if ($aadAuthentication -eq $null -or $wvdAuthentication -eq $null)
{
    Write-Error "Missing credentials! Please run Save-AutoscalingCredentials.ps1" -ErrorAction Continue
    DoExit -exitCode 3
}

# Set context to the appropriate tenant group
$CurrentTenantGroupName = (Get-RdsContext).TenantGroupName
if ($TenantGroupName -ne $CurrentTenantGroupName) {
  Write-Host "Running switching to the $TenantGroupName context"
  Set-RdsContext -TenantGroupName $TenantGroupName
}

# select the current Azure subscription specified in the config
Select-AzSubscription -SubscriptionId $CurrentAzureSubscriptionId

# Converting Datetime format
$BeginPeakDateTime = [datetime]::Parse($CurrentDateTime.ToShortDateString() + ' ' + $BeginPeakTime)
$EndPeakDateTime = [datetime]::Parse($CurrentDateTime.ToShortDateString() + ' ' + $EndPeakTime)

#Checking given host pool name exists in Tenant
Write-Host "Checking given host pool" -ForegroundColor $CommandInfo
$HostpoolInfo = Get-RdsHostPool -TenantName $TenantName -Name $HostpoolName
if ($HostpoolInfo -eq $null) {
    Write-Error "Hostpoolname '$HostpoolName' does not exist in the tenant of '$TenantName'. Ensure that you have entered the correct values." -ErrorAction Continue
    DoExit -exitCode 4
}	
  
#Checking MaxSessionLimit for given host pool
Write-Host "Checking MaxSessionLimit" -ForegroundColor $CommandInfo
$firstSessionHost = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName
$sessionHostName = $firstSessionHost.SessionHostName.Split(".")[0]
$sessionHostVm = Get-AzVM -Name $sessionHostName -ResourceGroupName $ResourceGroupName
$sessionHostSku = $sessionHostVm.HardwareProfile.VmSize
$sessionLimit = ($Variable.WVDScale.MaxSessionsPerVmType | ForEach-Object { $_.Types } | Where-Object { $_.Name -eq $sessionHostSku }).Value
if ($HostpoolInfo.MaxSessionLimit -ne $sessionLimit) {
    Write-Host "Setting MaxSessionLimit to $sessionLimit"
    Set-RdsHostPool -TenantName $TenantName -Name $HostpoolName -MaxSessionLimit $sessionLimit
}

#Checking LoadBalancerType for given host pool
Write-Host "Checking LoadBalancerType" -ForegroundColor $CommandInfo
if ($HostpoolInfo.LoadBalancerType -ne $LoadBalancingType) {
    Write-Host "Changing Hostpool Load Balance Type:$LoadBalancingType Current Date Time is: $CurrentDateTime"
    if ($LoadBalancingType -eq "DepthFirst") {                
        Set-RdsHostPool -TenantName $TenantName -Name $HostpoolName -DepthFirstLoadBalancer -MaxSessionLimit $HostpoolInfo.MaxSessionLimit
    }
    else {
        Set-RdsHostPool -TenantName $TenantName -Name $HostpoolName -BreadthFirstLoadBalancer -MaxSessionLimit $HostpoolInfo.MaxSessionLimit
    }
    Write-Host "Hostpool Load balancer Type is '$LoadBalancingType Load Balancing'"
}

# =============================================================
# Balancing
# =============================================================

Write-Host "Starting WVD Tenant Hosts Scale Optimization: Current Date Time is: $CurrentDateTime"
$HostpoolInfo = Get-RdsHostPool -TenantName $tenantName -Name $hostPoolName

#Balancing DepthFirst
if ($HostpoolInfo.LoadBalancerType -eq "DepthFirst") {

  Write-Host "$HostpoolName hostpool loadbalancer type is $($HostpoolInfo.LoadBalancerType)"

  #Gathering hostpool maximum session and calculating Scalefactor for each host.										  
  $HostpoolMaxSessionLimit = $HostpoolInfo.MaxSessionLimit
  $ScaleFactorEachHost = $HostpoolMaxSessionLimit * 0.80
  $SessionhostLimit = [math]::Floor($ScaleFactorEachHost)
  if ($SessionhostLimit -eq 0) { $SessionhostLimit = 1 }

  Write-Host "Hostpool Maximum Session Limit: $($HostpoolMaxSessionLimit)"
  Write-Host "Scaled Session Limit: $($SessionhostLimit)"

  if ($CurrentDateTime -ge $BeginPeakDateTime -and $CurrentDateTime -le $EndPeakDateTime) {
    #In peak hours
    Write-Host "It is in peak hours now"
    Write-Host "Peak hours: starting session hosts as needed based on current workloads."

    # Check dynamically created OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName) text file and will remove in peak hours.
    if (Test-Path -Path $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt) {
      Remove-Item -Path $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt
    }

    # Get all session hosts in the host pool
    $AllSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName | Sort-Object SessionHostName
    if ($AllSessionHosts -eq $null) {
        Write-Error "Session hosts does not exist in the Hostpool of '$HostpoolName'. Ensure that hostpool have hosts or not?." -ErrorAction Continue
        DoExit -exitCode 5
    }

    # Check the number of running session hosts
    $NumberOfRunningHost = 0
    foreach ($SessionHost in $AllSessionHosts) {
      Write-Host "Checking session host:$($SessionHost.SessionHostName | Out-String)  of sessions:$($SessionHost.Sessions) and status:$($SessionHost.Status)"
      $SessionCapacityofSessionHost = $SessionHost.Sessions
      if ($SessionHostLimit -le $SessionCapacityofSessionHost -or ($SessionHost.Status -eq "Available" -or $SessionHost.Status -eq "NeedsAssistance")) {
        $NumberOfRunningHost = $NumberOfRunningHost + 1
      }
    }
    Write-Host "Current number of running hosts: $NumberOfRunningHost"

    # If num hosts less than min required
    if ($NumberOfRunningHost -lt $MinimumNumberOfRDSH) {
      Write-Host "Current number of running session hosts is less than minimum requirements, start session host ..."
      foreach ($SessionHost in $AllSessionHosts) {
        if ($NumberOfRunningHost -lt $MinimumNumberOfRDSH) {
          $SessionHostSessions = $SessionHost.Sessions
          if ($HostpoolMaxSessionLimit -gt $SessionHostSessions) {
            # Check the session host status and if the session host is healthy before starting the host
            if (($SessionHost.Status -eq "NoHeartbeat" -or $SessionHost.Status -eq "Unavailable") -and $SessionHost.UpdateState -eq "Succeeded") {
              $SessionHostName = $SessionHost.SessionHostName | Out-String
              $VMName = $SessionHostName.Split(".")[0]
              $VmInfo = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName
              # Check the Session host is in maintenance
              if ($VmInfo.Tags.Keys -contains $MaintenanceTagName) {
                Write-Warning "Session host is in Maintenance: $SessionHostName, so this session host is skipped"
                continue
              }

              # Check if the session host is allowing new connections
              $StateOftheSessionHost = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost.SessionHostName
              if (!($StateOftheSessionHost.AllowNewSession)) {
                Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost.SessionHostName -AllowNewSession $true
              }

              # Start the Az VM
              try {
                Write-Host "Starting Azure VM: $VMName and waiting for it to complete ..."
                Start-AzVM -Name $VMName -ResourceGroupName $VmInfo.ResourceGroupName

              }
              catch {
                Write-Error "Failed to start Azure VM: $($VMName) with error: $($_.exception.message)" -ErrorAction Continue
                DoExit -exitCode 6
              }
              # Wait for the sessionhost is available
              $IsHostAvailable = $false
              while (!$IsHostAvailable) {

                $SessionHostStatus = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost.SessionHostName

                if (($SessionHostStatus.Status -eq "Available" -or $SessionHost.Status -eq "NeedsAssistance")) {
                  $IsHostAvailable = $true

                }
              }
            }
          }
          $NumberOfRunningHost = $NumberOfRunningHost + 1
        }
      }
    }
    else
    {
       #Do normal balancing
      $AllSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName | Sort-Object SessionHostName
      foreach ($SessionHost in $AllSessionHosts) {
        if ($SessionHost.Sessions -ne $HostpoolMaxSessionLimit) {
          if ($SessionHost.Sessions -ge $SessionHostLimit) {
            foreach ($SessionHost in $AllSessionHosts) {

              #Check the session host status and sessions before starting the one more session host
              if (($SessionHost.Status -eq "Available" -or $SessionHost.Status -eq "NeedsAssistance") -and $SessionHost.Sessions -eq 0)
              {
                break
              }
              # Check the session host status and if the session host is healthy before starting the host
              if (($SessionHost.Status -eq "NoHeartbeat" -or $SessionHost.Status -eq "Unavailable") -and $SessionHost.UpdateState -eq "Succeeded") {
                
                Write-Host "Existing Sessionhost Sessions value reached near by hostpool maximumsession limit need to start the session host"
                $SessionHostName = $SessionHost.SessionHostName | Out-String
                $VMName = $SessionHostName.Split(".")[0]

                # Check the session host is in maintenance
                $VmInfo = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName
                if ($VmInfo.Tags.Keys -contains $MaintenanceTagName) {
                  Write-Warning "Session Host is in Maintenance: $SessionHostName"
                  continue
                }

                # Check if the session host is allowing new connections
                $StateOftheSessionHost = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost.SessionHostName
                if (!($StateOftheSessionHost.AllowNewSession)) {
                  Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost.SessionHostName -AllowNewSession $true
                }

                # Start the Az VM
                try {
                  Write-Host "Starting Azure VM: $VMName and waiting for it to complete ..."
                  Start-AzVM -Name $VMName -ResourceGroupName $VMInfo.ResourceGroupName
                }
                catch {
                  Write-Error "Failed to start Azure VM: $($VMName) with error: $($_.exception.message)" -ErrorAction Continue
                  DoExit -exitCode 7
                }

                # Wait for the sessionhost is available
                $IsHostAvailable = $false
                while (!$IsHostAvailable) {

                  $SessionHostStatus = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost.SessionHostName

                  if (($SessionHostStatus.Status -eq "Available" -or $SessionHost.Status -eq "NeedsAssistance")) {
                    $IsHostAvailable = $true
                  }
                }
                $NumberOfRunningHost = $NumberOfRunningHost + 1
                break
              }
            }
          }
        }
      }
    }

    Write-Host "HostpoolName:$HostpoolName, NumberofRunnighosts:$NumberOfRunningHost"
    $DepthBool = $true
    Write-UsageLog -HostPoolName $HostpoolName -VMCount $NumberOfRunningHost -DepthBool $DepthBool
  }
  else {
    #Of peak hours
    Write-Host "It is Off-peak hours"
    Write-Host "It is off-peak hours. Starting to scale down RD session hosts..."
    Write-Host ("Processing hostPool {0}" -f $HostpoolName)

    # Get all session hosts in the host pool
    $AllSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName | Sort-Object Sessions
    if ($AllSessionHosts -eq $null) {
        Write-Error "Session hosts does not exist in the Hostpool of '$HostpoolName'. Ensure that hostpool have hosts or not?." -ErrorAction Continue
        DoExit -exitCode 5
    }

    # Check the number of running session hosts
    $NumberOfRunningHost = 0
    foreach ($SessionHost in $AllSessionHosts) {
      if (($SessionHost.Status -eq "Available" -or $SessionHost.Status -eq "NeedsAssistance")) {
        $NumberOfRunningHost = $NumberOfRunningHost + 1
      }
    }

    # Defined minimum no of rdsh value from JSON file
    [int]$DefinedMinimumNumberOfRDSH = $MinimumNumberOfRDSH

    # Check and Collecting dynamically stored MinimumNoOfRDSH Value																 
    if (Test-Path -Path $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt) {
      [int]$MinimumNumberOfRDSH = Get-Content $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt
    }

    if ($NumberOfRunningHost -gt $MinimumNumberOfRDSH) {
      foreach ($SessionHost in $AllSessionHosts.SessionHostName) {
        if ($NumberOfRunningHost -gt $MinimumNumberOfRDSH) {

          $SessionHostInfo = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost
          if (($SessionHostInfo.Status -eq "Available" -or $SessionHostInfo.Status -eq "NeedsAssistance")) {

            Write-Host "Stopping host: $($SessionHost)"

            # Ensure the running Azure VM is set as drain mode
            try {
              Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost -AllowNewSession $false -ErrorAction SilentlyContinue
            }
            catch {
              Write-Error "Unable to set it to allow connections on session host: $($SessionHost.SessionHost) with error: $($_.exception.message)" -ErrorAction Continue
              DoExit -exitCode 9
            }

            # Notify user to log off session
            # Get the user sessions in the hostPool
            try {
              $HostPoolUserSessions = Get-RdsUserSession -TenantName $TenantName -HostPoolName $HostpoolName
            }
            catch {
              Write-Error "Failed to retrieve user sessions in hostPool: $($HostpoolName) with error: $($_.exception.message)" -ErrorAction Continue
              DoExit -exitCode 10
            }
            $HostUserSessionCount = ($HostPoolUserSessions | Where-Object -FilterScript { $_.SessionHostName -eq $SessionHost }).Count
            Write-Host "Counting the current sessions on the host $SessionHost...:$HostUserSessionCount"

            $ExistingSession = 0
            foreach ($Session in $HostPoolUserSessions) {
              if ($Session.SessionHostName -eq $SessionHost) {
                if ($LimitSecondsToForceLogOffUser -ne 0) {
                  # Send notification to user
                  try {
                    Send-RdsUserSessionMessage -TenantName $TenantName -HostPoolName $HostpoolName -SessionHostName $session.SessionHostName -SessionId $session.sessionid -MessageTitle $LogOffMessageTitle -MessageBody "$($LogOffMessageBody) You will logged off in $($LimitSecondsToForceLogOffUser) seconds." -NoUserPrompt

                  }
                  catch {
                    Write-Error "Failed to send message to user with error: $($_.exception.message)" -ErrorAction Continue
                    DoExit -exitCode 11
                  }
                }

                $ExistingSession = $ExistingSession + 1
              }
            }

            #wait for n seconds to log off user
            if ($HostUserSessionCount -gt 0)
            {
                Write-Host "Waiting $($LimitSecondsToForceLogOffUser) seconds for user logoff"
                Start-Sleep -Seconds $LimitSecondsToForceLogOffUser
            }

            if ($LimitSecondsToForceLogOffUser -ne 0) {
              #force users to log off
              Write-Host "Force users to log off..."
              try {
                $HostPoolUserSessions = Get-RdsUserSession -TenantName $TenantName -HostPoolName $HostpoolName

              }
              catch {
                Write-Error "Failed to retrieve list of user sessions in hostPool: $($HostpoolName) with error: $($_.exception.message)" -ErrorAction Continue
                DoExit -exitCode 12
              }
              foreach ($Session in $HostPoolUserSessions) {
                if ($Session.SessionHostName -eq $SessionHost) {
                  #log off user
                  try {

                    Invoke-RdsUserSessionLogoff -TenantName $TenantName -HostPoolName $HostpoolName -SessionHostName $Session.SessionHostName -SessionId $Session.sessionid -NoUserPrompt
                    $ExistingSession = $ExistingSession - 1

                  }
                  catch {
                    Write-Error "Failed to log off user with error: $($_.exception.message)" -ErrorAction Continue
                    DoExit -exitCode 13
                  }
                }
              }
            }

            $VMName = $SessionHost.Split(".")[0]
            # Check the Session host is in maintenance
            $VmInfo = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName
            if ($VmInfo.Tags.Keys -contains $MaintenanceTagName) {
              Write-Warning "Session Host is in Maintenance: $($SessionHost | Out-String)"
              $NumberOfRunningHost = $NumberOfRunningHost - 1
              continue
            }

            # Check the session count before shutting down the VM
            if ($ExistingSession -eq 0) {
              # Shutdown the Azure VM
              try {
                Write-Host "Stopping Azure VM: $VMName and waiting for it to complete ..."

                Stop-AzVM -Name $VMName -ResourceGroupName $VmInfo.ResourceGroupName -Force
              }
              catch {
                Write-Error "Failed to stop Azure VM: $VMName with error: $_.exception.message" -ErrorAction Continue
                DoExit -exitCode 14
              }
            }

            # Check if the session host server is healthy before enable allowing new connections
            if ($SessionHostInfo.UpdateState -eq "Succeeded") {
              # Ensure Azure VMs that are stopped have the allowing new connections state True
              try {
                Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost -AllowNewSession $true -ErrorAction SilentlyContinue
              }
              catch {
                Write-Error "Unable to set it to allow connections on session host: $($SessionHost.SessionHost) with error: $($_.exception.message)" -ErrorAction Continue
                DoExit -exitCode 15
              }
            }

            # Decrement the number of running session host
            $NumberOfRunningHost = $NumberOfRunningHost - 1
          }
        }
      }
    }

    # Check whether minimumNoofRDSH Value stored dynamically
    if (Test-Path -Path $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt) {
      [int]$MinimumNumberOfRDSH = Get-Content $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt
      $NoConnectionsofhost = 0
      if ($NumberOfRunningHost -le $MinimumNumberOfRDSH) {
        foreach ($SessionHost in $AllSessionHosts) {
          if (($SessionHost.Status -eq "Available" -or $SessionHost.Status -eq "NeedsAssistance") -and $SessionHost.Sessions -eq 0) {
            $NoConnectionsofhost = $NoConnectionsofhost + 1

          }
        }
        if ($NoConnectionsofhost -gt $DefinedMinimumNumberOfRDSH) {
          [int]$MinimumNumberOfRDSH = [int]$MinimumNumberOfRDSH - $NoConnectionsofhost
          Clear-Content -Path $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt
          Set-Content -Path $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt $MinimumNumberOfRDSH
        }
      }
    }

    $HostpoolMaxSessionLimit = $HostpoolInfo.MaxSessionLimit
    $HostpoolSessionCount = (Get-RdsUserSession -TenantName $TenantName -HostPoolName $HostpoolName).Count
    if ($HostpoolSessionCount -eq 0) {
      Write-Host "HostpoolName:$HostpoolName, NumberofRunnighosts:$NumberOfRunningHost"
      #write to the usage log					   
      $DepthBool = $true
      Write-UsageLog -HostPoolName $HostpoolName -VMCount $NumberOfRunningHost -DepthBool $DepthBool
      Write-Host "End WVD Tenant Scale DepthFirst Optimization"
    }
    else {
      # Calculate the how many sessions will allow in minimum number of RDSH VMs in off peak hours and calculate TotalAllowSessions Scale Factor
      $TotalAllowSessionsInOffPeak = [int]$MinimumNumberOfRDSH * $HostpoolMaxSessionLimit
      $SessionsScaleFactor = $TotalAllowSessionsInOffPeak * 0.90
      $ScaleFactor = [math]::Floor($SessionsScaleFactor)

      if ($HostpoolSessionCount -ge $ScaleFactor) {

        foreach ($SessionHost in $AllSessionHosts) {
          if ($SessionHost.Sessions -ge $SessionHostLimit) {

            #$AllSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName | Sort-Object Sessions | Sort-Object Status
            $AllSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName | Sort-Object SessionHostName
            foreach ($SessionHost in $AllSessionHosts) {

              if (($SessionHost.Status -eq "Available" -or $SessionHost.Status -eq "NeedsAssistance") -and $SessionHost.Sessions -eq 0)
              { break }
              # Check the session host status and if the session host is healthy before starting the host
              if (($SessionHost.Status -eq "NoHeartbeat" -or $SessionHost.Status -eq "Unavailable") -and $SessionHost.UpdateState -eq "Succeeded") {
                Write-Host "Existing Sessionhost Sessions value reached near by hostpool maximumsession limit need to start the session host"
                $SessionHostName = $SessionHost.SessionHostName | Out-String

                $VMName = $SessionHostName.Split(".")[0]
                $VmInfo = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName
                # Check the Session host is in maintenance
                if ($VmInfo.Tags.Keys -contains $MaintenanceTagName) {
                  Write-Warning "Session Host is in Maintenance: $SessionHostName"
                  continue
                }

                # Check if the session host is allowing new connections
                $StateOftheSessionHost = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost.SessionHostName
                if (!($StateOftheSessionHost.AllowNewSession)) {
                  Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost.SessionHostName -AllowNewSession $true
                }

                # Start the Az VM
                try {
                  Write-Host "Starting Azure VM: $VMName and waiting for it to complete ..."
                  Start-AzVM -Name $VMName -ResourceGroupName $VmInfo.ResourceGroupName
                }
                catch {
                  Write-Error "Failed to start Azure VM: $($VMName) with error: $($_.exception.message)" -ErrorAction Continue
                  DoExit -exitCode 16
                }

                # Wait for the sessionhost is available
                $IsHostAvailable = $false
                while (!$IsHostAvailable) {

                  $SessionHostStatus = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost.SessionHostName

                  if (($SessionHostStatus.Status -eq "Available" -or $SessionHost.Status -eq "NeedsAssistance")) {
                    $IsHostAvailable = $true
                  }
                }
                $NumberOfRunningHost = $NumberOfRunningHost + 1
                [int]$MinimumNumberOfRDSH = $MinimumNumberOfRDSH + 1
                if (!(Test-Path -Path $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt)) {
                  New-Item -ItemType File -Path $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt
                  Add-Content $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt $MinimumNumberOfRDSH
                }
                else {
                  Clear-Content -Path $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt
                  Set-Content -Path $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt $MinimumNumberOfRDSH
                }
                break
              }
            }
          }
        }
      }
    }

    Write-Host "HostpoolName:$HostpoolName, NumberofRunnighosts:$NumberOfRunningHost"
    $DepthBool = $true
    Write-UsageLog -HostPoolName $HostpoolName -VMCount $NumberOfRunningHost -DepthBool $DepthBool
  }
  Write-Host "End WVD Tenant DepthFirst Scale Optimization."
}

#Balancing BreadthFirst
if ($HostpoolInfo.LoadBalancerType -eq "BreadthFirst") {
  Write-Host "$HostpoolName hostpool loadbalancer type is $($HostpoolInfo.LoadBalancerType)"
  # check if it is during the peak or off-peak time
  if ($CurrentDateTime -ge $BeginPeakDateTime -and $CurrentDateTime -le $EndPeakDateTime) {
    Write-Host "It is in peak hours now"
    Write-Host "Peak hours: starting session hosts as needed based on current workloads."
    # Get the Session Hosts in the hostPool		
    $AllSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -ErrorAction SilentlyContinue | Sort-Object SessionHostName
    if ($AllSessionHosts -eq $null) {
      Write-Error "Sessionhosts does not exist in the Hostpool of '$HostpoolName'. Ensure that hostpool have hosts or not?." -ErrorAction Continue
      DoExit -exitCode 17
    }

    # Get the User Sessions in the hostPool
    try {
      $HostPoolUserSessions = Get-RdsUserSession -TenantName $TenantName -HostPoolName $HostpoolName
    }
    catch {
      Write-Error "Failed to retrieve user sessions in hostPool:$($HostpoolName) with error: $($_.exception.message)" -ErrorAction Continue
      DoExit -exitCode 18
    }

    # Check and Remove the MinimumnoofRDSH value dynamically stored file												   
    if (Test-Path -Path $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt) {
      Remove-Item -Path $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt
    }

    # Check the number of running session hosts
    $NumberOfRunningHost = 0

    # Total of running cores
    $TotalRunningCores = 0

    # Total capacity of sessions of running VMs
    $AvailableSessionCapacity = 0

    foreach ($SessionHost in $AllSessionHosts) {
      Write-Host "Checking session host:$($SessionHost.SessionHostName | Out-String)  of sessions:$($SessionHost.Sessions) and status:$($SessionHost.Status)"
      $SessionHostName = $SessionHost.SessionHostName | Out-String
      $VMName = $SessionHostName.Split(".")[0]
      $VmInfo = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName
      # Check the Session host is in maintenance
      if ($VmInfo.Tags.Keys -contains $MaintenanceTagName) {
        Write-Warning "Session Host is in Maintenance: $SessionHostName"
        continue
      }
      $RoleInstance = Get-AzVM -Status | Where-Object { $_.Name.Contains($VMName) }
      if ($SessionHostName.ToLower().Contains($RoleInstance.Name.ToLower())) {
        # Check if the azure vm is running       
        if ($RoleInstance.PowerState -eq "VM running") {
          $NumberOfRunningHost = $NumberOfRunningHost + 1
          # Calculate available capacity of sessions						
          $RoleSize = Get-AzVMSize -Location $RoleInstance.Location | Where-Object { $_.Name -eq $RoleInstance.HardwareProfile.VmSize }
          $RoleLimit = ($Variable.WVDScale.MaxSessionsPerVmType | ForEach-Object { $_.Types } | Where-Object { $_.Name -eq $RoleSize }).Value
          #$AvailableSessionCapacity = $AvailableSessionCapacity + $RoleSize.NumberOfCores * $SessionThresholdPerCPU
          $AvailableSessionCapacity = $AvailableSessionCapacity + $RoleLimit
          $TotalRunningCores = $TotalRunningCores + $RoleSize.NumberOfCores
        }

      }

    }
    Write-Host "Current number of running hosts:$NumberOfRunningHost"

    if ($NumberOfRunningHost -le $MinimumNumberOfRDSH) {

      Write-Host "Current number of running session hosts is less than minimum requirements, start session host ..."

      # Start VM to meet the minimum requirement            
      foreach ($SessionHost in $AllSessionHosts.SessionHostName) {

        # Check whether the number of running VMs meets the minimum or not
        if ($NumberOfRunningHost -le $MinimumNumberOfRDSH) {

          $VMName = $SessionHost.Split(".")[0]
          $VmInfo = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName
          # Check the Session host is in maintenance
          if ($VmInfo.Tags.Keys -contains $MaintenanceTagName) {
            Write-Warning "Session Host is in Maintenance: $($SessionHost | Out-String )"
            continue
          }

          $RoleInstance = Get-AzVM -Status | Where-Object { $_.Name.Contains($VMName) }

          if ($SessionHost.ToLower().Contains($RoleInstance.Name.ToLower())) {

            # Check if the Azure VM is running and if the session host is healthy
            $SessionHostInfo = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost
            if ($RoleInstance.PowerState -ne "VM running" -and $SessionHostInfo.UpdateState -eq "Succeeded") {
              # Check if the session host is allowing new connections
              if ($SessionHostInfo.AllowNewSession -eq $false) {
                Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost -AllowNewSession $true

              }
              # Start the Az VM
              try {
                Write-Host "Starting Azure VM: $($RoleInstance.Name) and waiting for it to complete ..."
                Start-AzVM -Name $RoleInstance.Name -Id $RoleInstance.Id -ErrorAction SilentlyContinue
              }
              catch {
                Write-Error "Failed to start Azure VM: $($RoleInstance.Name) with error: $($_.exception.message)" -ErrorAction Continue
                DoExit -exitCode 19
              }
              # Wait for the VM to start
              $IsVMStarted = $false
              while (!$IsVMStarted) {

                $VMState = Get-AzVM -Status | Where-Object { $_.Name -eq $RoleInstance.Name }

                if ($VMState.PowerState -eq "VM running" -and $VMState.ProvisioningState -eq "Succeeded") {
                  $IsVMStarted = $true
                  Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost -AllowNewSession $true
                }
              }
              # Calculate available capacity of sessions

              $RoleSize = Get-AzVMSize -Location $RoleInstance.Location | Where-Object { $_.Name -eq $RoleInstance.HardwareProfile.VmSize }
              $RoleLimit = ($Variable.WVDScale.MaxSessionsPerVmType | ForEach-Object { $_.Types } | Where-Object { $_.Name -eq $RoleSize }).Value
              #$AvailableSessionCapacity = $AvailableSessionCapacity + $RoleSize.NumberOfCores * $SessionThresholdPerCPU
              $AvailableSessionCapacity = $AvailableSessionCapacity + $RoleLimit
              $NumberOfRunningHost = $NumberOfRunningHost + 1
              $TotalRunningCores = $TotalRunningCores + $RoleSize.NumberOfCores
              if ($NumberOfRunningHost -ge $MinimumNumberOfRDSH) {
                break;
              }
            }
          }
        }
      }
    }
    else {
      #check if the available capacity meets the number of sessions or not
      Write-Host "Current total number of user sessions: $(($HostPoolUserSessions).Count)"
      Write-Host "Current available session capacity is: $AvailableSessionCapacity"
      if ($HostPoolUserSessions.Count -ge $AvailableSessionCapacity) {
        Write-Host "Current available session capacity is less than demanded user sessions, starting session host"
        # Running out of capacity, we need to start more VMs if there are any 
        foreach ($SessionHost in $AllSessionHosts.SessionHostName) {
          if ($HostPoolUserSessions.Count -ge $AvailableSessionCapacity) {
            $VMName = $SessionHost.Split(".")[0]
            $VmInfo = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName
            # Check the Session host is in maintenance
            if ($VmInfo.Tags.Keys -contains $MaintenanceTagName) {
              Write-Warning "Session Host is in Maintenance: $($SessionHost | Out-String)"
              continue
            }


            $RoleInstance = Get-AzVM -Status | Where-Object { $_.Name.Contains($VMName) }
             if ($SessionHost.ToLower().Contains($RoleInstance.Name.ToLower())) {
              # Check if the Azure VM is running and if the session host is healthy
              $SessionHostInfo = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost
              if ($RoleInstance.PowerState -ne "VM running" -and $SessionHostInfo.UpdateState -eq "Succeeded") {
                # Check if the session host is allowing new connections
                if ($SessionHostInfo.AllowNewSession -eq $false) {
                  Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost -AllowNewSession $true
                }
                # Start the Az VM
                try {
                  Write-Host "Starting Azure VM: $($RoleInstance.Name) and waiting for it to complete ..."
                  Start-AzVM -Name $RoleInstance.Name -Id $RoleInstance.Id -ErrorAction SilentlyContinue

                }
                catch {
                  Write-Error "Failed to start Azure VM: $($RoleInstance.Name) with error: $($_.exception.message)" -ErrorAction Continue
                  DoExit -exitCode 20
                }
                # Wait for the VM to Start
                $IsVMStarted = $false
                while (!$IsVMStarted) {
                  $VMState = Get-AzVM -Status | Where-Object { $_.Name -eq $RoleInstance.Name }

                  if ($VMState.PowerState -eq "VM running" -and $VMState.ProvisioningState -eq "Succeeded") {
                    $IsVMStarted = $true
                    Write-Host "Azure VM has been started: $($RoleInstance.Name) ..."
                  }
                  else {
                    Write-Host "Waiting for Azure VM to start $($RoleInstance.Name) ..."
                  }
                }
                # Calculate available capacity of sessions

                $RoleSize = Get-AzVMSize -Location $RoleInstance.Location | Where-Object { $_.Name -eq $RoleInstance.HardwareProfile.VmSize }
                $RoleLimit = ($Variable.WVDScale.MaxSessionsPerVmType | ForEach-Object { $_.Types } | Where-Object { $_.Name -eq $RoleSize }).Value
                #$AvailableSessionCapacity = $AvailableSessionCapacity + $RoleSize.NumberOfCores * $SessionThresholdPerCPU
                $AvailableSessionCapacity = $AvailableSessionCapacity + $RoleLimit
                $NumberOfRunningHost = $NumberOfRunningHost + 1
                $TotalRunningCores = $TotalRunningCores + $RoleSize.NumberOfCores
                Write-Host "New available session capacity is: $AvailableSessionCapacity"
                if ($AvailableSessionCapacity -gt $HostPoolUserSessions.Count) {
                  break
                }
              }
              #Break # break out of the inner foreach loop once a match is found and checked
            }
          }
        }
      }
    }
    Write-Host "HostpoolName:$HostpoolName, TotalRunningCores:$TotalRunningCores NumberOfRunningHost:$NumberOfRunningHost"
    # Write to the usage log
    $DepthBool = $false
    Write-UsageLog -HostPoolName $HostpoolName -Corecount $TotalRunningCores -VMCount $NumberOfRunningHost -DepthBool $DepthBool
  }
  else {

    Write-Host "It is Off-peak hours"
    Write-Host "It is off-peak hours. Starting to scale down RD session hosts..."
    Write-Host "Processing hostPool $($HostpoolName)"
    # Get the Session Hosts in the hostPool
    #$AllSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName
    $AllSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName | Sort-Object SessionHostName
    # Check the sessionhosts are exist in the hostpool
    if ($AllSessionHosts -eq $null) {
      Write-Error "Sessionhosts does not exist in the Hostpool of '$HostpoolName'. Ensure that hostpool have hosts or not?." -ErrorAction Continue
      DoExit -exitCode 21
    }

    # Check the number of running session hosts
    $NumberOfRunningHost = 0

    # Total number of running cores
    $TotalRunningCores = 0

    foreach ($SessionHost in $AllSessionHosts.SessionHostName) {

      $VMName = $SessionHost.Split(".")[0]
      $RoleInstance = Get-AzVM -Status | Where-Object { $_.Name.Contains($VMName) }

      if ($SessionHost.ToLower().Contains($RoleInstance.Name.ToLower())) {
        #check if the Azure VM is running or not

        if ($RoleInstance.PowerState -eq "VM running") {
          $NumberOfRunningHost = $NumberOfRunningHost + 1

          # Calculate available capacity of sessions  
          $RoleSize = Get-AzVMSize -Location $RoleInstance.Location | Where-Object { $_.Name -eq $RoleInstance.HardwareProfile.VmSize }

          $TotalRunningCores = $TotalRunningCores + $RoleSize.NumberOfCores
        }
      }
    }
    # Defined minimum no of rdsh value from JSON file
    [int]$DefinedMinimumNumberOfRDSH = $MinimumNumberOfRDSH

    # Check and Collecting dynamically stored MinimumNoOfRDSH Value																 
    if (Test-Path $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt) {
      [int]$MinimumNumberOfRDSH = Get-Content $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt
    }

    if ($NumberOfRunningHost -gt $MinimumNumberOfRDSH) {


      # Shutdown VM to meet the minimum requirement
      foreach ($SessionHost in $AllSessionHosts.SessionHostName) {
        if ($NumberOfRunningHost -gt $MinimumNumberOfRDSH) {

          $VMName = $SessionHost.Split(".")[0]
          $RoleInstance = Get-AzVM -Status | Where-Object { $_.Name.Contains($VMName) }

          if ($SessionHost.ToLower().Contains($RoleInstance.Name.ToLower())) {

            # Check if the Azure VM is running
            if ($RoleInstance.PowerState -eq "VM running") {
              # Check if the role isntance status is ReadyRole before setting the session host
              $IsInstanceReady = $false
              $NumerOfRetries = 0

              while (!$IsInstanceReady -and $NumerOfRetries -le 3) {
                $NumerOfRetries = $NumerOfRetries + 1
                $Instance = Get-AzVM -Status | Where-Object { $_.Name -eq $RoleInstance.Name }
                if ($Instance.ProvisioningState -eq "Succeeded" -and $Instance -ne $null) {
                  $IsInstanceReady = $true
                }

              }
              if ($IsInstanceReady) {

                # Ensure the running Azure VM is set as drain mode
                try {
                  Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost -AllowNewSession $false -ErrorAction SilentlyContinue
                }
                catch {

                  Write-Error "Unable to set it to allow connections on session host: $($SessionHost.SessionHost) with error: $($_.exception.message)" -ErrorAction Continue
                  DoExit -exitCode 22

                }
                # Notify user to log off session
                # Get the user sessions in the hostPool
                try {

                  $HostPoolUserSessions = Get-RdsUserSession -TenantName $TenantName -HostPoolName $HostpoolName

                }
                catch {
                  Write-Error "Failed to retrieve user sessions in hostPool: $($HostpoolName) with error: $($_.exception.message)" -ErrorAction Continue
                  DoExit -exitCode 23
                }

                $HostUserSessionCount = ($HostPoolUserSessions | Where-Object -FilterScript { $_.SessionHostName -eq $SessionHost }).Count
                Write-Host "Counting the current sessions on the host $SessionHost...:$HostUserSessionCount"
                #Write-Host "Counting the current sessions on the host..."
                $ExistingSession = 0

                foreach ($session in $HostPoolUserSessions) {

                  if ($session.SessionHostName -eq $SessionHost) {



                    if ($LimitSecondsToForceLogOffUser -ne 0) {
                      # Send notification
                      try {

                        Send-RdsUserSessionMessage -TenantName $TenantName -HostPoolName $HostpoolName -SessionHostName $SessionHost -SessionId $session.sessionid -MessageTitle $LogOffMessageTitle -MessageBody "$($LogOffMessageBody) You will logged off in $($LimitSecondsToForceLogOffUser) seconds." -NoUserPrompt

                      }
                      catch {

                        Write-Error "Failed to send message to user with error: $($_.exception.message)" -ErrorAction Continue
                        DoExit -exitCode 23

                      }
                    }

                    $ExistingSession = $ExistingSession + 1
                  }
                }
                # Wait for n seconds to log off user
                Start-Sleep -Seconds $LimitSecondsToForceLogOffUser

                if ($LimitSecondsToForceLogOffUser -ne 0) {
                  # Force users to log off
                  Write-Host "Force users to log off..."
                  try {
                    $HostPoolUserSessions = Get-RdsUserSession -TenantName $TenantName -HostPoolName $HostpoolName
                  }
                  catch {
                    Write-Error "Failed to retrieve list of user sessions in hostPool: $($HostpoolName) with error: $($_.exception.message)" -ErrorAction Continue
                    DoExit -exitCode 24
                  }
                  foreach ($Session in $HostPoolUserSessions) {
                    if ($Session.SessionHostName -eq $SessionHost) {
                      #Log off user
                      try {

                        Invoke-RdsUserSessionLogoff -TenantName $TenantName -HostPoolName $HostpoolName -SessionHostName $Session.SessionHostName -SessionId $Session.sessionid -NoUserPrompt

                        $ExistingSession = $ExistingSession - 1
                      }
                      catch {
                        Write-Error "Failed to log off user with error: $($_.exception.message)" -ErrorAction Continue
                        DoExit -exitCode 25
                      }
                    }
                  }
                }


                # Check the session count before shutting down the VM
                if ($ExistingSession -eq 0) {

                  # Check the Session host is in maintenance
                  $VmInfo = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName
                  if ($VmInfo.Tags.Keys -contains $MaintenanceTagName) {
                    Write-Host "Session Host is in Maintenance: $($SessionHost | Out-String)"
                    $NumberOfRunningHost = $NumberOfRunningHost - 1
                    continue
                  }

                  # Shutdown the Azure VM
                  try {
                    Write-Host "Stopping Azure VM: $($RoleInstance.Name) and waiting for it to complete ..."
                    Stop-AzVM -Name $RoleInstance.Name -Id $RoleInstance.Id -Force -ErrorAction SilentlyContinue

                  }
                  catch {
                    Write-Error "Failed to stop Azure VM: $($RoleInstance.Name) with error: $($_.exception.message)" -ErrorAction Continue
                    DoExit -exitCode 26
                  }
                  #wait for the VM to stop
                  $IsVMStopped = $false
                  while (!$IsVMStopped) {

                    $vm = Get-AzVM -Status | Where-Object { $_.Name -eq $RoleInstance.Name }

                    if ($vm.PowerState -eq "VM deallocated") {
                      $IsVMStopped = $true
                      Write-Host "Azure VM has been stopped: $($RoleInstance.Name) ..."
                    }
                    else {
                      Write-Host "Waiting for Azure VM to stop $($RoleInstance.Name) ..."
                    }
                  }
                  $SessionHostInfo = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost
                  if ($SessionHostInfo.UpdateState -eq "Succeeded") {
                    # Ensure the Azure VMs that are off have Allow new connections mode set to True
                    try {
                      Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost -AllowNewSession $true -ErrorAction SilentlyContinue
                    }
                    catch {
                      Write-Error "Unable to set it to allow connections on session host: $($SessionHost | Out-String) with error: $($_.exception.message)" -ErrorAction Continue
                      DoExit -exitCode 27
                    }
                  }
                  $RoleSize = Get-AzVMSize -Location $RoleInstance.Location | Where-Object { $_.Name -eq $RoleInstance.HardwareProfile.VmSize }
                  #decrement number of running session host
                  $NumberOfRunningHost = $NumberOfRunningHost - 1
                  $TotalRunningCores = $TotalRunningCores - $RoleSize.NumberOfCores
                }
              }
            }
          }
        }
      }

    }

    # Check whether minimumNoofRDSH Value stored dynamically and calculate minimumNoOfRDSh value
    if (Test-Path -Path $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt) {
      [int]$MinimumNumberOfRDSH = Get-Content $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt
      $NoConnectionsofhost = 0
      if ($NumberOfRunningHost -le $MinimumNumberOfRDSH) {
        $MinimumNumberOfRDSH = $NumberOfRunningHost
        #$AllSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName | Sort-Object sessions | Sort-Object status
        $AllSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName | Sort-Object SessionHostName
        foreach ($SessionHost in $AllSessionHosts) {
          if (($SessionHost.Status -eq "Available" -or $SessionHost.Status -eq "NeedsAssistance") -and $SessionHost.Sessions -eq 0) {
            $NoConnectionsofhost = $NoConnectionsofhost + 1

          }
        }
        if ($NoConnectionsofhost -gt $DefinedMinimumNumberOfRDSH) {
          [int]$MinimumNumberOfRDSH = [int]$MinimumNumberOfRDSH - $NoConnectionsofhost
          Clear-Content -Path $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt
          Set-Content -Path $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt $MinimumNumberOfRDSH
        }
      }
    }
    # Calculate the how many sessions will allow in minimum number of RDSH VMs in off peak hours
    $HostpoolMaxSessionLimit = $HostpoolInfo.MaxSessionLimit
    $HostpoolSessionCount = (Get-RdsUserSession -TenantName $TenantName -HostPoolName $HostpoolName).Count
    if ($HostpoolSessionCount -eq 0) {
      Write-Host "HostpoolName:$HostpoolName, TotalRunningCores:$TotalRunningCores NumberOfRunningHost:$NumberOfRunningHost"
      # Write to the usage log
      $DepthBool = $false
      Write-UsageLog $HostpoolName $TotalRunningCores $NumberOfRunningHost $DepthBool
      Write-Host "End WVD Tenant Scale BreadthFirst Optimization"
    }
    else {
      # Calculate the how many sessions will allow in minimum number of RDSH VMs in off peak hours and calculate TotalAllowSessions Scale Factor
      $TotalAllowSessionsInOffPeak = [int]$MinimumNumberOfRDSH * $HostpoolMaxSessionLimit
      $SessionsScaleFactor = $TotalAllowSessionsInOffPeak * 0.90
      $ScaleFactor = [math]::Floor($SessionsScaleFactor)


      if ($HostpoolSessionCount -ge $ScaleFactor) {

        # Check if the available capacity meets the number of sessions or not
        Write-Host "Current total number of user sessions: $HostpoolSessionCount"
        Write-Host "Current available session capacity is less than demanded user sessions, starting session host"
        # Running out of capacity, we need to start more VMs if there are any 
        foreach ($SessionHost in $AllSessionHosts) {
          $SessionHostName = $SessionHost.SessionHostName | Out-String
          $VMName = $SessionHostName.Split(".")[0]

          $VmInfo = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName
          # Check the Session host is in maintenance
          if ($VmInfo.Tags.Keys -contains $MaintenanceTagName) {
            Write-Host "Session Host is in Maintenance: $SessionHostName"
            continue
          }
          $RoleInstance = Get-AzVM -Status | Where-Object { $_.Name.Contains($VMName) }
          #
          if (($SessionHost.Status -eq "Available" -or $SessionHost.Status -eq "NeedsAssistance") -and $SessionHost.Sessions -eq 0)
          { break }
          if ($SessionHostName.ToLower().Contains($RoleInstance.Name.ToLower())) {
            # Check if the Azure VM is running and if the session host is healthy
            $SessionHostInfo = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost.SessionHostName
            if ($RoleInstance.PowerState -ne "VM running" -and $SessionHostInfo.UpdateState -eq "Succeeded") {

              if ($SessionHostInfo.AllowNewSession -eq $false) {
                Set-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost.SessionHostName -AllowNewSession $true

              }
              # Start the Az VM
              try {
                Write-Host "Starting Azure VM: $($RoleInstance.Name) and waiting for it to complete ..."
                Start-AzVM -Name $RoleInstance.Name -Id $RoleInstance.Id -ErrorAction SilentlyContinue

              }
              catch {
                Write-Error "Failed to start Azure VM: $($RoleInstance.Name) with error: $($_.exception.message)" -ErrorAction Continue
                DoExit -exitCode 28
              }
              # Wait for the VM to start
              $IsVMStarted = $false
              while (!$IsVMStarted) {
                $VMState = Get-AzVM -Status | Where-Object { $_.Name -eq $RoleInstance.Name }

                if ($VMState.PowerState -eq "VM running" -and $VMState.ProvisioningState -eq "Succeeded") {
                  $IsVMStarted = $true
                  Write-Host "Azure VM has been started: $($RoleInstance.Name) ..."
                }
                else {
                  Write-Host "Waiting for Azure VM to start $($RoleInstance.Name) ..."
                }
              }
              # Calculate available capacity of sessions

              $RoleSize = Get-AzVMSize -Location $RoleInstance.Location | Where-Object { $_.Name -eq $RoleInstance.HardwareProfile.VmSize }
              $AvailableSessionCapacity = $TotalAllowSessions + $HostpoolInfo.MaxSessionLimit
              $NumberOfRunningHost = $NumberOfRunningHost + 1
              $TotalRunningCores = $TotalRunningCores + $RoleSize.NumberOfCores
              Write-Host "New available session capacity is: $AvailableSessionCapacity"

              [int]$MinimumNumberOfRDSH = [int]$MinimumNumberOfRDSH + 1
              if (!(Test-Path -Path $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt)) {
                New-Item -ItemType File -Path $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt
                Add-Content $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt $MinimumNumberOfRDSH
              }
              else {
                Clear-Content -Path $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt
                Set-Content $($AlyaLogs)\scripts\wvd\autoscale\OffPeakUsage-MinimumNoOfRDSH-$($HostpoolName).txt $MinimumNumberOfRDSH
              }
              break
            }
            #Break # break out of the inner foreach loop once a match is found and checked
          }
        }
      }

    }

    Write-Host "HostpoolName:$HostpoolName, TotalRunningCores:$TotalRunningCores NumberOfRunningHost:$NumberOfRunningHost"
    #write to the usage log
    $DepthBool = $false
    Write-UsageLog -HostPoolName $HostpoolName -Corecount $TotalRunningCores -VMCount $NumberOfRunningHost -DepthBool $DepthBool
  } #Scale hostPool

  Write-Host "End WVD Tenant BreadthFirst Scale Optimization."
}

# Stopping Transcript
Stop-Transcript

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCALoqUAfHmtfiFK
# MS1/NNl92cRiG3M5aaaokk2QZ+Gd+KCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIO4NHT5M
# Cldix08fmqP85iY+jxil1O7fkp82kTJgUJYFMA0GCSqGSIb3DQEBAQUABIICABEE
# 6kEluPxe7JKDiSLUSNTr4JvRt0ZhhChcQ3cp2LlT1iH2IoQO3g4vt4rng/s3diR3
# wiDkNz9r03anmOfZ025FUOGFysUwU2lTqD3PNDdmeqbC7SEQFbVBWji9nAiKHs2M
# OPFq3xMmA6tdclSxRS+kY+JK9SGV0bk8jB6qejfjYap13HRhwIAdz4lpBqGhCN6q
# DUxuIxy2X8mbdfLPrw0m2ascL0oBHqVRISIw6qpEZ07p3WtqIAC8ThAQEOawOFiK
# mYc8DUNC1+ShQ2WwTHGInT4z5FvS7Jf18Mat9tRQ/FZ+vXws5A5fLfAqfFdEVlZD
# HI0CH4NyYLR8Pp+/w8GQOMIxhn7ThNGsFaog/wLp0WFkvyxThm0yor1UMK6TG4Q6
# VYMXDzFC2duW41DmOANovivMY8FWYtvK7sqY2EuGCMUTiWqwwdjOWZtjyq/RIwaD
# 57XeAN5qYZdxKJpUx4f6kSSgn1IZe/qJu1H+S0BtZAM6IyJ9+7HKTnwDmkLTkFhh
# 8BaB7ufOMZho/ecZXAhW3U9srfb6QyWk8Wx2UY0DcVlwAl8K1R8gyhYEiE93jD1U
# 8mPTyFM1fxSL4nJ/2SG1oT+hxf35gLeC0c6jQ4ayFc9SLmeH2Td7ygz+y+BFSgNi
# t4yHTuJ3Q+aivRJ2KSCurWTLaS9P3ZF8jfevXfxHoYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCBA9znIwI9cDxb0zWamNnmrjCLo7tjMqIpsbEXrXhX90wIUe5BV
# YFJ+YJtpQE4jilkKyUi9OJcYDzIwMjYwODI5MTU0MjUwWjADAgEBoF2kWzBZMQsw
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
# BDEyBDCkYTdKE4k02kbCmHV1+mhC2rWv8yuPUuT270lpmS6GsQGKBFEm94tFEseL
# UOkF51QwgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGATFrUZ+uzE+WMtvYPYG7VRGfGJDPjB4K3mMs+K0rGtsTe
# 9ldkZjHKkRVgFnIozjunZFTBYjMFig/93zc40aedNRIl0G6nsW5NUtdO7w/h0TOk
# 2JvgXxfEUnP+kFSMA8DsvjVuzHgm5k05hzOX21bedjmAL/0qBsIT0/DCGTRaQjTC
# +69DUtT25Yi9HGwba9RwjYHz9y2cOvWErNrs7IEwZd9KbAfcsbu6xCpup8NI4k8W
# LFNfNCIh9x9Vwa5Se1MvOKhH08+FBidfTQqz2iKZz7GUUcKu0HrhDDZat5pzppyg
# mhUzWmPycZupZ7wbm36tvwJfnMPefVyJQItDUfijflk1WaW1DSURo973WoGdpeH6
# J9yilzASKp9q3UlXMj0H0xQWl8KrtMuYjfV+tWIVBp0ba9VDoFDGPFJYi6WtVlYx
# 1/ahoBEefdMfxYjKHc1Ix9AZECNe1l9IYhtzqReZMox94vH41J8X/OK1SiB5Maeu
# 5Wl9bY1mI2qks7yy+Adw
# SIG # End signature block
