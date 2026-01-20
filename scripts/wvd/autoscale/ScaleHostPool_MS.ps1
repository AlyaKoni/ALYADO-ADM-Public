#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2026

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
    21.04.2020 Konrad Brunner       Initial Version

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

#Reading configuration
. $RootDir\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
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

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD6eHn+AfQflH1B
# rvUTEZpOXHiaIKmEwqFuxHE5wkRIn6CCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIB/mSRTWFtWMN6HL
# VDr91iPcWuF6g4TrpkOeVeTkG3MKMA0GCSqGSIb3DQEBAQUABIICAJYSPmYxqCrc
# TUVAMz+rQDvo5/AYc4u4S3cgbVArKxgsFtriHIPmePSiUD/NNtDNfSY8+uSUFyRo
# dDjHZCldlL9SN9FX7dFMUdDJiRzMs3P5cwplpykQgUSsjrQHwu99h+6Y37X6ZLfZ
# +2oB3CJU36tP2FnkifOLLq2TpZo3kUDjmCfSiHuEioIDsS8rSHJjZrKPsGLrqd3j
# BTIDQZVVqPHv6+3S8w1MvRiGHX844aHDeBqIkcM3n2Hl9PXbuP41xR+TmECvT9IG
# XAdtitQuwU1yqxl/pNB3q1jfheAS3Baz5/TiRgTeU/fDOhuZkkfFlCzwu4HQ4htZ
# iqVRzVNsb4IEKFcNQybFm3DjXw6hVMVksx7zDHJqfpYhyNT63NltTN+Hr/HzJEOQ
# ZAX2JZZSGeeKcH2E4VMO/lqmIEO2JREmS2onwJadM27nLTowtj6KcD66nup+f77+
# 3tYu55e0rfGEGTG669d4gbiq5QXNlSJgkMS1eAUx607Zuw/dyqLTfEgnYmhSne+l
# iPldzzTOuz6cIbyqVLAQhSXDaUwl6rpSQA0TrYYnAfmS1lqO13JI43ldt7vT/2uL
# 2+aD3pZla2NHVCECf2G1AJ4hnstVUXaQwQ8xHkVdEi2AN7zikHuvjsEzqXUOwKeR
# Rqqu1htIHMrIhdnYWVXyym6wDqBrCrtIoYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCA6xI60sg2HvUNg4/mtikqQnz6+LOpdY/5xqmQBHTajFAIUHHLeN4crVvw0
# x1UgA7buIJIYztoYDzIwMjYwMTIwMTAxMjU1WjADAgEBoFikVjBUMQswCQYDVQQG
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
# IL2YJLvl2mCHIp79sbH4CYKmO+BgYmQq5wWSvr+V3HPXMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAXOYVB+1HQOGX
# syJ3LXTrNsuaplJUX2D64Ng5GGmO7DR/1nZYy/p9LIcX7k6I4oR8aplGhDk2Qudg
# R6whe0tswQOd+/GMT2HRrFdp9zcs+0XFzfNkQ544EB6gEx25fOImINhsu2z8SCwn
# MgfaGjAEp/3uBibzqHx41DwNAUWPyMSsf/e+nosZbmE07Owcbp+UZqCeux8BgOLU
# lC7mLXXnutvWEjc+cf8D+sJTzzWqR7Ju80DHMNk1A8iE6gfAnXdzeCF24crWb577
# SyoId3Dnum0VfT6DkKgpHC4CxHMDIIf2AZYEykX6mFQewLtBFjxsaHXuD0pssBqV
# RA+u0JZ0Bkir7ZQM/EBj7PgqoTFKlt9aOQx0pvIM1OFniUMbNRNdPk09L3yWStTC
# hIiDM2UR62jR2dezVpqAfZaI2e692aN5tLl3EsSWgu65UBtTyhzcuv1Crb5uedUp
# eVDLCvyttNiWPh/qO+YnTtQXC8bDWFdM7jIGc8XAKxJeNkfEoav4
# SIG # End signature block
