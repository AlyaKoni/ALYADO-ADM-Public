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
