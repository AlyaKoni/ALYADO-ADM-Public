#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

    This unpublished material is proprietary to Alya Consulting.
    All rights reserved. The methods and techniques described
    herein are considered trade secrets and/or confidential. 
    Reproduction or distribution, in whole or in part, is 
    forbidden except by express written permission of Alya Consulting.

    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    11.08.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$false)]
    [string]$ConfigFile = "Config_alyainfphpol003.json"
)

$RootDir = Split-Path $script:MyInvocation.MyCommand.Path

#Reading configuration
. $RootDir\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\autoscale\03_ScaleHostPool-$($AlyaTimeString).log" | Out-Null

# Constants
$ActualDate = Get-Date
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "Microsoft.RDInfra.RDPowershell"

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | 03_ScaleHostPool | WVD" -ForegroundColor $CommandInfo
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
            $CredentialList = @(Get-ChildItem -Path "$($RootDir)\Creds" -Filter *.cred -ErrorAction STOP)
            foreach ($Cred in $CredentialList) {
                Write-Output $Cred.BaseName
            }
        }
        catch {
            Write-Warning $_.Exception.Message
        }
    }
    if ($UserName) {
        if (Test-Path "$($RootDir)\Creds\$($Username).cred") {
            $PwdSecureString = Get-Content "$($RootDir)\Creds\$($Username).cred" | ConvertTo-SecureString
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
$JsonPath = "$RootDir\$ConfigFile"

# Log path
$WVDTenantUsagelog = "$RootDir\Logs\WVDTenantUsage_$($ConfigFile).log"
New-Item -Path "$($RootDir)\Logs" -ItemType Directory -Force | Out-Null

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
    Write-Error "Missing credentials! Please run 02_SaveCredentials.ps1"
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
    Write-Error "Hostpoolname '$HostpoolName' does not exist in the tenant of '$TenantName'. Ensure that you have entered the correct values."
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

# Get all session hosts in the host pool
$AllSessionHosts = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName | Sort-Object SessionHostName
if ($AllSessionHosts -eq $null) {
    Write-Error "Session hosts does not exist in the Hostpool of '$HostpoolName'. Ensure that hostpool have hosts or not?."
    DoExit -exitCode 5
}

# Check the number of running session hosts and sessions
$HostCount = 0
$NumberOfRunningHost = 0
$NumberOfSessions = 0
foreach ($SessionHost in $AllSessionHosts) {
    Write-Host "Checking session host:$($SessionHost.SessionHostName | Out-String)  of sessions:$($SessionHost.Sessions) and status:$($SessionHost.Status)"
    $SessionCapacityofSessionHost = $SessionHost.Sessions
    if ($SessionHost.Status -eq "Available" -or $SessionHost.Status -eq "NeedsAssistance") {
        $NumberOfRunningHost = $NumberOfRunningHost + 1
        $NumberOfSessions = $NumberOfSessions + $SessionHost.Sessions
    }
}
Write-Host "Current number of running hosts: $NumberOfRunningHost"
Write-Host "Current number of sessions: $NumberOfSessions"

$MaxSessions = $NumberOfRunningHost * $sessionLimit
$PeakSessions = [math]::Floor($MaxSessions * (1 - ($AllSessionHosts.Count - $NumberOfRunningHost) * 0.1))
Write-Host "Current number of peak sessions: $PeakSessions"

if ($NumberOfSessions -gt $PeakSessions)
{
    Write-Host "Current number of running session hosts is less than minimum requirements, start session host ..."
    $hostStartet = $false
    foreach ($SessionHost in $AllSessionHosts) {
        if ($hostStartet) { break }
        if (($SessionHost.Status -eq "NoHeartbeat" -or $SessionHost.Status -eq "Unavailable") -and $SessionHost.UpdateState -eq "Succeeded") {
            $SessionHostName = $SessionHost.SessionHostName | Out-String
            $VMName = $SessionHostName.Split(".")[0]
            $VmInfo = Get-AzVM -Name $VMName -ResourceGroupName $ResourceGroupName

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
                Write-Error "Failed to start Azure VM: $($VMName) with error: $($_.exception.message)"
                DoExit -exitCode 6
            }

            # Wait for the sessionhost to start
            $IsHostAvailable = $false
            while (!$IsHostAvailable) {
                $SessionHostStatus = Get-RdsSessionHost -TenantName $TenantName -HostPoolName $HostpoolName -Name $SessionHost.SessionHostName
                if (($SessionHostStatus.Status -eq "Available" -or $SessionHost.Status -eq "NeedsAssistance")) {
                    $IsHostAvailable = $true
                    $NumberOfRunningHost = $NumberOfRunningHost + 1
                    $hostStartet = $true
                }
                else
                {
                    Start-Sleep -Seconds 15
                }
            }
        }
    }
}

Write-Host "HostpoolName:$HostpoolName, NumberofRunnighosts:$NumberOfRunningHost"
Write-UsageLog -HostPoolName $HostpoolName -VMCount $NumberOfRunningHost -DepthBool $true

#Stopping Transscript
Stop-Transcript
