#Requires -Version 2.0

<#
    Copyright (c) Basler & Hofmann, 2021

    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    10.11.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [ValidateSet("AD","AAD")]
    [String]
    $JoinOption = "AD",
    [ValidateSet("Image","Gallery")]
    [String]
    $ImageOption = "Gallery"
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\avd\admin\test\06_Update-SessionHosts-$($AlyaTimeString).log" | Out-Null

# Constants
$ShResourceGroupName = "$($AlyaNamingPrefixTest)resg$($AlyaResIdAvdSessionHostsResGrp)"
$ResourceGroupName = "$($AlyaNamingPrefixTest)resg$($AlyaResIdAvdManagementResGrp)"
$HostPoolName = "$($AlyaNamingPrefixTest)avdh$($AlyaResIdAvdHostpool)"
$WorkspaceName = "$($AlyaNamingPrefixTest)avdw$($AlyaResIdAvdWorkspace)"

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.DesktopVirtualization"
Install-ModuleIfNotInstalled "Az.Resources"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionNameTest

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AVD | 06_Update-SessionHosts | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Asking update
$title    = "HostPool Update"
$question = "Do you like to update host pool $($HostPoolName) with latest image version?"
$choices  = "&Yes", "&No"
$decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
if ($decision -ne 0) {
    exit
}

# Checking HostPool
Write-Host "Checking HostPool $($HostPoolName)" -ForegroundColor $CommandInfo
$HstPl = Get-AzWvdHostPool -Name $HostPoolName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $HstPl)
{
    throw "HostPool not found. Please create the HostPool $($HostPoolName) with the script 02_Create-HostPool.ps1"
}

# Checking workspace
Write-Host "Checking workspace" -ForegroundColor $CommandInfo
$WrkSpc = Get-AzWvdWorkspace -Name $WorkspaceName -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
if (-Not $WrkSpc)
{
    throw "Workspace not found. Please create the workspace $($WorkspaceName) with the script Create-Workspace.ps1"
}

# Removing session hosts
Write-Host "Removing session hosts" -ForegroundColor $CommandInfo

$sessionHosts = Get-AzVM -ResourceGroupName $ShResourceGroupName
foreach($sessionHost in $sessionHosts)
{
    $VMName = $sessionHost.Name
    Write-Host "Removing session host $VMName" -ForegroundColor $CommandInfo
    $shost = Get-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName | Where-Object { $_.Name -like "*$VMName*"}
    if ($shost)
    {
        $sHostName = $shost.Name.Replace($HostPoolName, "").Trim("/")
        Remove-AzWvdSessionHost -HostPoolName $HostPoolName -ResourceGroupName $ResourceGroupName -Name $sHostName -SubscriptionId $Context.Subscription.Id -Force
    }
}

# Checking ressource group
Write-Host "Checking ressource group $($ShResourceGroupName)" -ForegroundColor $CommandInfo
$ResGrp = Get-AzResourceGroup -Name $ShResourceGroupName -ErrorAction SilentlyContinue
if (-Not $ResGrp)
{
    Write-Host "    Does not exist. Nothing to do" -ForegroundColor $CommandWarning
}
else
{
    Write-Warning "Deleting ressource group $($ShResourceGroupName)"
    $ResGrp = Remove-AzResourceGroup -Name $ShResourceGroupName -ErrorAction SilentlyContinue
    do
    {
        $ResGrp = Get-AzResourceGroup -Name $ShResourceGroupName -ErrorAction SilentlyContinue
        if ($ResGrp) { Start-Sleep -Seconds 10 }
    }
    while ($ResGrp)
}

# Starting session host creation
& "$PSScriptRoot\06_Create-SessionHosts.ps1" -JoinOption $JoinOption -ImageOption $ImageOption

#Stopping Transscript
Stop-Transcript
