#Requires -Version 2.0

<#
    Copyright (c) SwissShooting, 2022

    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    20.05.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\avd\admin\test\Configure-AutoScaleRole-$($AlyaTimeString).log" | Out-Null

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionNameTest

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "AVD | Configure-AutoScaleRole | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking custom role
Write-Host "Checking custom role" -ForegroundColor $CommandInfo
$scope = "/subscriptions/$($Context.Subscription.Id)"
$role = Get-AzRoleDefinition -Name "$($AlyaCompanyNameShortM365)AutoscaleTest" -Scope $scope -ErrorAction SilentlyContinue
if (-Not $Role)
{
    $roleDef = @"
{
  "Name": "$($AlyaCompanyNameShortM365)AutoscaleTest",
  "IsCustom": true,
  "Description": "Role to allow avd autoscaling hostpools.",
  "Actions": [
    "Microsoft.Insights/eventtypes/values/read",
    "Microsoft.Compute/virtualMachines/deallocate/action",
    "Microsoft.Compute/virtualMachines/restart/action",
    "Microsoft.Compute/virtualMachines/powerOff/action",
    "Microsoft.Compute/virtualMachines/start/action",
    "Microsoft.Compute/virtualMachines/read",
    "Microsoft.DesktopVirtualization/hostpools/read",
    "Microsoft.DesktopVirtualization/hostpools/write",
    "Microsoft.DesktopVirtualization/hostpools/sessionhosts/read",
    "Microsoft.DesktopVirtualization/hostpools/sessionhosts/write",
    "Microsoft.DesktopVirtualization/hostpools/sessionhosts/usersessions/delete",
    "Microsoft.DesktopVirtualization/hostpools/sessionhosts/usersessions/read",
    "Microsoft.DesktopVirtualization/hostpools/sessionhosts/usersessions/sendMessage/action"
  ],
  "NotActions": [],
  "DataActions": [],
  "NotDataActions": [],
  "AssignableScopes": [
    "$scope"
  ]
}
"@
    $temp = New-TemporaryFile
    $roleDef | Set-Content -Path $temp -Encoding UTF8 -Force
    New-AzRoleDefinition -InputFile $temp.FullName
    Remove-Item -Path $temp -Force
    do
    {
        Start-Sleep -Seconds 10
        $role = Get-AzRoleDefinition -Name "$($AlyaCompanyNameShortM365)AutoscaleTest" -Scope $scope -ErrorAction SilentlyContinue
    }
    while (-Not $role)
}

# Checking role assignment
Write-Host "Checking role assignment" -ForegroundColor $CommandInfo
$objs = Get-AzADServicePrincipal -DisplayName "Windows Virtual Desktop"
foreach($obj in $objs)
{
    $ra = Get-AzRoleAssignment -RoleDefinitionName "$($AlyaCompanyNameShortM365)AutoscaleTest" -ObjectId $obj.Id -ErrorAction SilentlyContinue
    if (-Not $ra)
    {
        Write-Warning "  Role assigment on subscription not found. Adding it now..."
        $ra = New-AzRoleAssignment -RoleDefinitionName "$($AlyaCompanyNameShortM365)AutoscaleTest" -ObjectId $obj.Id
    }
}

$objs = Get-AzADServicePrincipal -DisplayName "Azure Virtual Desktop"
foreach($obj in $objs)
{
    $ra = Get-AzRoleAssignment -RoleDefinitionName "$($AlyaCompanyNameShortM365)AutoscaleTest" -ObjectId $obj.Id -ErrorAction SilentlyContinue
    if (-Not $ra)
    {
        Write-Warning "  Role assigment on subscription not found. Adding it now..."
        $ra = New-AzRoleAssignment -RoleDefinitionName "$($AlyaCompanyNameShortM365)AutoscaleTest" -ObjectId $obj.Id
    }
}

#Stopping Transscript
Stop-Transcript
