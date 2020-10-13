#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting: 2020

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
    Alya Basis Konfiguration ist Freie Software: Sie koennen es unter den
	Bedingungen der GNU General Public License, wie von der Free Software
	Foundation, Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
    veroeffentlichten Version, weiter verteilen und/oder modifizieren.
    Alya Basis Konfiguration wird in der Hoffnung, dass es nuetzlich sein wird,
	aber OHNE JEDE GEWAEHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewaehrleistung der MARKTFAEHIGKEIT oder EIGNUNG FUER EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Public License fuer weitere Details:
	https://www.gnu.org/licenses/gpl-3.0.txt

    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    12.03.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\wvd\admin\fall2019prod\11_createOrUpdateAppGroups_hpol001-$($AlyaTimeString).log" | Out-Null

# Constants
$HostPoolName = "$($AlyaNamingPrefix)hpol001"
$KeyVaultName = "$($AlyaNamingPrefix)keyv$($AlyaResIdMainKeyVault)"
$AppGroupNameToDelete = "Desktop Application Group"
$appDefs = @(`
    @("MesserliAdr",@("L:\Messerli\Programme\AdrMess.exe","","C:\$($AlyaCompanyName)\WvdIcons\MesserliAdr.Ico",0)), `
    @("MesserliBau",@("L:\Messerli\Programme\WINMESS.EXE","","C:\$($AlyaCompanyName)\WvdIcons\MesserliBau.Ico",0)), `
    @("ImmoTopKreditoren",@("I:\WWProg\omnis.exe","KRISTART.lbs","C:\$($AlyaCompanyName)\WvdIcons\ImmoTopKreditoren.Ico",0)), `
    @("ImmoTopLiegenschaften",@("I:\WWProg\omnis.exe","LGISTART.lbs","C:\$($AlyaCompanyName)\WvdIcons\ImmoTopLiegenschaften.Ico",0)), `
    @("RealFM24",@("C:\Program Files\Mozilla Firefox\firefox.exe","https://app.realfm24.ch","C:\$($AlyaCompanyName)\WvdIcons\RealFM24.Ico",0)), `
    @("Explorer",@("C:\Windows\explorer.exe","","C:\$($AlyaCompanyName)\WvdIcons\Explorer.Ico",0)), `
    @("Abacus",@("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\AlyaConsulting\AbacusStart.cmd","","C:\$($AlyaCompanyName)\WvdIcons\AbacusAbaStart.Ico",0)), `
    @("Logoff",@("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\AlyaConsulting\Logoff.cmd","","C:\$($AlyaCompanyName)\WvdIcons\Logoff.Ico",0)), `
    @("SiaVTool",@("L:\SIA\vTool_DE_10_14.xlam","","C:\$($AlyaCompanyName)\WvdIcons\SiaVTool.Ico",0)), `
    @("Office365",@("C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe","https://portal.office.com","C:\$($AlyaCompanyName)\WvdIcons\Explorer.Ico",0)) `
)
$appsToGroup = @(@("Standard Apps",@("Access","Excel","OneDrive","OneNote2016","Outlook","PowerPoint","Word","Explorer","MicrosoftEdge","Taskmanager", "AcrobatReader2020", "RemoteDesktopVerbindung", "AdobeCreativeCloud", "AdobeAcrobatDC", "AdressPLUS2017", "Terminmanager", "AzureInformationProtectionViewer", "Comatic7", "RealFM24", "MesserliAdr", "MesserliBau", "ImmoTopKreditoren", "ImmoTopLiegenschaften", "Abacus", "SiaVTool","Logoff"),@("ALYASG-ADM-APPSTD")),`
                 @("Visio App",@("Visio"),@("ALYASG-ADM-APPVISIO")),`
                 @("Project App",@("Project"),@("ALYASG-ADM-APPPRJCT"))<#, `
                 @("Adobe Apps",@("AdobeCreativeCloud","AdobeAcrobatDC"),@("ALYASG-ADM-APPADOBE"))#>)
$BasePath = "C:\$($AlyaCompanyName)\WvdIcons"
$availableIcons = @("Word","Excel","PowerPoint","Outlook","OneDrive","Access","Visio","Explorer","OneNote2016","SkypeForBusiness","Project","GoogleChrome","CitrixWorkspace","IrfanView64453","Pdf24","Taskmanager","SapLogon","FinancialConsolidation","FileZilla","BarracudaMessageArchiverSearch","AcrobatReader2017","AcrobatReader2020","AutodeskDesignReview","DwgTrueView2020English","Visimove","DimMan","DrTaxOffice","IDLCockpit","Immopac","Quorum","Teams","IMSWare","AbacusAbaStart","AdobeCreativeCloud","AgentRansack","Firefox","TinyPicExe","WinRar","Notepad","RemoteDesktopConnection","RemoteDesktopVerbindung","MicrosoftEdge","MicrosoftEdgeBeta","AcrobatReaderDC","AdobeAcrobatDC","AdressPLUS2017","Terminmanager","AzureInformationProtectionViewer","Comatic7","RealFM24","MesserliAdr","MesserliBau","ImmoTopKreditoren","ImmoTopLiegenschaften")

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "Microsoft.RDInfra.RDPowershell"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

# =============================================================
# Azure stuff
# =============================================================

Write-Host "`n`n=====================================================" -ForegroundColor $CommandInfo
Write-Host "WVD | 11_createOrUpdateAppGroups_hpol001 | AZURE" -ForegroundColor $CommandInfo
Write-Host "=====================================================`n" -ForegroundColor $CommandInfo

# Getting context
$Context = Get-AzContext
if (-Not $Context)
{
    Write-Error "Can't get Az context! Not logged in?" -ErrorAction Continue
    Exit 1
}

# Checking application
Write-Host "Checking application" -ForegroundColor $CommandInfo
$AzureAdApplication = Get-AzADApplication -DisplayName $AlyaWvdServicePrincipalNameProd -ErrorAction SilentlyContinue
if (-Not $AzureAdApplication)
{
    throw "Azure AD Application not found. Please create the Azure AD Application $AlyaWvdServicePrincipalNameProd"
}
$AzureAdServicePrincipal = Get-AzADServicePrincipal -DisplayName $AlyaWvdServicePrincipalNameProd

# Checking azure key vault secret
Write-Host "Checking azure key vault secret" -ForegroundColor $CommandInfo
$AlyaWvdServicePrincipalAssetName = "$($AlyaWvdServicePrincipalNameProd)Key"
$AzureKeyVaultSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $AlyaWvdServicePrincipalAssetName -ErrorAction SilentlyContinue
if (-Not $AzureKeyVaultSecret)
{
    throw "Key Vault secret not found. Please create the secret $AlyaWvdServicePrincipalAssetName"
}
$AlyaWvdServicePrincipalPassword = ($AzureKeyVaultSecret.SecretValue | foreach { [System.Net.NetworkCredential]::new("", $_).Password })
$AlyaWvdServicePrincipalPasswordSave = ConvertTo-SecureString $AlyaWvdServicePrincipalPassword -AsPlainText -Force

# Login to WVD
if (-Not $Global:RdsContext)
{
	Write-Host "Logging in to wvd" -ForegroundColor $CommandInfo
	$rdsCreds = New-Object System.Management.Automation.PSCredential($AzureAdServicePrincipal.ApplicationId, $AlyaWvdServicePrincipalPasswordSave)
	$Global:RdsContext = Add-RdsAccount -DeploymentUrl $AlyaWvdRDBroker -Credential $rdsCreds -ServicePrincipal -AadTenantId $AlyaTenantId
	#LoginTo-Wvd -AppId $AzureAdServicePrincipal.ApplicationId -SecPwd $AlyaWvdServicePrincipalPasswordSave
}

# Deleting app group
Write-Host "Deleting app group $AppGroupNameToDelete" -ForegroundColor $CommandInfo
$appToDelete = Get-RdsAppGroup -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName | where { $_.AppGroupName -eq $AppGroupNameToDelete }
if ($appToDelete)
{
    Remove-RdsAppGroup -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -Name $AppGroupNameToDelete
}

# Building app groups
Write-Host "Building app groups" -ForegroundColor $CommandInfo
foreach($appGrp in $appsToGroup)
{
    $appGrpName = $appGrp[0]
    Write-Host "App group $($appGrpName)"
    $appsFromGrp = $appGrp[1]
    $accessToGrp = $appGrp[2]
    $appGrp = Get-RdsAppGroup -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -Name $appGrpName -ErrorAction SilentlyContinue
    if (-Not $appGrp)
    {
        Write-Host " - Adding app group $($appGrpName)"
        $appGrp = New-RdsAppGroup -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -Name $appGrpName
    }
    $appGrpApps = Get-RdsRemoteApp -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -AppGroupName $appGrpName
    foreach ($appName in $appsFromGrp)
    {
        $existApp = $appGrpApps | where { $_.RemoteAppName -eq $appName }
        if (-Not $existApp)
        {
            Write-Host " - Adding app $($appName)"
            $wasDefinedApp = $false
            foreach ($appDef in $appDefs)
            {
                if ($appDef[0] -eq $appName)
                {
                    $wasDefinedApp = $true
                    $params = $appDef[1]
                    if ($params[1] -ne $null -and $params[1].Length -gt 0)
                    {
                        New-RdsRemoteApp -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -AppGroupName $appGrpName -Name $appName -FilePath $params[0] -RequiredCommandLine $params[1] -CommandLineSetting Require -IconPath $params[2] -IconIndex $params[3]
                    }
                    else
                    {
                        New-RdsRemoteApp -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -AppGroupName $appGrpName -Name $appName -FilePath $params[0] -IconPath $params[2] -IconIndex $params[3]
                    }
                    break
                }
            }
            if (-Not $wasDefinedApp)
            {
                $iconPath = $BasePath + "\" + $appName + ".Ico"
                if ($availableIcons -contains $appName)
                {
                    New-RdsRemoteApp -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -AppGroupName $appGrpName -AppAlias $appName -Name $appName -IconPath $iconPath -IconIndex 0
                }
                else
                {
                    New-RdsRemoteApp -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -AppGroupName $appGrpName -AppAlias $appName -Name $appName
                }
            }
        }
    }
    $appGrpApps = Get-RdsRemoteApp -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -AppGroupName $appGrpName
    foreach ($existApp in $appGrpApps)
    {
        $missingApp = $appsFromGrp | where { $_ -eq $existApp.RemoteAppName }
        if (-Not $missingApp)
        {
            Write-Host " - Removing app $($existApp.RemoteAppName)"
            Remove-RdsRemoteApp -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -AppGroupName $appGrpName -Name $existApp.RemoteAppName
        }
    }
    $grpUsers = Get-RdsAppGroupUser $AlyaWvdTenantNameProd $HostPoolName $appGrpName
    $allMembs = @()
    Write-Host " - Access for admins"
    foreach ($admin in $AlyaWvdAdmins)
    {
        if (-Not $allMembs.Contains($admin))
        {
            $allMembs += $admin
        }
        $grpUser = $grpUsers | where { $_.UserPrincipalName -eq $admin }
        if (-Not $grpUser)
        {
            Write-Host "   - Adding user $($admin)"
            Add-RdsAppGroupUser $AlyaWvdTenantNameProd $HostPoolName $appGrpName -UserPrincipalName $admin
        }
    }
    foreach ($accessGrp in $accessToGrp)
    {
        Write-Host " - Access for $($accessGrp)"
        $grp = Get-AzADGroup -SearchString $accessGrp | Select-Object -First 1
        $membs = Get-AzADGroupMember -GroupObject $grp
        foreach ($memb in $membs)
        {
            if (-Not $allMembs.Contains($memb.UserPrincipalName))
            {
                $allMembs += $memb.UserPrincipalName
            }
            $grpUser = $grpUsers | where { $_.UserPrincipalName -eq $memb.UserPrincipalName }
            if (-Not $grpUser)
            {
                Write-Host "   - Adding user $($memb.UserPrincipalName)"
                Add-RdsAppGroupUser $AlyaWvdTenantNameProd $HostPoolName $appGrpName -UserPrincipalName $memb.UserPrincipalName
            }
        }
    }
    foreach ($grpUser in $grpUsers)
    {
        $memb = $allMembs | where { $_ -eq $grpUser.UserPrincipalName }
        if (-Not $memb)
        {
            Write-Host " - Removing user $($grpUser.UserPrincipalName)"
            Remove-RdsAppGroupUser $AlyaWvdTenantNameProd $HostPoolName $appGrpName -UserPrincipalName $grpUser.UserPrincipalName
        }
    }
}


#Get-RdsStartMenuApp -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -AppGroupName "Desktop Application Group" | select AppAlias
#(Get-RdsRemoteApp -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -AppGroupName "Standard Apps").FriendlyName
#Remove-RdsRemoteApp -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -AppGroupName "Standard Apps" -Name "DynamicsCRM"
#Get-RdsRemoteApp -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -AppGroupName "Standard Apps" -Name "Quorum"
#Set-RdsRemoteApp -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -AppGroupName "Standard Apps" -Name "Explorer" -CommandLineSetting Allow
#Set-RdsRemoteApp -TenantName $AlyaWvdTenantNameProd -HostPoolName $HostPoolName -AppGroupName "Standard Apps" -Name "Explorer" -IconPath "C:\SSV\WvdIcons\Explorer.Ico" -IconIndex 0


#Stopping Transscript
Stop-Transcript