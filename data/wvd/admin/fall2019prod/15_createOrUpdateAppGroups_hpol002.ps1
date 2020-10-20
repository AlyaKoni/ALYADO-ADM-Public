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
    20.10.2020 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\..\..\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\data\wvd\admin\fall2019prod\15_createOrUpdateAppGroups_hpol002-$($AlyaTimeString).log" | Out-Null

# Constants
$HostPoolName = "$($AlyaNamingPrefix)hpol002"
$appDefs = @(`
    @("Explorer",@("C:\Windows\explorer.exe","","C:\SSV\WvdIcons\Explorer.Ico",0)),`
    @("Teams",@("C:\Program Files (x86)\Teams Installer\Teams.exe","--checkInstall --source=PROPLUS","C:\SSV\WvdIcons\Teams.Ico",0))`
)
$appsToGroup = @(@("Standard Apps",@("Access","Excel","OneDrive","OneNote2016","Outlook","PowerPoint","Word","Explorer","GoogleChrome","IrfanView64453","Pdf24","Taskmanager","AcrobatReader2017","RemoteDesktopConnection","Teams","AgentRansack","Firefox","TinyPicExe","WinRar","Notepad"),@("WVDPAPPGRP_Standard")),`
                 @("Visio App",@("Visio"),@("WVDPAPPGRP_Visio")),`
                 @("Project App",@("Project"),@("WVDPAPPGRP_Project")),`
                 @("Abacus App",@("AbacusAbaStart"),@("WVDPAPPGRP_Abacus")),`
                 @("Adobe Apps",@("AdobeCreativeCloud"),@("WVDPAPPGRP_Adobe")))
                 #"AdobeAcrobatDC","AdobeLightroom","AdobePremiereRush","AdobeAfterEffects2019","AdobeAnimate2019","AdobeAudition2019","AdobeBridge2019","AdobeFuseCCBeta","AdobeIllustrator2019","AdobeIncopy2019","AdobeIndesign2019","AdobeMediaEncoder2019","AdobePhotoshopCC2019","AdobePrelude2019","AdobePremierePro2019"
$availableIcons = @("Word","Excel","PowerPoint","Outlook","OneDrive","Access","Visio","Explorer","OneNote2016","Project","GoogleChrome","CitrixWorkspace","IrfanView64453","Pdf24","Taskmanager","SapLogon","FinancialConsolidation","FileZilla","BarracudaMessageArchiverSearch","AcrobatReader2017","AutodeskDesignReview","DwgTrueView2020English","Visimove","DimMan","DrTaxOffice","IDLCockpit","Immopac","Quorum","Teams","IMSWare","AbacusAbaStart","AdobeCreativeCloud","AgentRansack","Firefox","TinyPicExe","WinRar","Notepad","RemoteDesktopConnection")

Write-Host "Launching hostpool script" -ForegroundColor $CommandInfo
& "$($AlyaScripts)\wvd\admin\fall2019prod\15_createOrUpdateAppGroupsApp.ps1" -HostPoolName $HostPoolName -appDefs $appDefs -appsToGroup $appsToGroup -availableIcons $availableIcons

#Stopping Transscript
Stop-Transcript