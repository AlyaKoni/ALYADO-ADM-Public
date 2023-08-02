#Requires -Version 2.0

<#
    Copyright (c) Alya Consulting, 2019-2023

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
    24.10.2020 Konrad Brunner       Initial version
    20.04.2023 Konrad Brunner       Updated module list and added cleaning old once
#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\04_PrepareModulesAndPackages-$($AlyaTimeString).log" | Out-Null

#Main
Install-ModuleIfNotInstalled "PackageManagement"
Install-ModuleIfNotInstalled "PowershellGet"

Install-ModuleIfNotInstalled "AIPService"
Install-ModuleIfNotInstalled "Az"
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.ADDomainServices"
Install-ModuleIfNotInstalled "Az.Advisor"
Install-ModuleIfNotInstalled "Az.Aks"
Install-ModuleIfNotInstalled "Az.AnalysisServices"
Install-ModuleIfNotInstalled "Az.ApiManagement"
Install-ModuleIfNotInstalled "Az.AppConfiguration"
Install-ModuleIfNotInstalled "Az.ApplicationInsights"
Install-ModuleIfNotInstalled "Az.Attestation"
Install-ModuleIfNotInstalled "Az.Automation"
Install-ModuleIfNotInstalled "Az.Batch"
Install-ModuleIfNotInstalled "Az.Billing"
Install-ModuleIfNotInstalled "Az.Cdn"
Install-ModuleIfNotInstalled "Az.CloudService"
Install-ModuleIfNotInstalled "Az.CognitiveServices"
Install-ModuleIfNotInstalled "Az.Compute"
Install-ModuleIfNotInstalled "Az.ConfidentialLedger"
Install-ModuleIfNotInstalled "Az.ContainerInstance"
Install-ModuleIfNotInstalled "Az.ContainerRegistry"
Install-ModuleIfNotInstalled "Az.CosmosDB"
Install-ModuleIfNotInstalled "Az.DataBoxEdge"
Install-ModuleIfNotInstalled "Az.Databricks"
Install-ModuleIfNotInstalled "Az.DataFactory"
Install-ModuleIfNotInstalled "Az.DataLakeAnalytics"
Install-ModuleIfNotInstalled "Az.DataLakeStore"
Install-ModuleIfNotInstalled "Az.DataProtection"
Install-ModuleIfNotInstalled "Az.DataShare"
Install-ModuleIfNotInstalled "Az.DeploymentManager"
Install-ModuleIfNotInstalled "Az.DesktopVirtualization"
Install-ModuleIfNotInstalled "Az.DevTestLabs"
Install-ModuleIfNotInstalled "Az.Dns"
Install-ModuleIfNotInstalled "Az.EventGrid"
Install-ModuleIfNotInstalled "Az.EventHub"
Install-ModuleIfNotInstalled "Az.FrontDoor"
Install-ModuleIfNotInstalled "Az.Functions"
Install-ModuleIfNotInstalled "Az.HDInsight"
Install-ModuleIfNotInstalled "Az.HealthcareApis"
Install-ModuleIfNotInstalled "Az.IotHub"
Install-ModuleIfNotInstalled "Az.KeyVault"
Install-ModuleIfNotInstalled "Az.Kusto"
Install-ModuleIfNotInstalled "Az.LogicApp"
Install-ModuleIfNotInstalled "Az.MachineLearning"
Install-ModuleIfNotInstalled "Az.Maintenance"
Install-ModuleIfNotInstalled "Az.ManagedServiceIdentity"
Install-ModuleIfNotInstalled "Az.ManagedServices"
Install-ModuleIfNotInstalled "Az.MarketplaceOrdering"
Install-ModuleIfNotInstalled "Az.Media"
Install-ModuleIfNotInstalled "Az.Migrate"
Install-ModuleIfNotInstalled "Az.Monitor"
Install-ModuleIfNotInstalled "Az.MySql"
Install-ModuleIfNotInstalled "Az.Network"
Install-ModuleIfNotInstalled "Az.NotificationHubs"
Install-ModuleIfNotInstalled "Az.OperationalInsights"
Install-ModuleIfNotInstalled "Az.PolicyInsights"
Install-ModuleIfNotInstalled "Az.PostgreSql"
Install-ModuleIfNotInstalled "Az.PowerBIEmbedded"
Install-ModuleIfNotInstalled "Az.PrivateDns"
Install-ModuleIfNotInstalled "Az.RecoveryServices"
Install-ModuleIfNotInstalled "Az.RedisCache"
Install-ModuleIfNotInstalled "Az.RedisEnterpriseCache"
Install-ModuleIfNotInstalled "Az.Relay"
Install-ModuleIfNotInstalled "Az.ResourceMover"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "Az.Security"
Install-ModuleIfNotInstalled "Az.SecurityInsights"
Install-ModuleIfNotInstalled "Az.ServiceBus"
Install-ModuleIfNotInstalled "Az.ServiceFabric"
Install-ModuleIfNotInstalled "Az.SignalR"
Install-ModuleIfNotInstalled "Az.Sql"
Install-ModuleIfNotInstalled "Az.SqlVirtualMachine"
Install-ModuleIfNotInstalled "Az.StackHCI"
Install-ModuleIfNotInstalled "Az.Storage"
Install-ModuleIfNotInstalled "Az.StorageSync"
Install-ModuleIfNotInstalled "Az.StreamAnalytics"
Install-ModuleIfNotInstalled "Az.Support"
Install-ModuleIfNotInstalled "Az.Synapse"
Install-ModuleIfNotInstalled "Az.TrafficManager"
Install-ModuleIfNotInstalled "Az.Websites"
Install-ModuleIfNotInstalled "AzTable"
Install-ModuleIfNotInstalled "AzureADPreview"
Install-ModuleIfNotInstalled "DataGateway"
Install-ModuleIfNotInstalled "DataGateway.Profile"
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"
Install-ModuleIfNotInstalled "ImportExcel"
Install-ModuleIfNotInstalled "Microsoft.Graph"
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Applications"
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication"
Install-ModuleIfNotInstalled "Microsoft.Graph.Bookings"
Install-ModuleIfNotInstalled "Microsoft.Graph.Calendar"
Install-ModuleIfNotInstalled "Microsoft.Graph.ChangeNotifications"
Install-ModuleIfNotInstalled "Microsoft.Graph.CloudCommunications"
Install-ModuleIfNotInstalled "Microsoft.Graph.Compliance"
Install-ModuleIfNotInstalled "Microsoft.Graph.CrossDeviceExperiences"
Install-ModuleIfNotInstalled "Microsoft.Graph.DeviceManagement"
Install-ModuleIfNotInstalled "Microsoft.Graph.DeviceManagement.Actions"
Install-ModuleIfNotInstalled "Microsoft.Graph.DeviceManagement.Administration"
Install-ModuleIfNotInstalled "Microsoft.Graph.DeviceManagement.Enrolment"
Install-ModuleIfNotInstalled "Microsoft.Graph.DeviceManagement.Functions"
Install-ModuleIfNotInstalled "Microsoft.Graph.Devices.CloudPrint"
Install-ModuleIfNotInstalled "Microsoft.Graph.Devices.CorporateManagement"
Install-ModuleIfNotInstalled "Microsoft.Graph.DirectoryObjects"
Install-ModuleIfNotInstalled "Microsoft.Graph.Education"
Install-ModuleIfNotInstalled "Microsoft.Graph.Files"
Install-ModuleIfNotInstalled "Microsoft.Graph.Financials"
Install-ModuleIfNotInstalled "Microsoft.Graph.Groups"
Install-ModuleIfNotInstalled "Microsoft.Graph.Identity.DirectoryManagement"
Install-ModuleIfNotInstalled "Microsoft.Graph.Identity.Governance"
Install-ModuleIfNotInstalled "Microsoft.Graph.Identity.SignIns"
Install-ModuleIfNotInstalled "Microsoft.Graph.Intune"
Install-ModuleIfNotInstalled "Microsoft.Graph.Mail"
Install-ModuleIfNotInstalled "Microsoft.Graph.Notes"
Install-ModuleIfNotInstalled "Microsoft.Graph.People"
Install-ModuleIfNotInstalled "Microsoft.Graph.PersonalContacts"
Install-ModuleIfNotInstalled "Microsoft.Graph.Planner"
Install-ModuleIfNotInstalled "Microsoft.Graph.Reports"
Install-ModuleIfNotInstalled "Microsoft.Graph.SchemaExtensions"
Install-ModuleIfNotInstalled "Microsoft.Graph.Search"
Install-ModuleIfNotInstalled "Microsoft.Graph.Security"
Install-ModuleIfNotInstalled "Microsoft.Graph.Sites"
Install-ModuleIfNotInstalled "Microsoft.Graph.Teams"
Install-ModuleIfNotInstalled "Microsoft.Graph.Users"
Install-ModuleIfNotInstalled "Microsoft.Graph.Users.Actions"
Install-ModuleIfNotInstalled "Microsoft.Graph.Users.Functions"
Install-ModuleIfNotInstalled "Microsoft.Graph.WindowsUpdates"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Applications"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Bookings"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Calendar"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.ChangeNotifications"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.CloudCommunications"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Compliance"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.CrossDeviceExperiences"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.DeviceManagement"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.DeviceManagement.Actions"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.DeviceManagement.Administration"
#Install-ModuleIfNotInstalled "Microsoft.Graph.DeviceManagement.Enrolment"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.DeviceManagement.Functions"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Devices.CloudPrint"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Devices.CorporateManagement"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.DirectoryObjects"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Education"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Files"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Financials"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Groups"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.DirectoryManagement"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.Governance"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.SignIns"
#Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Intune"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Mail"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Notes"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.People"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.PersonalContacts"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Planner"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Reports"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.SchemaExtensions"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Search"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Security"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Sites"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Teams"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users.Actions"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users.Functions"
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.WindowsUpdates"
Install-ModuleIfNotInstalled "Microsoft.Online.SharePoint.PowerShell"
Install-ModuleIfNotInstalled "Microsoft.PowerApps.PowerShell"
Install-ModuleIfNotInstalled "Microsoft.PowerApps.Administration.PowerShell"
Install-ModuleIfNotInstalled "Microsoft.Xrm.Tooling.CrmConnector.PowerShell"
Install-ModuleIfNotInstalled "MicrosoftTeams"
Install-ModuleIfNotInstalled "MSAL.PS"
Install-ModuleIfNotInstalled "MSIdentityTools"
Install-ModuleIfNotInstalled "MSOnline"
Install-ModuleIfNotInstalled "MSStore"
Install-ModuleIfNotInstalled "PnP.PowerShell"
Install-ModuleIfNotInstalled "Pscx"
Install-ModuleIfNotInstalled "PSWindowsUpdate"
Install-ModuleIfNotInstalled "WindowsAutoPilotIntune"

Remove-OneDriveItemRecursive "$($AlyaTools)\Packages\Microsoft.SharePointOnline.CSOM"
Remove-OneDriveItemRecursive "$($AlyaTools)\Packages\log4net"
Install-PackageIfNotInstalled "Microsoft.SharePointOnline.CSOM"
Install-PackageIfNotInstalled "log4net"
Install-ScriptIfNotInstalled "Get-WindowsAutoPilotInfo"
Uninstall-ModuleIfInstalled "AzureAd"

. $PSScriptRoot\07_CleanOldModules.ps1

#Stopping Transscript
Stop-Transcript
