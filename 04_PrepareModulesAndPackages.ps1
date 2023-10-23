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
    16.10.2023 Konrad Brunner       Not loading modules on update
#>

[CmdletBinding()]
Param(
)

#Reading configuration
. $PSScriptRoot\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\04_PrepareModulesAndPackages-$($AlyaTimeString).log" | Out-Null

#Main
Install-ModuleIfNotInstalled "PackageManagement" -doNotLoadModules $true
Install-ModuleIfNotInstalled "PowershellGet" -doNotLoadModules $true

Install-ModuleIfNotInstalled "AIPService" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Accounts" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.ADDomainServices" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Advisor" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Aks" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.AnalysisServices" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.ApiManagement" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.AppConfiguration" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.ApplicationInsights" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Attestation" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Automation" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Batch" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Billing" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Cdn" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.CloudService" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.CognitiveServices" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Compute" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.ConfidentialLedger" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.ContainerInstance" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.ContainerRegistry" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.CosmosDB" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.DataBoxEdge" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Databricks" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.DataFactory" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.DataLakeAnalytics" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.DataLakeStore" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.DataProtection" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.DataShare" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.DeploymentManager" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.DesktopVirtualization" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.DevTestLabs" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Dns" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.EventGrid" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.EventHub" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.FrontDoor" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Functions" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.HDInsight" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.HealthcareApis" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.IotHub" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.KeyVault" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Kusto" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.LogicApp" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.MachineLearning" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Maintenance" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.ManagedServiceIdentity" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.ManagedServices" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.MarketplaceOrdering" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Media" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Migrate" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Monitor" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.MySql" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Network" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.NotificationHubs" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.OperationalInsights" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.PolicyInsights" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.PostgreSql" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.PowerBIEmbedded" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.PrivateDns" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.RecoveryServices" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.RedisCache" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.RedisEnterpriseCache" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Relay" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.ResourceMover" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Resources" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Security" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.SecurityInsights" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.ServiceBus" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.ServiceFabric" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.SignalR" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Sql" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.SqlVirtualMachine" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.StackHCI" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Storage" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.StorageSync" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.StreamAnalytics" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Support" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Synapse" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.TrafficManager" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az.Websites" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Az" -doNotLoadModules $true
Install-ModuleIfNotInstalled "AzTable" -doNotLoadModules $true
Install-ModuleIfNotInstalled "AzureADPreview" -doNotLoadModules $true
Install-ModuleIfNotInstalled "DataGateway.Profile" -doNotLoadModules $true
Install-ModuleIfNotInstalled "DataGateway" -doNotLoadModules $true
Install-ModuleIfNotInstalled "ExchangeOnlineManagement" -doNotLoadModules $true
Install-ModuleIfNotInstalled "ImportExcel" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Applications" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Authentication" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Bookings" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Calendar" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.ChangeNotifications" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.CloudCommunications" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Compliance" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.CrossDeviceExperiences" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.DeviceManagement" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.DeviceManagement.Actions" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.DeviceManagement.Administration" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.DeviceManagement.Enrolment" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.DeviceManagement.Functions" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Devices.CloudPrint" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Devices.CorporateManagement" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.DirectoryObjects" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Education" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Files" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Financials" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Groups" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Identity.DirectoryManagement" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Identity.Governance" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Identity.SignIns" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Intune" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Mail" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Notes" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.People" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.PersonalContacts" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Planner" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Reports" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.SchemaExtensions" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Search" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Security" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Sites" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Teams" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Users" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Users.Actions" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Users.Functions" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.WindowsUpdates" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Applications" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Bookings" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Calendar" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.ChangeNotifications" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.CloudCommunications" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Compliance" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.CrossDeviceExperiences" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.DeviceManagement" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.DeviceManagement.Actions" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.DeviceManagement.Administration" -doNotLoadModules $true
#Install-ModuleIfNotInstalled "Microsoft.Graph.DeviceManagement.Enrolment" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.DeviceManagement.Functions" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Devices.CloudPrint" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Devices.CorporateManagement" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.DirectoryObjects" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Education" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Files" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Financials" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Groups" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.DirectoryManagement" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.Governance" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Identity.SignIns" -doNotLoadModules $true
#Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Intune" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Mail" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Notes" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.People" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.PersonalContacts" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Planner" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Reports" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.SchemaExtensions" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Search" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Security" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Sites" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Teams" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users.Actions" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.Users.Functions" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta.WindowsUpdates" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Graph.Beta" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Online.SharePoint.PowerShell" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.PowerApps.PowerShell" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.PowerApps.Administration.PowerShell" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Microsoft.Xrm.Tooling.CrmConnector.PowerShell" -doNotLoadModules $true
Install-ModuleIfNotInstalled "MicrosoftTeams" -doNotLoadModules $true
Install-ModuleIfNotInstalled "MSAL.PS" -doNotLoadModules $true
Install-ModuleIfNotInstalled "MSIdentityTools" -doNotLoadModules $true
Install-ModuleIfNotInstalled "MSOnline" -doNotLoadModules $true
Install-ModuleIfNotInstalled "MSStore" -doNotLoadModules $true
Install-ModuleIfNotInstalled "PnP.PowerShell" -doNotLoadModules $true
Install-ModuleIfNotInstalled "Pscx" -doNotLoadModules $true
Install-ModuleIfNotInstalled "PSWindowsUpdate" -doNotLoadModules $true
Install-ModuleIfNotInstalled "WindowsAutoPilotIntune" -doNotLoadModules $true

Remove-OneDriveItemRecursive "$($AlyaTools)\Packages\Microsoft.SharePointOnline.CSOM"
Remove-OneDriveItemRecursive "$($AlyaTools)\Packages\log4net"
Install-PackageIfNotInstalled "Microsoft.SharePointOnline.CSOM"
Install-PackageIfNotInstalled "log4net"
Install-ScriptIfNotInstalled "Get-WindowsAutoPilotInfo"
Uninstall-ModuleIfInstalled "AzureAd"

. $PSScriptRoot\07_CleanOldModules.ps1

#Stopping Transscript
Stop-Transcript
