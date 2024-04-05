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
$modules = @(
	"PackageManagement", 
	"PowershellGet", 
	"AIPService", 
	"Az", 
	"Az.Accounts", 
	"Az.ADDomainServices", 
	"Az.Advisor", 
	"Az.Aks", 
	"Az.AnalysisServices", 
	"Az.ApiManagement", 
	"Az.App", 
	"Az.AppConfiguration", 
	"Az.ApplicationInsights", 
	"Az.Attestation", 
	"Az.ArcResourceBridge", 
	"Az.Automanage", 
	"Az.Automation", 
	"Az.Batch", 
	"Az.Billing", 
	"Az.Cdn", 
	"Az.CloudService", 
	"Az.CognitiveServices", 
	"Az.Compute", 
	"Az.ConnectedMachine",
	"Az.ConfidentialLedger", 
	"Az.ContainerInstance", 
	"Az.ContainerRegistry", 
	"Az.CosmosDB", 
	"Az.DataBoxEdge", 
	"Az.Databricks", 
	"Az.DataFactory", 
	"Az.DataLakeAnalytics", 
	"Az.DataLakeStore", 
	"Az.DataProtection", 
	"Az.DataShare", 
	"Az.DeploymentManager", 
	"Az.DesktopVirtualization", 
	"Az.DevCenter", 
	"Az.DevTestLabs", 
	"Az.Dns", 
	"Az.ElasticSan", 
	"Az.EventGrid", 
	"Az.EventHub", 
	"Az.FrontDoor", 
	"Az.Functions", 
	"Az.HDInsight", 
	"Az.HealthcareApis", 
	"Az.IotHub", 
	"Az.KeyVault", 
	"Az.Kusto", 
	"Az.LogicApp", 
	"Az.LoadTesting", 
	"Az.MachineLearning", 
	"Az.MachineLearningServices", 
	"Az.Maintenance", 
	"Az.ManagedServiceIdentity", 
	"Az.ManagedServices", 
	"Az.MarketplaceOrdering", 
	"Az.Media", 
	"Az.Migrate", 
	"Az.Monitor", 
	"Az.MonitoringSolutions", 
	"Az.MySql", 
	"Az.Network", 
	"Az.NetworkCloud", 
	"Az.Nginx", 
	"Az.NotificationHubs", 
	"Az.OperationalInsights", 
	"Az.PolicyInsights", 
	"Az.PostgreSql", 
	"Az.PowerBIEmbedded", 
	"Az.PrivateDns", 
	"Az.RecoveryServices", 
	"Az.RedisCache", 
	"Az.RedisEnterpriseCache", 
	"Az.Relay", 
	"Az.ResourceMover", 
	"Az.Resources", 
	"Az.Security", 
	"Az.SecurityInsights", 
	"Az.ServiceBus", 
	"Az.ServiceFabric", 
	"Az.SignalR", 
	"Az.Sql", 
	"Az.SqlVirtualMachine", 
	"Az.StackHCI", 
	"Az.StackHCIVM", 
	"Az.Storage", 
	"Az.StorageMover", 
	"Az.StorageSync", 
	"Az.StreamAnalytics", 
	"Az.Support", 
	"Az.Synapse", 
	"Az.TrafficManager", 
	"Az.Websites", 
	"AzTable", 
	"DataGateway.Profile", 
	"DataGateway", 
	"ExchangeOnlineManagement", 
	"ImportExcel", 
	"Microsoft.Graph", 
	"Microsoft.Graph.Authentication", 
	"Microsoft.Graph.Applications", 
	"Microsoft.Graph.Authentication", 
	"Microsoft.Graph.Bookings", 
	"Microsoft.Graph.Calendar", 
	"Microsoft.Graph.ChangeNotifications", 
	"Microsoft.Graph.CloudCommunications", 
	"Microsoft.Graph.Compliance", 
	"Microsoft.Graph.CrossDeviceExperiences", 
	"Microsoft.Graph.DeviceManagement", 
	"Microsoft.Graph.DeviceManagement.Actions", 
	"Microsoft.Graph.DeviceManagement.Administration", 
	"Microsoft.Graph.DeviceManagement.Enrollment", 
	"Microsoft.Graph.DeviceManagement.Functions", 
	"Microsoft.Graph.Devices.CloudPrint", 
	"Microsoft.Graph.Devices.CorporateManagement", 
	"Microsoft.Graph.Devices.ServiceAnnouncement", 
	"Microsoft.Graph.DirectoryObjects", 
	"Microsoft.Graph.Education", 
	"Microsoft.Graph.Files", 
	"Microsoft.Graph.Financials", 
	"Microsoft.Graph.Groups", 
	"Microsoft.Graph.Identity.DirectoryManagement", 
	"Microsoft.Graph.Identity.Governance", 
	"Microsoft.Graph.Identity.Partner", 
	"Microsoft.Graph.Identity.SignIns", 
	"Microsoft.Graph.Intune", 
	"Microsoft.Graph.Mail", 
	"Microsoft.Graph.Notes", 
	"Microsoft.Graph.People", 
	"Microsoft.Graph.PersonalContacts", 
	"Microsoft.Graph.Planner", 
	"Microsoft.Graph.Reports", 
	"Microsoft.Graph.SchemaExtensions", 
	"Microsoft.Graph.Search", 
	"Microsoft.Graph.Security", 
	"Microsoft.Graph.Sites", 
	"Microsoft.Graph.Teams", 
	"Microsoft.Graph.Users", 
	"Microsoft.Graph.Users.Actions", 
	"Microsoft.Graph.Users.Functions", 
	"Microsoft.Graph.WindowsUpdates", 
	"Microsoft.Graph.Beta", 
	"Microsoft.Graph.Beta.Applications", 
	"Microsoft.Graph.Beta.Bookings", 
	"Microsoft.Graph.Beta.Calendar", 
	"Microsoft.Graph.Beta.ChangeNotifications", 
	"Microsoft.Graph.Beta.CloudCommunications", 
	"Microsoft.Graph.Beta.Compliance", 
	"Microsoft.Graph.Beta.CrossDeviceExperiences", 
	"Microsoft.Graph.Beta.DeviceManagement", 
	"Microsoft.Graph.Beta.DeviceManagement.Actions", 
	"Microsoft.Graph.Beta.DeviceManagement.Administration", 
	"Microsoft.Graph.Beta.DeviceManagement.Enrollment", 
	"Microsoft.Graph.Beta.DeviceManagement.Functions", 
	"Microsoft.Graph.Beta.Devices.CloudPrint", 
	"Microsoft.Graph.Beta.Devices.CorporateManagement", 
	"Microsoft.Graph.Beta.Devices.ServiceAnnouncement", 
	"Microsoft.Graph.Beta.DirectoryObjects", 
	"Microsoft.Graph.Beta.Education", 
	"Microsoft.Graph.Beta.Files", 
	"Microsoft.Graph.Beta.Financials", 
	"Microsoft.Graph.Beta.Groups", 
	"Microsoft.Graph.Beta.Identity.DirectoryManagement", 
	"Microsoft.Graph.Beta.Identity.Governance", 
	"Microsoft.Graph.Beta.Identity.Partner", 
	"Microsoft.Graph.Beta.Identity.SignIns", 
	#"Microsoft.Graph.Beta.Intune", 
	"Microsoft.Graph.Beta.ManagedTenants", 
	"Microsoft.Graph.Beta.Mail", 
	"Microsoft.Graph.Beta.Notes", 
	"Microsoft.Graph.Beta.People", 
	"Microsoft.Graph.Beta.PersonalContacts", 
	"Microsoft.Graph.Beta.Planner", 
	"Microsoft.Graph.Beta.Reports", 
	"Microsoft.Graph.Beta.SchemaExtensions", 
	"Microsoft.Graph.Beta.Search", 
	"Microsoft.Graph.Beta.Security", 
	"Microsoft.Graph.Beta.Sites", 
	"Microsoft.Graph.Beta.Teams", 
	"Microsoft.Graph.Beta.Users", 
	"Microsoft.Graph.Beta.Users.Actions", 
	"Microsoft.Graph.Beta.Users.Functions", 
	"Microsoft.Graph.Beta.WindowsUpdates", 
	"Microsoft.Online.SharePoint.PowerShell", 
	"Microsoft.PowerApps.PowerShell", 
	"Microsoft.PowerApps.Administration.PowerShell", 
	"Microsoft.Xrm.Tooling.CrmConnector.PowerShell", 
	"MicrosoftTeams", 
	"MSAL.PS", 
	"MSIdentityTools", 
	"MSOnline", 
	"MSStore", 
	"PnP.PowerShell", 
	"Pscx", 
	"PSWindowsUpdate", 
	"WindowsAutoPilotIntune"
)
foreach($module in $modules)
{
    Install-ModuleIfNotInstalled $module -doNotLoadModules $true
}

Remove-OneDriveItemRecursive "$($AlyaTools)\Packages\Microsoft.SharePointOnline.CSOM"
Remove-OneDriveItemRecursive "$($AlyaTools)\Packages\log4net"
Install-PackageIfNotInstalled "Microsoft.SharePointOnline.CSOM"
Install-PackageIfNotInstalled "log4net"
Install-ScriptIfNotInstalled "Get-WindowsAutoPilotInfo"
Uninstall-ModuleIfInstalled "AzureAd"
Uninstall-ModuleIfInstalled "AzureADPreview"

. $PSScriptRoot\07_CleanOldModules.ps1

$modulesD = Get-ChildItem -Path $AlyaModulePath
foreach($module in $modulesD)
{
    if ($modules -notcontains $module.Name)
    {
        Write-Warning "New module found: $($module.Name)"
    }
}

#Stopping Transscript
Stop-Transcript
