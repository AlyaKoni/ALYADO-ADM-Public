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
    01.02.2021 Konrad Brunner       Initial Creation

    Original Source from:
    https://github.com/cisagov/Sparrow

#>

[CmdletBinding()]
Param(
    [Parameter()]
    [string] $AzureEnvironment = "AzureCloud",
    [Parameter()]
    [string] $ExchangeEnvironment = "O365Default",
    [Parameter()]
    [datetime] $StartDate = [DateTime]::UtcNow.AddDays(-364),
    [Parameter()]
    [datetime] $EndDate = [DateTime]::UtcNow,
    [Parameter()]
    [string] $ExportDir = $null, #Defaults to $AlyaData\security
    [Parameter()]
    [switch] $NoO365 = $false
)

#Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

#Starting Transscript
Start-Transcript -Path "$($AlyaLogs)\scripts\security\Sparrow-$($AlyaTimeString).log" | Out-Null

# Constants
if (-Not $ExportDir)
{
    $ExportDir = "$AlyaData\security"
}
if (-Not (Test-Path $ExportDir))
{
    New-Item -Path $ExportDir -ItemType Directory -Force
}

# Checking modules
Write-Host "Checking modules" -ForegroundColor $CommandInfo
Install-ModuleIfNotInstalled "Az.Accounts"
Install-ModuleIfNotInstalled "Az.Resources"
Install-ModuleIfNotInstalled "AzureADPreview"
Install-ModuleIfNotInstalled "ExchangeOnlineManagement"
Install-ModuleIfNotInstalled "MSOnline"

# Logins
LoginTo-Az -SubscriptionName $AlyaSubscriptionName

Function New-ExcelFromCsv() {

    [cmdletbinding()]Param(
        [Parameter(Mandatory=$true)]
        [string] $ExportDir
        )

    Try {
        $Excel = New-Object -ComObject Excel.Application
    }
    Catch { 
        Write-Host 'Warning; Excel not found - skipping combined file.' 
        Return
    }

    #Open each file and move it in a single workbook
    $Excel.DisplayAlerts = $False
    $Workbook = $Excel.Workbooks.Add()
    $Csvs = Get-ChildItem -Path "${ExportDir}\*.csv" -Force
    $ToDeletes = $Workbook.Sheets | Select-Object -ExpandProperty Name
    ForEach ($Csv in $Csvs) {
        $TempWorkbook = $Excel.Workbooks.Open($Csv.FullName)
        $TempWorkbook.Sheets[1].Copy($Workbook.Sheets[1], [Type]::Missing) | Out-Null
        $Workbook.Sheets[1].UsedRange.Columns.AutoFit() | Out-Null
        $Workbook.Sheets[1].Name = $Csv.BaseName -replace '_Operations_.*',''
    }

    #Save out the new file
    ForEach ($ToDelete in $ToDeletes) { 
        $Workbook.Activate()
        $Workbook.Sheets[$ToDelete].Activate()
        $Workbook.Sheets[$ToDelete].Delete()
    }
    $Workbook.SaveAs((Join-Path $ExportDir 'Summary_Export.xlsx'))
    $Excel.Quit()
}

Function Get-UALData {

    [cmdletbinding()]Param(
        [Parameter(Mandatory=$true)]
        [datetime] $StartDate,
        [Parameter(Mandatory=$true)]
        [datetime] $EndDate,
        [Parameter(Mandatory=$true)]
        [string] $AzureEnvironment,
        [Parameter(Mandatory=$true)]
        [string] $ExchangeEnvironment,
        [Parameter(Mandatory=$true)]
        [string] $ExportDir
        )

        
    #Calling on CloudConnect to connect to the tenant's Exchange Online environment via PowerShell
    Connect-ExchangeOnline -ExchangeEnvironmentName $ExchangeEnvironment

    #Connecting to MSOnline
    Connect-MsolService -AzureEnvironment $AzureEnvironment

    $LicenseQuestion = Read-Host 'Do you have an Office 365/Microsoft 365 E5/G5 license? Y/N'
    Switch ($LicenseQuestion){
        Y {$LicenseAnswer = "Yes"}
        N {$LicenseAnswer = "No"}
    }
    $AppIdQuestion = Read-Host 'Would you like to investigate a certain application? Y/N'
    Switch ($AppIdQuestion){
        Y {$AppIdInvestigation = "Yes"}
        N {$AppIdInvestigation = "No"}
    }
    If ($AppIdInvestigation -eq "Yes"){
        $SusAppId = Read-Host "Enter the application's AppID to investigate"
    } Else{
        Write-Host "Skipping AppID investigation"
    }

    #Searches for any modifications to the domain and federation settings on a tenant's domain
    Write-Verbose "Searching for 'Set domain authentication' and 'Set federation settings on domain' operations in the UAL."
    $DomainData = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations "Set domain authentication","Set federation settings on domain" -ResultSize 5000 | Select-Object -ExpandProperty AuditData | Convertfrom-Json
    #You can modify the resultant CSV output by changing the -CsvName parameter
    #By default, it will show up as Domain_Operations_Export.csv
    Export-UALData -ExportDir $ExportDir -UALInput $DomainData -CsvName "Domain_Operations_Export" -WorkloadType "AAD"

    #Searches for any modifications or credential modifications to an application
    Write-Verbose "Searching for 'Update application' and 'Update application ? Certificates and secrets management' in the UAL."
    $AppData = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations "Update application","Update application ? Certificates and secrets management" -ResultSize 5000 | Select-Object -ExpandProperty AuditData | Convertfrom-Json
    #You can modify the resultant CSV output by changing the -CsvName parameter
    #By default, it will show up as AppUpdate_Operations_Export.csv
    Export-UALData -ExportDir $ExportDir -UALInput $AppData -CsvName "AppUpdate_Operations_Export" -WorkloadType "AAD"

    #Searches for any modifications or credential modifications to a service principal
    Write-Verbose "Searching for 'Update service principal' and 'Add service principal credentials' in the UAL."
    $SpData = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations "Update service principal","Add service principal credentials" -ResultSize 5000 | Select-Object -ExpandProperty AuditData | Convertfrom-Json
    #You can modify the resultant CSV output by changing the -CsvName parameter
    #By default, it will show up as ServicePrincipal_Operations_Export.csv   
    Export-UALData -ExportDir $ExportDir -UALInput $SpData -CsvName "ServicePrincipal_Operations_Export" -WorkloadType "AAD"

    #Searches for any app role assignments to service principals, users, and groups
    Write-Verbose "Searching for 'Add app role assignment to service principal', 'Add app role assignment grant to user', and 'Add app role assignment to group' in the UAL."
    $AppRoleData = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations "Add app role assignment" -ResultSize 5000 | Select-Object -ExpandProperty AuditData | Convertfrom-Json
    #You can modify the resultant CSV output by changing the -CsvName parameter
    #By default, it will show up as AppRoleAssignment_Operations_Export.csv      
    Export-UALData -ExportDir $ExportDir -UALInput $AppRoleData -CsvName "AppRoleAssignment_Operations_Export" -WorkloadType "AAD"

    #Searches for any OAuth or application consents
    Write-Verbose "Searching for 'Add OAuth2PermissionGrant' and 'Consent to application' in the UAL."
    $ConsentData = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations "Add OAuth2PermissionGrant","Consent to application" -ResultSize 5000 | Select-Object -ExpandProperty AuditData | Convertfrom-Json
    #You can modify the resultant CSV output by changing the -CsvName parameter
    #By default, it will show up as Consent_Operations_Export.csv       
    Export-UALData -ExportDir $ExportDir -UALInput $ConsentData -CsvName "Consent_Operations_Export" -WorkloadType "AAD"

    #Searches for SAML token usage anomaly (UserAuthenticationValue of 16457) in the Unified Audit
    $federatedDomains = Get-MsolDomain | Where-Object {$_.Authentication -eq "Federated"}
    # Get only root domains so we can get SupportMFA status
    $rootDomains = $federatedDomains | Where-Object {$_.RootDomain -eq $null}
    # Get root domains that don't support MFA, hence Federated MFA is not expected. Note: federated MFA is still possible when SupportsMFA is false, however less likely. Check your STS configuration.
    $rootDomainsSupportMFAFalse = @()
    
    foreach ($rootDomain in $rootDomains)
    {
        $fedProps = Get-MsolDomainFederationSettings -DomainName $rootDomain.Name 
        If ($fedProps.SupportsMfa -ne $True) {
            $rootDomainsSupportMFAFalse += $rootDomain.Name
        }
    }
    # Add all child domains where its root is on the list
    $childDomainsSupportMFAFalse = @()
    $childDomains = $federatedDomains | Where-Object {$_.RootDomain -ne $null}

    foreach ($childDomain in $childDomains)
    {
        if ($childDomain.RootDomain -in $rootDomainsSupportMFAFalse){
            $childDomainsSupportMFAFalse += $childDomain.name
        }
    }

    $domainsToFlag = $rootDomainsSupportMFAFalse + $childDomainsSupportMFAFalse
    If ($null -ne $domainsToFlag)
    {
        Write-Verbose "Searching for 16457 in UserLoggedIn and UserLoginFailed operations in the UAL."
        $SAMLData = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations "UserLoggedIn","UserLoginFailed" -ResultSize 5000 -FreeText "16457" | Select-Object -ExpandProperty AuditData | Convertfrom-Json
        $FilteredSAMLData = $SAMLData | Where-Object {$_.UserId.Split('@')[1] -in $domainsToFlag}
        #You can modify the resultant CSV output by changing the -CsvName parameter
        #By default, it will show up as SAMLToken_Operations_Export.csv      
        Export-UALData -ExportDir $ExportDir -UALInput $FilteredSAMLData -CsvName "SAMLToken_Operations_Export" -WorkloadType "AAD"
    } else {
        Write-Verbose "No federated domains found--16457 check will be skipped and no CSV will be produced."
    }

    #Searches for PowerShell logins into mailboxes
    Write-Verbose "Searching for PowerShell logins into mailboxes in the UAL."
    $PSMailboxData = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -Operations "MailboxLogin" -FreeText "Powershell" | Select-Object -ExpandProperty AuditData | Convertfrom-Json
    #You can modify the resultant CSV output by changing the -CsvName parameter
    #By default, it will show up as PSMailbox_Operations_Export.csv      
    Export-UALData -ExportDir $ExportDir -UALInput $PSMailboxData -CsvName "PSMailbox_Operations_Export" -WorkloadType "EXO2"

    #Searches for well-known AppID for Exchange Online PowerShell
    Write-Verbose "Searching for PowerShell logins using known PS application ids in the UAL."
    $PSLoginData1 = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000  -FreeText "a0c73c16-a7e3-4564-9a95-2bdf47383716" | Select-Object -ExpandProperty AuditData | Convertfrom-Json
    #You can modify the resultant CSV output by changing the -CsvName parameter
    #By default, it will show up as PSLogin_Operations_Export.csv  
    Export-UALData -ExportDir $ExportDir -UALInput $PSLoginData1 -CsvName "PSLogin_Operations_Export" -WorkloadType "AAD"

    #Searches for well-known AppID for PowerShell
    $PSLoginData2 = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000  -FreeText "1b730954-1685-4b74-9bfd-dac224a7b894" | Select-Object -ExpandProperty AuditData | Convertfrom-Json
    #The resultant CSV will be appended with the $PSLoginData* resultant CSV.
    #If you want a separate CSV with a different name, remove the -AppendType parameter (-AppendType "Append")
    #By default, it will show up as part of the PSLogin_Operations_Export.csv  
    Export-UALData -ExportDir $ExportDir -UALInput $PSLoginData2 -CsvName "PSLogin_Operations_Export" -WorkloadType "AAD" -AppendType "Append"

    #Searches for WinRM useragent string in the user logged in and user login failed operations
    $PSLoginData3 = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -ResultSize 5000 -Operations "UserLoggedIn","UserLoginFailed" -FreeText "WinRM" | Select-Object -ExpandProperty AuditData | Convertfrom-Json
    #The resultant CSV will be appended with the $PSLoginData* resultant CSV.
    #If you want a separate CSV with a different name, remove the -AppendType parameter (-AppendType "Append")
    #By default, it will show up as part of the PSLogin_Operations_Export.csv 
    Export-UALData -ExportDir $ExportDir -UALInput $PSLoginData3 -CsvName "PSLogin_Operations_Export" -WorkloadType "AAD" -AppendType "Append"

    If ($AppIdInvestigation -eq "Yes"){
        If ($LicenseAnswer -eq "Yes"){
            #Searches for the AppID to see if it accessed mail items.
            Write-Verbose "Searching for $SusAppId in the MailItemsAccessed operation in the UAL."
            $SusMailItems = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations "MailItemsAccessed" -ResultSize 5000 -FreeText $SusAppId -Verbose | Select-Object -ExpandProperty AuditData | Convertfrom-Json
            #You can modify the resultant CSV output by changing the -CsvName parameter
            #By default, it will show up as MailItems_Operations_Export.csv  
            Export-UALData -ExportDir $ExportDir -UALInput $SusMailItems -CsvName "MailItems_Operations_Export" -WorkloadType "EXO"
        } else {
            Write-Host "MailItemsAccessed query will be skipped as it is not present without an E5/G5 license."
        }

        #Searches for the AppID to see if it accessed SharePoint or OneDrive items
        Write-Verbose "Searching for $SusAppId in the FileAccessed and FileAccessedExtended operations in the UAL."
        $SusFileItems = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -Operations "FileAccessed","FileAccessedExtended" -ResultSize 5000 -FreeText $SusAppId -Verbose | Select-Object -ExpandProperty AuditData | Convertfrom-Json
        #You can modify the resultant CSV output by changing the -CsvName parameter
        #By default, it will show up as FileItems_Operations_Export.csv  
        Export-UALData -ExportDir $ExportDir -UALInput $SusFileItems -CsvName "FileItems_Operations_Export" -WorkloadType "SharePoint"
    }
}

Function Get-AzureDomains {

    [cmdletbinding()]Param(
        [Parameter(Mandatory=$true)]
        [string] $AzureEnvironment,
        [Parameter(Mandatory=$true)]
        [string] $ExportDir
        )

    #Connect to AzureAD
    Connect-AzureAD -AzureEnvironmentName $AzureEnvironment

    $DomainData = Get-AzureADDomain
    $DomainArr = @()
    
    ForEach ($Domain in $DomainData){
        $DomainProps = [ordered]@{
            AuthenticationType = $Domain.AuthenticationType
            AvailabilityStatus = $Domain.AvailabilityStatus
            ForceDeleteState = $Domain.ForceDeleteState
            IsAdminManaged = $Domain.IsAdminManaged
            IsDefault = $Domain.IsDefault
            IsInitial = $Domain.IsInitial
            IsRoot = $Domain.IsRoot
            IsVerified = $Domain.IsVerified
            Name = $Domain.Name
            State = $Domain.State
            SupportedServices = ($Domain.SupportedServices -join ';')
        }
        $DomainObj = New-Object -TypeName PSObject -Property $DomainProps
        $DomainArr += $DomainObj
    }
    $DomainArr | Export-Csv $ExportDir\Domain_List.csv -NoTypeInformation
}

Function Get-AzureSPAppRoles {

    [cmdletbinding()]Param(
        [Parameter(Mandatory=$true)]
        [string] $AzureEnvironment,
        [Parameter(Mandatory=$true)]
        [string] $ExportDir
        )

    #Connect to your tenant's AzureAD environment
    Connect-AzureAD -AzureEnvironmentName $AzureEnvironment

    #Retrieve all service principals that are applications
    $SPArr = Get-AzureADServicePrincipal -All $true | Where-Object {$_.ServicePrincipalType -eq "Application"}

    #Retrieve all service principals that have a display name of Microsoft Graph
    $GraphSP = Get-AzureADServicePrincipal -All $true | Where-Object {$_.DisplayName -eq "Microsoft Graph"}

    $GraphAppRoles = $GraphSP.AppRoles | Select-Object -Property AllowedMemberTypes, Id, Value

    $AppRolesArr = @()
    Foreach ($SP in $SPArr) {
        $GraphResource = Get-AzureADServiceAppRoleAssignedTo -ObjectId $SP.ObjectId | Where-Object {$_.ResourceDisplayName -eq "Microsoft Graph"}
        ForEach ($GraphObj in $GraphResource){
            For ($i=0; $i -lt $GraphAppRoles.Count; $i++){
                if ($GraphAppRoles[$i].Id -eq $GraphObj.Id) {
                    $ListProps = [ordered]@{
                        ApplicationDisplayName = $GraphObj.PrincipalDisplayName
                        ClientID = $GraphObj.PrincipalId
                        Value = $GraphAppRoles[$i].Value
                    }
                }
            }
            $ListObj = New-Object -TypeName PSObject -Property $ListProps
            $AppRolesArr += $ListObj 
            }
        }
    #If you want to change the default export directory, please change the $ExportDir value.
    #Otherwise, the default export is the user's home directory, Desktop folder, and ExportDir folder.
    #You can change the name of the CSV as well, the default name is "ApplicationGraphPermissions"
    $AppRolesArr | Export-Csv $ExportDir\ApplicationGraphPermissions.csv -NoTypeInformation
}

Function Export-UALData {
    Param(
        [Parameter(ValueFromPipeline=$True)]
        [Object[]]$UALInput,
        [Parameter(Mandatory=$true)]
        [String]$CsvName,
        [Parameter(Mandatory=$true)]
        [String]$WorkloadType,
        [Parameter()]
        [String]$AppendType,
        [Parameter(Mandatory=$true)]
        [string] $ExportDir
        )

        If ($UALInput.Count -eq 5000)
        {
            Write-Host 'Warning: Result set may have been truncated; narrow start/end date.'
        }

        $DataArr = @()
        If ($WorkloadType -eq "AAD") {
            ForEach ($Data in $UALInput){
                $DataProps = [ordered]@{
                    CreationTime = $Data.CreationTime
                    Id = $Data.Id
                    Operation = $Data.Operation
                    Organization = $Data.Organization
                    RecordType = $Data.RecordType
                    ResultStatus = $Data.ResultStatus
                    LogonError = $Data.LogonError
                    UserKey = $Data.UserKey
                    UserType = $Data.UserType
                    Version = $Data.Version
                    Workload = $Data.Workload
                    ClientIP = $Data.ClientIP
                    ObjectId = $Data.ObjectId
                    UserId = $Data.UserId
                    AzureActiveDirectoryEventType = $Data.AzureActiveDirectoryEventType
                    ExtendedProperties = ($Data.ExtendedProperties | ConvertTo-Json -Compress | Out-String).Trim()
                    ModifiedProperties = (($Data.ModifiedProperties | ConvertTo-Json -Compress) -replace "\\r\\n" | Out-String).Trim()
                    Actor = ($Data.Actor | ConvertTo-Json -Compress | Out-String).Trim()
                    ActorContextId = $Data.ActorContextId
                    ActorIpAddress = $Data.ActorIpAddress
                    InterSystemsId = $Data.InterSystemsId
                    IntraSystemId = $Data.IntraSystemId
                    SupportTicketId = $Data.SupportTicketId
                    Target = ($Data.Target | ConvertTo-Json -Compress | Out-String).Trim()
                    TargetContextId = $Data.TargetContextId
                }
                $DataObj = New-Object -TypeName PSObject -Property $DataProps
                $DataArr += $DataObj           
            }
        } elseif ($WorkloadType -eq "EXO"){
            ForEach ($Data in $UALInput){
                $DataProps = [ordered]@{
                    CreationTime = $Data.CreationTime
                    Id = $Data.Id
                    Operation = $Data.Operation
                    OrganizationId = $Data.OrganizationId
                    RecordType = $Data.RecordType
                    ResultStatus = $Data.ResultStatus
                    UserKey = $Data.UserKey
                    UserType = $Data.UserType
                    Version = $Data.Version
                    Workload = $Data.Workload
                    UserId = $Data.UserId
                    AppId = $Data.AppId
                    ClientAppId = $Data.ClientAppId
                    ClientIPAddress = $Data.ClientIPAddress
                    ClientInfoString = $Data.ClientInfoString
                    ExternalAccess = $Data.ExternalAccess
                    InternalLogonType = $Data.InternalLogonType
                    LogonType = $Data.LogonType
                    LogonUserSid = $Data.LogonUserSid
                    MailboxGuid = $Data.MailboxGuid
                    MailboxOwnerSid = $Data.MailboxOwnerSid
                    MailboxOwnerUPN = $Data.MailboxOwnerUPN
                    OperationProperties = ($Data.OperationProperties | ConvertTo-Json -Compress | Out-String).Trim()
                    OrganizationName = $Data.OrganizationName
                    OriginatingServer = $Data.OriginatingServer
                    Folders = ((($Data.Folders | ConvertTo-Json -Compress).replace("\u003c","")).replace("\u003e","")  | Out-String).Trim()
                    OperationCount = $Data.OperationCount
                }
                $DataObj = New-Object -TypeName PSObject -Property $DataProps
                $DataArr += $DataObj           
            }
        } elseif ($WorkloadType -eq "EXO2"){
            ForEach ($Data in $UALInput){
                $DataProps = [ordered]@{
                    CreationTime = $Data.CreationTime
                    Id = $Data.Id
                    Operation = $Data.Operation
                    OrganizationId = $Data.OrganizationId
                    RecordType = $Data.RecordType
                    ResultStatus = $Data.ResultStatus
                    UserKey = $Data.UserKey
                    UserType = $Data.UserType
                    Version = $Data.Version
                    Workload = $Data.Workload
                    ClientIP = $Data.ClientIP
                    UserId = $Data.UserId
                    ClientIPAddress = $Data.ClientIPAddress
                    ClientInfoString = $Data.ClientInfoString
                    ExternalAccess = $Data.ExternalAccess
                    InternalLogonType = $Data.InternalLogonType
                    LogonType = $Data.LogonType
                    LogonUserSid = $Data.LogonUserSid
                    MailboxGuid = $Data.MailboxGuid
                    MailboxOwnerSid = $Data.MailboxOwnerSid
                    MailboxOwnerUPN = $Data.MailboxOwnerUPN
                    OrganizationName = $Data.OrganizationName
                    OriginatingServer = $Data.OriginatingServer
                }
                $DataObj = New-Object -TypeName PSObject -Property $DataProps
                $DataArr += $DataObj           
            }
        } elseif ($WorkloadType -eq "SharePoint"){
            ForEach ($Data in $UALInput){
                $DataProps = [ordered]@{
                    CreationTime = $Data.CreationTime
                    Id = $Data.Id
                    Operation = $Data.Operation
                    OrganizationId = $Data.OrganizationId
                    RecordType = $Data.RecordType
                    UserKey = $Data.UserKey
                    UserType = $Data.UserType
                    Version = $Data.Version
                    Workload = $Data.Workload
                    ClientIP = $Data.ClientIP
                    ObjectId = $Data.ObjectId
                    UserId = $Data.UserId
                    ApplicationId = $Data.ApplicationId
                    CorrelationId = $Data.CorrelationId
                    EventSource = $Data.EventSource
                    ItemType = $Data.ItemType
                    ListId = $Data.ListId
                    ListItemUniqueId = $Data.ListItemUniqueId
                    Site = $Data.Site
                    UserAgent = $Data.UserAgent
                    WebId = $Data.WebId
                    HighPriorityMediaProcessing = $Data.HighPriorityMediaProcessing
                    SourceFileExtension = $Data.SourceFileExtension
                    SiteUrl = $Data.SiteUrl
                    SourceFileName = $Data.SourceFileName
                    SourceRelativeUrl = $Data.SourceRelativeUrl
                }
                $DataObj = New-Object -TypeName PSObject -Property $DataProps
                $DataArr += $DataObj
            }
        }
        If ($AppendType -eq "Append"){
            $DataArr | Export-csv $ExportDir\$CsvName.csv -NoTypeInformation -Append
        } Else {
            $DataArr | Export-csv $ExportDir\$CsvName.csv -NoTypeInformation
        }
        
        Remove-Variable UALInput -ErrorAction SilentlyContinue
        Remove-Variable Data -ErrorAction SilentlyContinue
        Remove-Variable DataObj -ErrorAction SilentlyContinue
        Remove-Variable DataProps -ErrorAction SilentlyContinue
        Remove-Variable DataArr -ErrorAction SilentlyContinue
}

# Main
If ($($ExchangeEnvironment -ne "None") -and $($NoO365 -eq $false)) {
    Get-UALData -ExportDir $ExportDir -StartDate $StartDate -EndDate $EndDate -ExchangeEnvironment $ExchangeEnvironment -AzureEnvironment $AzureEnvironment -Verbose
} 
Get-AzureDomains -AzureEnvironment $AzureEnvironment -ExportDir $ExportDir -Verbose
Get-AzureSPAppRoles -AzureEnvironment $AzureEnvironment -ExportDir $ExportDir -Verbose
New-ExcelFromCsv -ExportDir $ExportDir
Write-Host "Exported excel $((Join-Path $ExportDir 'Summary_Export.xlsx'))" -ForegroundColor $CommandInfo

#Stopping Transscript
Stop-Transcript

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCYmK7/1hZRY1eA
# E1wjy91TKdHxMaR5zZAXV9bGv+/Y9KCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIP4KTLg+rkOZq8pt
# ZebiOmfFKMLONa4F1kBmv61w34PpMA0GCSqGSIb3DQEBAQUABIICAAGNsOTj4xi9
# DbKAxTKgUqmgx80ByO531iMhCYsAJTaQDPSEqfvyC5y3tFy9qqLtBVOUOabXXUb6
# yToNikW/tNHyUTD8kOedG3VXg78j7/9AIb/h8NXBPgBVEhvqSgHEKZ5D9X10HXo6
# y58pugsqt9jr0Es7VfzZLZn5QqvVhAZ+6KzP2V/BqjXILojGt32uqN3AGqOHjb4o
# UQ035cz88SfLx5sJ6fi0KpbdEbcbOyXNv+fA8arac1ZBOMMaRE/L2YAkF+9sK9N5
# uRzDrXQPGSbooqDPmpwbnoy0PSP8opn9syCbf8i0AqoZiuaWxDCC5PsJQpGNKfRh
# Ish5fcXObZ/55Jx2XRHfe/ZzTzltRnMIILhw9bImJ9NLWz7r+n2mDzaUoBVgl2Ml
# uBkwQKm8WEL0dggBQv6lP2C2GRLJVU7NsuMLmUsnKm5fXOC1YCv354ozP+FpuTwN
# Gd58sju+vw9wi+ttPKQesUjHyMnJ6b/woQH03ECkgMJb5kaevzsVRN1bTlxsGDs4
# m4n0kHQ/Zqqk+CYsFH2+fTJ8eLn9JDlG7z1VAwF8RfHwwL8CULDdM8lUx2O5FqlI
# 5N40p5IFbyzNHxJ0jnqcITSz+GK6dsX4tW+h0Qh/kTcLdGAQRuXOjP8DTwZQxBug
# Gst+hk51B0PjJJNDK+3TDHmIlALyz7CdoYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCBEI3K17pU5zBMFJDhaUyKJuewcocQ0U263os9UhKDSxQIUd7y80RfLWEJ0
# x7w9bZREAZo7r+kYDzIwMjYwMTIwMTAwMTMxWjADAgEBoFikVjBUMQswCQYDVQQG
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
# IGRS07UFf8cnsXnPgbR5O0Zs/Y+wEQrMiKJnZ+4VEyc6MIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGACnZqOkbOb2iy
# dkCfxZybKGqObXRJkqMk7NKO7ODKKUuTVyEO0iJEuRRXcro75NXyi0w1+ZjHuS8Y
# Ox7LqRftTt8r1Nm6hPKWGtkJGPZJtTV1rt0qDwaXvd9RwoyByFB0A3Ioeo74I6lY
# RkAZLIUbDuQ/3QCT4f8yt4C2tlXCFfsPD4I+0pH6zGn2SyzfCOcy+6vraEgZsSW7
# BG+a+n+4h4lVrkE6qTJRWLBiTdYLnXgXo7ghUkd+vh8/xpksOmADkdHlaN5RTfTv
# 93NvsvpEFyXyFvcHUquGeru1vM+nmpieziaGvSJCTrXAvFdCcGNWSFtgsL6gOD+b
# xj7gdtbrlUSZy2zXdJxmUAU6S3LPZjUA2RzUgLYBNmNh1EUJa0/7jLHLgj91mVjK
# C8mq5CaZD/F2rr/4bBSlNjEwwrDlDfOHU+nLOfnlYDHcI2/bicT/1M1ZwcOYwHRt
# LFItbjAZO12vCKXqEd/3yd911PPkTBZUigyVC9KVJbZBLrfGKSyf
# SIG # End signature block
