# Constants
$lastDcFqdn = "server.domain.local"
$addDnsServer = @()
$titleColor = "Cyan"

# Defining Members
Write-Host "Defining Members" -ForegroundColor $titleColor
$thisDcName = ($env:COMPUTERNAME).ToLower()
$thisDcFqdn = ($env:COMPUTERNAME+"."+$env:USERDNSDOMAIN).ToLower()
$userDomain = ($env:USERDNSDOMAIN).ToLower()

# Getting Credentials
Write-Host "Getting Credentials" -ForegroundColor $titleColor
$locPassword = Read-Host -Prompt "Please specify the local admin password to be set for the local administrator:" -AsSecureString
$orgCred = Get-Credential -Message "Please specify enterprise admin credentials for $userDomain"
$domCred = Get-Credential -Message "Please specify domain admin credentials for $userDomain or cancel to use enterprise admin credentials"
if ([string]::IsNullOrEmpty($domCred.UserName))
{
    $domCred = $orgCred
}
$dnsCred = Get-Credential -Message "Please specify dns admin credentials for $userDomain or cancel to use enterprise admin credentials"
if ([string]::IsNullOrEmpty($dnsCred.UserName))
{
    $dnsCred = $orgCred
}

# Checking if demote already happended
Write-Host "Checking if demote already happended" -ForegroundColor $titleColor
$dcs = $null
try
{
    Get-ADDomainController -Filter * | Select-Object Name, Domain, Forest, OperationMasterRoles
    $dcs = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue | Select-Object Name
} catch {}
if ($dcs -contains $thisDcName -or $dcs -contains $thisDcFqdn)
{
    # Checking FSMO roles
    if ($thisDcFqdn -ne $lastDcFqdn)
    {
        Write-Host "Checking FSMO roles" -ForegroundColor $titleColor
        $dom = Get-ADDomain
        $for = Get-ADForest
        if ($dom.InfrastructureMaster.ToLower() -eq $thisDcFqdn -or $dom.InfrastructureMaster.ToLower() -eq $thisDc)
        {
            Write-Warning "This DC is InfrastructureMaster. Moving it to last DC $lastDcFqdn"
            Move-ADDirectoryServerOperationMasterRole -OperationMasterRole InfrastructureMaster -Identity $lastDcFqdn -Credential $domCred -Force -Confirm:$false
        }
        if ($dom.RIDMaster.ToLower() -eq $thisDcFqdn -or $dom.RIDMaster.ToLower() -eq $thisDc)
        {
            Write-Warning "This DC is RIDMaster. Moving it to last DC $lastDcFqdn"
            Move-ADDirectoryServerOperationMasterRole -OperationMasterRole RIDMaster -Identity $lastDcFqdn -Credential $domCred -Force -Confirm:$false
        }
        if ($dom.PDCEmulator.ToLower() -eq $thisDcFqdn -or $dom.PDCEmulator.ToLower() -eq $thisDc)
        {
            Write-Warning "This DC is PDCEmulator. Moving it to last DC $lastDcFqdn"
            Move-ADDirectoryServerOperationMasterRole -OperationMasterRole PDCEmulator -Identity $lastDcFqdn -Credential $domCred -Force -Confirm:$false
        }
        if ($for.SchemaMaster.ToLower() -eq $thisDcFqdn -or $for.SchemaMaster.ToLower() -eq $thisDc)
        {
            Write-Warning "This DC is SchemaMaster. Moving it to last DC $lastDcFqdn"
            Move-ADDirectoryServerOperationMasterRole -OperationMasterRole SchemaMaster -Identity $lastDcFqdn -Credential $orgCred -Force -Confirm:$false
        }
        if ($for.DomainNamingMaster.ToLower() -eq $thisDcFqdn -or $for.DomainNamingMaster.ToLower() -eq $thisDc)
        {
            Write-Warning "This DC is DomainNamingMaster. Moving it to last DC $lastDcFqdn"
            Move-ADDirectoryServerOperationMasterRole -OperationMasterRole DomainNamingMaster -Identity $lastDcFqdn -Credential $orgCred -Force -Confirm:$false
        }

        # Disabling global catalog
        Set-ADObject -Identity (Get-ADDomainController $thisDcFqdn).ntdssettingsobjectdn -Replace @{options='0'}

    }

    # Checking if we are last
    if ($thisDcFqdn -eq $lastDcFqdn)
    {
        Write-Host "We are on last DC" -ForegroundColor $titleColor
        if ((Get-ADDomainController -Filter * | Select-Object Name).Count -gt 1)
        {
            Write-Warning "Looks like there are still other domain controllers present. Please only continue if you are sure this is the last!"
            pause
        }
    }

    # Configuring dns client
    if ($addDnsServer.Count -gt 0)
    {
        Write-Host "Configuring dns client" -ForegroundColor $titleColor
        $dnsConfs = Get-DnsClientServerAddress | Where-Object { $_.AddressFamily -eq 2 }
        foreach($dnsConf in $dnsConfs)
        {
            if ($dnsConf.ServerAddresses.Count -gt 0)
            {
                $newAdrs = $addDnsServer
                $newAdrs += $dnsConf.ServerAddresses
                Set-DnsClientServerAddress -InterfaceAlias $dnsConf.InterfaceAlias -ServerAddresses $newAdrs
            }
        }
        Register-DnsClient
    }

    # Demoting dc
    Write-Host "Demoting dc" -ForegroundColor $titleColor
    Write-Host "ATTENTION: we demote now this dc. The server will reboot. Please relaunch this script after the reboot!" -ForegroundColor Yellow
    pause
    if ($thisDcFqdn -eq $lastDcFqdn)
    {
        Write-Host "Demoting last dc and deleting ad"
        Test-ADDSDomainControllerUninstallation -Credential $orgCred -ForceRemoval:$true -DemoteOperationMasterRole:$true -LastDomainControllerInDomain:$true -IgnoreLastDCInDomainMismatch:$true -RemoveApplicationPartitions:$true -IgnoreLastDNSServerForZone:$true -RemoveDNSDelegation:$true -DNSDelegationRemovalCredential $dnsCred -LocalAdministratorPassword $locPassword -Confirm:$false -NoRebootOnCompletion:$false -Force:$true
        Write-Host "Please check result and press a key to demote!"
        pause
        Uninstall-ADDSDomainController -Credential $orgCred -ForceRemoval:$true -DemoteOperationMasterRole:$true -LastDomainControllerInDomain:$true -IgnoreLastDCInDomainMismatch:$true -RemoveApplicationPartitions:$true -IgnoreLastDNSServerForZone:$true -RemoveDNSDelegation:$true -DNSDelegationRemovalCredential $dnsCred -LocalAdministratorPassword $locPassword -Confirm:$false -NoRebootOnCompletion:$false -Force:$true
        Restart-Computer -Force
    }
    else
    {
        Write-Host "Uninstalling DNS"
        Uninstall-WindowsFeature -Name "DNS" -IncludeManagementTools
        Write-Host "Demoting additional dc"
        $result = Test-ADDSDomainControllerUninstallation -Credential $domCred -ForceRemoval:$false -DemoteOperationMasterRole:$true -LocalAdministratorPassword $locPassword -NoRebootOnCompletion:$false -Force:$true
        Write-Host "Please check result and press a key to demote!"
        pause
        Uninstall-ADDSDomainController -Credential $domCred -ForceRemoval:$false -DemoteOperationMasterRole:$true -LocalAdministratorPassword $locPassword -Confirm:$false -NoRebootOnCompletion:$false -Force:$true
        Restart-Computer -Force
    }
}
else
{
    Write-Host "Logs are located in:"
    Write-Host "  %systemroot%\debug\dcpromo.log"
    Write-Host "  %systemroot%\debug\dcpromoui.log"
    Uninstall-WindowsFeature -Name "AD-Domain-Services" -IncludeManagementTools
    Uninstall-WindowsFeature -Name "RSAT-AD-Tools"
    Uninstall-WindowsFeature -Name "DNS" -IncludeManagementTools
    Uninstall-WindowsFeature -Name "GPMC" -IncludeManagementTools
    if ($thisDcFqdn -eq $lastDcFqdn)
    {
        Write-Host "You have demoted the last dc"
        Write-Host "Please check if the domain has been deleted"
        Write-Host "Don't forget to delete the delegations in parent DNS zones"
    }
    else
    {
        Remove-Computer -UnjoinDomainCredential $domCred -Restart -Force
    }
}
