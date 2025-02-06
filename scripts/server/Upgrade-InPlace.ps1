#Requires -Version 4.0
#Requires -RunAsAdministrator

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
    20.12.2022 Konrad Brunner       Initial Version

#>

[CmdletBinding()]
Param(
    [switch]$GatterOnly,
    [string]$ReattachToReportsDir = $null,
	[switch]$ProceedAlways
)

<#
	
	==================================================
	Script to inplace upgrade a windows server to 2022
	==================================================
	
	This script works with the following directory structure on a share:
	\\server\$mediaShareRoot
		Media
			Windows Server 20xx $mediaLang
			Windows Server 2019 $mediaLang
			Windows Server 2022 $mediaLang
		Reports
			$compName
				$timeStr <- ReattachToReportsDir
		Scripts
			ThisScript

#>

# Members
Write-Host "Members" -ForegroundColor Cyan
$mypath = $MyInvocation.MyCommand.Path
$scriptsDir = $PSScriptRoot
Push-Location "$PSScriptRoot\.."
$mediaShareRoot = $pwd.ProviderPath
Pop-Location 
$compName = ($env:COMPUTERNAME).ToLower()
$compNameFqdn = ($env:COMPUTERNAME+"."+$env:USERDNSDOMAIN).ToLower()
$reportRootDir = [System.IO.Path]::Combine($mediaShareRoot, "Reports")
$serverDir = [System.IO.Path]::Combine($reportRootDir, $compName)
$timeStr = (Get-Date).ToString("yyyyMMddHHmmssfff")
$reportServerDir = [System.IO.Path]::Combine($reportRootDir, $compName)
$reportDir = [System.IO.Path]::Combine($reportServerDir, $timeStr)

if ($ReattachToReportsDir)
{
    if (-Not $ReattachToReportsDir.Contains("\"))
    {
        $reportDir = [System.IO.Path]::Combine($reportServerDir, $ReattachToReportsDir)
    }
    else
    {
    	$reportDir = $ReattachToReportsDir
    }
	$rd = Get-Item -Path $reportDir
    if ($rd.Parent.Name -ne $compName)
    {
        throw "Wrong reattachToReportsDir applied!"
    }
}

if (-Not (Test-Path $reportRootDir))
{
	New-Item -Path $reportRootDir -ItemType Directory -Force
}
if (-Not (Test-Path $reportServerDir))
{
	New-Item -Path $reportServerDir -ItemType Directory -Force
}
if (-Not (Test-Path $reportDir))
{
	New-Item -Path $reportDir -ItemType Directory -Force
}

Start-Transcript -IncludeInvocationHeader -Path "$reportDir\Transcript-$timeStr.txt" -Force
sl $reportDir

# Functions
function Select-Item()
{
    Param(
	    $list,
	    $message = "Please select an item",
	    [ValidateSet("Single","Multiple","None")]
	    $outputMode = "Single"
    )
	$sel = $list | Out-GridView -Title $message -OutputMode $outputMode
	return $sel
}
function SelectDcName()
{
	$list = Get-ADDomainController -Filter * | Select-Object Name, Domain, Forest, OperationMasterRoles
	$sel = Select-Item -list $list
	return $sel.Name
}

if (-Not $ReattachToReportsDir)
{
	# Gattering computer information
	Write-Host "Gattering computer information" -ForegroundColor Cyan
	Get-Partition | Out-File -FilePath "$reportDir\partitions.txt" -Encoding utf8
	Get-Disk | Out-File -FilePath "$reportDir\disks.txt" -Encoding utf8
	systeminfo.exe | Out-File -FilePath "$reportDir\systeminfo.txt" -Encoding utf8
	ipconfig /all | Out-File -FilePath "$reportDir\ipconfig.txt" -Encoding utf8
	dxdiag /t | Out-File -FilePath "$reportDir\dxdiag.txt" -Encoding utf8
	Get-WindowsFeature | Out-File -FilePath "$reportDir\windowsFeature.txt" -Encoding utf8
	Get-Service | Out-File -FilePath "$reportDir\services.txt" -Encoding utf8
	dir env: | Out-File -FilePath "$reportDir\env.txt" -Encoding utf8
	Get-Process -IncludeUserName | Select-Object UserName, ProcessName | Out-File -FilePath "$reportDir\processes.txt" -Encoding utf8
	Dism /Online /Cleanup-Image /ScanHealth | Out-File -FilePath "$reportDir\dismScanHealth.txt" -Encoding utf8
	Dism /Online /Cleanup-Image /CheckHealth | Out-File -FilePath "$reportDir\dismCheckHealth.txt" -Encoding utf8
	sfc.exe /scannow | Out-File -FilePath "$reportDir\sfcscan.txt" -Encoding utf8
	bcdedit | Out-File -FilePath "$reportDir\bcdedit.txt" -Encoding utf8

	$isDc = (Get-WindowsFeature -Name "AD-Domain-Services").Installed
	if ($isDc)
	{
		dcdiag /s:$compName | Out-File -FilePath "$reportDir\dcdiag.txt" -Encoding utf8
		dcdiag /s:$compName /test:dns | Out-File -FilePath "$reportDir\dcdiagDns.txt" -Encoding utf8
		repadmin /showrepl | Out-File -FilePath "$reportDir\repadminShowrepl.txt" -Encoding utf8
		repadmin /replsum | Out-File -FilePath "$reportDir\repadminReplsum.txt" -Encoding utf8
	}

	$isAdfs = (Get-WindowsFeature -Name "ADFS-Federation").Installed
	if ($isAdfs)
	{
		# Exporting ADFS configuration
		Write-Host "Exporting ADFS configuration" -ForegroundColor Cyan
		#TODO C:\Windows\ADFS\Export-FederationConfiguration.ps1
		#add-pssnapin "Microsoft.adfs.powershell"
		Get-AdfsFarmInformation | Out-File -FilePath "$reportDir\adfsFarmInformation.txt" -Encoding utf8
		Get-ADFSCertificate | Out-File -FilePath "$reportDir\adfsCertificates.txt" -Encoding utf8
		$certs = Get-ADFSCertificate
		$mypwd = ConvertTo-SecureString -String $compName -Force -AsPlainText
		foreach($cert in $certs)
		{
			Write-Host "Exporting Cert $($cert.Thumbprint)"
			Get-ChildItem -Path "cert:\*\$($cert.Thumbprint)" -Recurse | Export-PfxCertificate -FilePath "$reportDir\adfsCert$($cert.Thumbprint).pfx" -Password $mypwd
		}
		copy "$($env:SystemRoot)\ADFS\\Microsoft.IdentityServer.Servicehost.exe.config" "$reportDir\adfs-Microsoft.IdentityServer.Servicehost.exe.config"
		Get-ADFSProperties | Out-File ".\adfsProperties.txt"
		setspn -L $compName | Out-File -FilePath "$reportDir\adfsSpns.txt" -Encoding utf8
		$filter = 'Name=' + "'adfssrv'" + ''
		$service = Get-CimInstance -namespace "root\cimv2" -class Win32_Service -Filter $filter
		$service | Format-List -Property * | Out-File -FilePath "$reportDir\adfsService.txt" -Encoding utf8
		Get-ADFSEndpoint | Out-File -FilePath "$reportDir\adfsEndpoints.txt" -Encoding utf8
		Get-ADFSClaimDescription | Out-File -FilePath "$reportDir\adfsClaimtypes.txt" -Encoding utf8
		Get-ADFSClaimsProviderTrust | Out-File -FilePath "$reportDir\adfsCptrusts.txt" -Encoding utf8
		Get-ADFSRelyingPartyTrust | Out-File -FilePath "$reportDir\adfsRptrusts.txt" -Encoding utf8
		Get-ADFSAttributeStore | Out-File -FilePath "$reportDir\adfsAtrstores.txt" -Encoding utf8
	}

	# Storing last upgrade logs
	if (Test-Path "C:\$WINDOWS.~BT")
	{
		robocopy /mir "C:\$WINDOWS.~BT" "$reportDir\WINDOWSBT"
	}

	# Health check dxdiag
	Write-Host "Health check dxdiag" -ForegroundColor Cyan
	#TODO check unsigned drivers (what to do?)
		Write-Host "  TODO"

	# Health check sfc
	Write-Host "Health check sfc" -ForegroundColor Cyan
	$check = (Get-Content -Path "$reportDir\sfcscan.txt" -Encoding $AlyaUtf8Encoding -Raw).Replace("`0", "")
	if (-Not ($check -like "*Der Windows-Ressourcenschutz hat keine Integrit?tsverletzungen gefunden.*" -or $check -like "*Windows Resource Protection did not find any integrity violations.*"))
	{
		Write-Host "sfc.exe has reported an error. Please see $reportDir\sfcscan.txt" -ForegroundColor Red
		Write-Host "Please mount installation media and run:" -ForegroundColor Red
		Write-Host "  Dism /Online /Cleanup-Image /RestoreHealth /Source:D:\sources\install.wim /LimitAccess" -ForegroundColor Red
		Write-Host "And restart the script" -ForegroundColor Red
		if (-Not $ProceedAlways) {Stop-Transcript; exit 1}
	}
	else
	{
		Write-Host "  Passed"
	}

	# Health check Dism ScanHealth
	Write-Host "Health check Dism ScanHealth" -ForegroundColor Cyan
	$check = Get-Content -Path "$reportDir\dismScanHealth.txt" -Encoding $AlyaUtf8Encoding -Raw
	if (-Not ($check -like "*Es wurde keine Komponentenspeicherbesch?digung erkannt.*" -or $check -like "*No component store corruption detected.*")) 
	{
		Write-Host "Dism ScanHealth has reported an error. Please see $reportDir\dismScanHealth.txt" -ForegroundColor Red
		Write-Host "Please run:" -ForegroundColor Red
		Write-Host "  Dism /Online /Cleanup-Image /CheckHealth" -ForegroundColor Red
		Write-Host "  Dism /Online /Cleanup-Image /RestoreHealth /Source:D:\sources\install.wim /LimitAccess" -ForegroundColor Red
		Write-Host "And restart the script" -ForegroundColor Red
		if (-Not $ProceedAlways) {Stop-Transcript; exit 2}
	}
	else
	{
		Write-Host "  Passed"
	}

	# Health check Dism CheckHealth
	Write-Host "Health check Dism CheckHealth" -ForegroundColor Cyan
	$check = Get-Content -Path "$reportDir\dismCheckHealth.txt" -Encoding $AlyaUtf8Encoding -Raw
	if (-Not ($check -like "*Es wurde keine Komponentenspeicherbesch?digung erkannt.*" -or $check -like "*No component store corruption detected.*"))
	{
		Write-Host "Dism CheckHealth has reported an error. Please see $reportDir\dismCheckHealth.txt" -ForegroundColor Red
		Write-Host "Please run:" -ForegroundColor Red
		Write-Host "  Dism /Online /Cleanup-Image /RestoreHealth /Source:D:\sources\install.wim /LimitAccess" -ForegroundColor Red
		Write-Host "And restart the script" -ForegroundColor Red
		if (-Not $ProceedAlways) {Stop-Transcript; exit 3}
	}
	else
	{
		Write-Host "  Passed"
	}
}

# Reading systeminfo
Write-Host "Reading systeminfo" -ForegroundColor Cyan
$sysInfo = Get-Content -Path "$reportDir\systeminfo.txt" -Encoding $AlyaUtf8Encoding
$OsName = ($sysInfo | Where-Object { $_ -like "*Betriebssystemname:*" -or $_ -like "*OS Name:*" }).Split(":")[1].Trim()
$OsVersion = ($sysInfo | Where-Object { $_ -like "*Betriebssystemversion:*" -or $_ -like "*OS Version:*" }).Split(":")[1].Trim()
$OsConfiguration = ($sysInfo | Where-Object { $_ -like "*Betriebssystemkonfiguration:*" -or $_ -like "*OS Configuration:*" }).Split(":")[1].Trim()
$OsType = ($sysInfo | Where-Object { $_ -like "*Systemtyp:*" -or $_ -like "*System Type:*" }).Split(":")[1].Trim()
$OsLocale = ($sysInfo | Where-Object { $_ -like "*Systemgebietsschema:*" -or $_ -like "*System Locale:*" }).Split(":")[1].Split(";")[0].Trim()
$OsDomain = ($sysInfo | Where-Object { $_ -like "*Dom?ne:*" -or $_ -like "*Domain:*" }).Split(":")[1].Trim()
$OsPartition = Get-Partition | Where-Object { $_.DriveLetter -eq $env:SystemDrive.Replace(":", "") }

$OsCode = (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language -Name InstallLanguage).InstallLanguage
switch($OsCode)
{
	"0409" { $OsLocale = "en-US" }
	"0809" { $OsLocale = "en-GB" }
	"2055" { $OsLocale = "de-CH" }
	"0C07" { $OsLocale = "de-AT" }
	"0407" { $OsLocale = "de-DE" }
	default {
	throw "Don't know language $OsCode"
	}
}
$OsLocale | Out-File -FilePath "$reportDir\osLocale.txt" -Encoding utf8

$BootMode = bcdedit | Select-String "path.*efi"
if ($null -eq $BootMode) {
            $OsBootMode = "Legacy"
}else {
            $OsBootMode = "UEFI"
}
$OsBootMode | Out-File -FilePath "$reportDir\osBootMode.txt" -Encoding utf8

# Defining upgrade path
Write-Host "Defining upgrade path" -ForegroundColor Cyan
$mediaEdition = $null
$mediaShare = [System.IO.Path]::Combine($mediaShareRoot, "Media")
$mediaLang = $OsLocale.Split("-")[0].ToUpper()
$atpOffboarding = $null
switch ($OsName)
{
	"Microsoft Windows Server 2008 R2 Standard" {
		$mediaShare = [System.IO.Path]::Combine($mediaShare, "Windows Server 2012 R2 $mediaLang")
		$mediaEdition = "Windows Server 2012 R2 SERVERSTANDARD"
	}
	"Microsoft Windows Server 2012 Standard" {
		$mediaShare = [System.IO.Path]::Combine($mediaShare, "Windows Server 2012 R2 $mediaLang")
		$mediaEdition = "Windows Server 2012 R2 SERVERSTANDARD"
	}
	"Microsoft Windows Server 2012 R2 Standard" {
		$mediaShare = [System.IO.Path]::Combine($mediaShare, "Windows Server 2019 $mediaLang")
		$mediaEdition = "Windows Server 2019 SERVERSTANDARD"
        $atpOffboarding = "Server-2012-2016"
	}
	"Microsoft Windows Server 2016 Standard" {
		$mediaShare = [System.IO.Path]::Combine($mediaShare, "Windows Server 2022 $mediaLang")
		$mediaEdition = "Windows Server 2022 SERVERSTANDARD"
        $atpOffboarding = "Server-2012-2016"
	}
	"Microsoft Windows Server 2019 Standard" {
		$mediaShare = [System.IO.Path]::Combine($mediaShare, "Windows Server 2022 $mediaLang")
		$mediaEdition = "Windows Server 2022 SERVERSTANDARD"
        $atpOffboarding = "Server-2019-2022"
	}
	"Microsoft Windows Server 2022 Standard" {
        $atpOffboarding = "Server-2019-2022"
	}
	"Microsoft Windows Server 2008 R2 Datacenter" {
		$mediaShare = [System.IO.Path]::Combine($mediaShare, "Windows Server 2012 R2 $mediaLang")
		$mediaEdition = "Windows Server 2012 R2 SERVERDATACENTER"
	}
	"Microsoft Windows Server 2012 Datacenter" {
		$mediaShare = [System.IO.Path]::Combine($mediaShare, "Windows Server 2012 R2 $mediaLang")
		$mediaEdition = "Windows Server 2012 R2 SERVERDATACENTER"
	}
	"Microsoft Windows Server 2012 R2 Datacenter" {
		$mediaShare = [System.IO.Path]::Combine($mediaShare, "Windows Server 2019 $mediaLang")
		$mediaEdition = "Windows Server 2019 SERVERDATACENTER"
        $atpOffboarding = "Server-2012-2016"
	}
	"Microsoft Windows Server 2016 Datacenter" {
		$mediaShare = [System.IO.Path]::Combine($mediaShare, "Windows Server 2022 $mediaLang")
		$mediaEdition = "Windows Server 2022 SERVERDATACENTER"
        $atpOffboarding = "Server-2012-2016"
	}
	"Microsoft Windows Server 2019 Datacenter" {
		$mediaShare = [System.IO.Path]::Combine($mediaShare, "Windows Server 2022 $mediaLang")
		$mediaEdition = "Windows Server 2022 SERVERDATACENTER"
        $atpOffboarding = "Server-2019-2022"
	}
	"Microsoft Windows Server 2022 Datacenter" {
        $atpOffboarding = "Server-2019-2022"
	}
	default { throw "Unknown OS name!" }
}
$mediaWimFile = [System.IO.Path]::Combine($mediaShare, "sources")
$mediaWimFile = [System.IO.Path]::Combine($mediaWimFile, "install.wim")
$SetupLogFile = [System.IO.Path]::Combine($reportDir, "setupLog.txt")
$mediaShare | Out-File -FilePath "$reportDir\mediaShare.txt" -Encoding utf8
$mediaEdition | Out-File -FilePath "$reportDir\mediaEdition.txt" -Encoding utf8

if ($GatterOnly)
{
	Write-Host "GatterOnly switch applied. Stopping now the script."
	Write-Host "Please relaunch with:"
	Write-Host "$mypath -reattachToReportsDir $reportDir"
	Stop-Transcript; exit
}

if ($mediaEdition -ne $null)
{
	# Checking vim file
	if (-Not (Test-Path $mediaWimFile))
	{
		Write-Warning "Please relaunch this script with:"
		Write-Warning "$mypath -reattachToReportsDir $reportDir"
		throw "Can't not find the wim file $mediaWimFile"
	}

	# Checking UEFI boot
	if ($mediaEdition -like "*2022*" -and $OsBootMode -eq "Legacy")
	{ 
		Write-Warning "Please relaunch this script with:"
		Write-Warning "$mypath -reattachToReportsDir $reportDir"
		throw "You need to enable UEFI boot mode!"
	}
	
	$hasDefenderEndpoint = Get-Service -Name SENSE -ErrorAction SilentlyContinue
    if ($hasDefenderEndpoint)
	{
		Write-Host "Upgrade with Defender for Endpoint is not supported. Needs to be uninstalled!" -ForegroundColor Cyan
        
        $alreadyOffboarded = $false
        if ($hasDefenderEndpoint.Status -eq "Stopped")
        {
            Write-Warning "The SENSE service is in stopped state. Have you already offboarded?"
            $title    = "Confirm"
            $question = "Defender for Endpoint already offboarded?"
            $choices  = "&Yes", "&No"
            $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
            if ($decision -eq 0) {
                $alreadyOffboarded = $true
            }
        }
        if (-Not $alreadyOffboarded)
        {
		    $hasDefenderEndpoint | Out-File -FilePath "$reportDir\hadDefenderEndpoint.txt" -Encoding utf8

            if (-Not $atpOffboarding)
            {
                Write-Warning "Your operating system is not supported by this script to offboard Defender for Endpoint. Please uninstall it manually."
		        Write-Warning "Please uninstall Defender for Endpoint and relaunch this script with:"
            }
            else
            {
                $atpScript = $null
                $scripts = Get-Item -Path "$scriptsDir\WindowsDefenderATPOffboardingScript_$($atpOffboarding)_valid_until_*.cmd"
                foreach($script in $scripts)
                {
                    $dateStr = $script.Name.Replace("WindowsDefenderATPOffboardingScript_$($atpOffboarding)_valid_until_", "").Replace(".cmd", "")
                    $scriptValidity = [DateTime]::ParseExact($dateStr, "yyyy-MM-dd", [CultureInfo]::InvariantCulture)
                    if ($scriptValidity -gt (Get-Date).AddDays(-25))
                    {
                        $atpScript = $script
                        break
                    }
                }
		        if (-Not $atpScript)
		        {
			        Write-Warning "You need to provide the Offboarding script for Defender for Endpoint!"
			        Write-Warning "Please go to https://security.microsoft.com/preferences2/offboarding and download the script."
			        Write-Warning "Save it to:"
			        Write-Warning "$scriptsDir\WindowsDefenderATPLocalOffboardingScript_$($atpOffboarding)_valid_until_yyyy-MM-dd.cmd"
			        Write-Warning ""
			        Write-Warning "Please relaunch this script with:"
			        Write-Warning "$mypath -reattachToReportsDir $reportDir"
			        Stop-Transcript; exit
		        }
                Write-Host "Please start an elevated command prompt and run following command:" -ForegroundColor Green
		        Write-Host "$($atpScript.FullName)" -ForegroundColor Green
                pause
    		    Write-Warning "Please reboot and relaunch this script with:"
            }
		    Write-Warning "$mypath -reattachToReportsDir $reportDir"
		    Stop-Transcript; exit
        }
	}
    
	if ($isDc)
	{
		# Checking domain controller roles
		Write-Host "Checking domain controller roles" -ForegroundColor Cyan
		Get-ADDomainController -Filter * | Select-Object Name, Domain, Forest, OperationMasterRoles | Format-List | Out-File -FilePath "$reportDir\domainControllers.txt" -Encoding utf8
		Get-ADDomainController -Filter * | Select-Object Name, Domain, Forest, OperationMasterRoles
		$dom = Get-ADDomain
		$for = Get-ADForest
		if ($dom.InfrastructureMaster.ToLower() -eq $compNameFqdn -or $dom.InfrastructureMaster.ToLower() -eq $compName)
		{
			if (-Not $otherDcFqdn) { $otherDcFqdn = SelectDcName }
			Write-Warning "This DC is InfrastructureMaster. Moving it to last DC $otherDcFqdn"
			Move-ADDirectoryServerOperationMasterRole -OperationMasterRole InfrastructureMaster -Identity $otherDcFqdn -Force -Confirm:$false
			"InfrastructureMaster" | Out-File -FilePath "$reportDir\domainControllerRolesMoved.txt" -Append -Force
		}
		if ($dom.RIDMaster.ToLower() -eq $compNameFqdn -or $dom.RIDMaster.ToLower() -eq $compName)
		{
			if (-Not $otherDcFqdn) { $otherDcFqdn = SelectDcName }
			Write-Warning "This DC is RIDMaster. Moving it to last DC $otherDcFqdn"
			Move-ADDirectoryServerOperationMasterRole -OperationMasterRole RIDMaster -Identity $otherDcFqdn -Force -Confirm:$false
			"RIDMaster" | Out-File -FilePath "$reportDir\domainControllerRolesMoved.txt" -Append -Force
		}
		if ($dom.PDCEmulator.ToLower() -eq $compNameFqdn -or $dom.PDCEmulator.ToLower() -eq $compName)
		{
			if (-Not $otherDcFqdn) { $otherDcFqdn = SelectDcName }
			Write-Warning "This DC is PDCEmulator. Moving it to last DC $otherDcFqdn"
			Move-ADDirectoryServerOperationMasterRole -OperationMasterRole PDCEmulator -Identity $otherDcFqdn -Force -Confirm:$false
			"PDCEmulator" | Out-File -FilePath "$reportDir\domainControllerRolesMoved.txt" -Append -Force
		}
		if ($for.SchemaMaster.ToLower() -eq $compNameFqdn -or $for.SchemaMaster.ToLower() -eq $compName)
		{
			if (-Not $otherDcFqdn) { $otherDcFqdn = SelectDcName }
			Write-Warning "This DC is SchemaMaster. Moving it to last DC $otherDcFqdn"
			Move-ADDirectoryServerOperationMasterRole -OperationMasterRole SchemaMaster -Identity $otherDcFqdn -Force -Confirm:$false
			"SchemaMaster" | Out-File -FilePath "$reportDir\domainControllerRolesMoved.txt" -Append -Force
		}
		if ($for.DomainNamingMaster.ToLower() -eq $compNameFqdn -or $for.DomainNamingMaster.ToLower() -eq $compName)
		{
			if (-Not $otherDcFqdn) { $otherDcFqdn = SelectDcName }
			Write-Warning "This DC is DomainNamingMaster. Moving it to last DC $otherDcFqdn"
			Move-ADDirectoryServerOperationMasterRole -OperationMasterRole DomainNamingMaster -Identity $otherDcFqdn -Force -Confirm:$false
			"DomainNamingMaster" | Out-File -FilePath "$reportDir\domainControllerRolesMoved.txt" -Append -Force
		}    
	}

	# Checking domain controller schema
	if ($isDc)
	{
		$requiredSchemaVersion = 66
		if ($mediaEdition -like "*2016*") { $requiredSchemaVersion = 88 }
		if ($mediaEdition -like "*2019*") { $requiredSchemaVersion = 88 }
		if ($mediaEdition -like "*2022*") { $requiredSchemaVersion = 88 }
		$schemaVersion = $null
		$schemDn = "CN=Schema,CN=Configuration,DC=rbzh,DC=ch"
		$adObj = Get-AdObject -Identity $schemDn -Properties *
		$schemaVersion = $adObj.objectVersion
		if ($schemaVersion -lt $requiredSchemaVersion)
		{
			#repadmin /syncall /AdeP
			cmd /c "$mediaShare\support\adprep\adprep.exe" /forestprep
			cmd /c "$mediaShare\support\adprep\adprep.exe" /domainprep
		}
	}

    # Needs update
	<#
    # Creating autounattend.xml
    Write-Host "Creating autounattend.xml" -ForegroundColor Cyan
    $AutounattendFile = [System.IO.Path]::Combine($reportDir, "autounattend.xml")
    $Autounattend = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
    <settings pass="windowsPE">
        <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm=http://schemas.microsoft.com/WMIConfig/2002/State; xmlns:xsi=http://www.w3.org/2001/XMLSchema-instance>
            <ComplianceCheck>
                <DisplayReport>OnError</DisplayReport>
            </ComplianceCheck>
            <UpgradeData>
                <Upgrade>true</Upgrade>
                <WillShowUI>OnError</WillShowUI>
            </UpgradeData>
            <UserData>
                <AcceptEula>true</AcceptEula>
            </UserData>
            <ImageInstall>
                <OSImage>
                    <InstallFrom>
                        <MetaData wcm:action="add">
                            <Key>/IMAGE/NAME</Key>
                            <Value>$($mediaEdition)</Value>
                        </MetaData>
                        <Path>$($mediaWimFile)</Path>
                    </InstallFrom>
                    <InstallTo>
                        <DiskID>$($OsPartition.DiskNumber)</DiskID>
                        <PartitionID>$($OsPartition.PartitionNumber)</PartitionID>
                    </InstallTo>
                </OSImage>
            </ImageInstall>
            <LogPath>$($SetupLogFile)</LogPath>
        </component>
    </settings>
</unattend>
"@
    $Autounattend | Set-Content -Path $AutounattendFile -Encoding UTF8 -Force
	#>
	
	# Stopping services
	$isSccm = Get-Service -Name "SMS_EXECUTIVE" -ErrorAction SilentlyContinue
	if ($isSccm)
	{
		Get-Service | Where-Object {$_.DisplayName -like "SMS*"} | Stop-Service -Force
        Start-Sleep -Seconds 20
		Get-Service | Where-Object {$_.DisplayName -like "SMS*"} | Stop-Service -Force
	}
	
	$isMsSql = Get-Service -Name "SQLBrowser" -ErrorAction SilentlyContinue
	if ($isSccm)
	{
		Get-Service | Where-Object {$_.DisplayName -like "SQL*"} | Stop-Service -Force
        Start-Sleep -Seconds 20
		Get-Service | Where-Object {$_.DisplayName -like "SQL*"} | Stop-Service -Force
	}
	
	# Launching update
	Write-Host "Launching update" -ForegroundColor Cyan
	$setupFile = [System.IO.Path]::Combine($mediaShare, "setup.exe")
	if (-Not (Test-Path $mediaWimFile))
	{
		Write-Warning "Please relaunch this script with:"
		Write-Warning "$mypath -reattachToReportsDir $reportDir"
		throw "Can't not find the setup file $setupFile"
	}
	
	Write-Host "OsName: $($OsName)"
	Write-Host "OsVersion: $($OsVersion)"
	Write-Host "OsConfiguration: $($OsConfiguration)"
	Write-Host "OsType: $($OsType)"
	Write-Host "OsLocale: $($OsLocale)"
	Write-Host "OsDomain: $($OsDomain)"
	
	Push-Location $mediaShare
	& "$setupFile"
	#& "$setupFile" /unattend:$AutounattendFile
	Pop-Location 

	<#
    # Done
    Write-Host "Done" -ForegroundColor Cyan
    Write-Warning "Please restart server and relaunch this script"
    pause
    #Restart-Computer -Force
	#>
}
else
{
    # Update to 2022 done

    # Reading first run data
	Write-Host "Reading first run data" -ForegroundColor Cyan
	$childs = Get-ChildItem -Path $reportServerDir
	$firstRun = Get-Date
	$firstReportDir = $null
	try
	{
		foreach ($child in $childs)
		{
			if ([DateTime]::ParseExact($child.Name, "yyyyMMddHHmmssfff", [CultureInfo]::InvariantCulture) -lt $firstRun)
			{
				$firstRun = [DateTime]::ParseExact($child.Name, "yyyyMMddHHmmssfff", [CultureInfo]::InvariantCulture)
			}
		}
		$firstReportDir = [System.IO.Path]::Combine($reportServerDir, $firstRun.ToString("yyyyMMddHHmmssfff"))
	}
	catch
	{
		foreach ($child in $childs)
		{
			if ([DateTime]::ParseExact($child.Name, "yyyyMMddhhmmssfff", [CultureInfo]::InvariantCulture) -lt $firstRun)
			{
				$firstRun = [DateTime]::ParseExact($child.Name, "yyyyMMddhhmmssfff", [CultureInfo]::InvariantCulture)
			}
		}
		$firstReportDir = [System.IO.Path]::Combine($reportServerDir, $firstRun.ToString("yyyyMMddhhmmssfff"))
	}
	if ($firstReportDir -eq $null)
	{
		throw "Not able to find first run directory!"
	}
	$firstServices = Get-Content -Path "$firstReportDir\services.txt" -Encoding $AlyaUtf8Encoding
	$firstProcesses = Get-Content -Path "$firstReportDir\processes.txt" -Encoding $AlyaUtf8Encoding
	$actualServices = Get-Content -Path "$reportDir\services.txt" -Encoding $AlyaUtf8Encoding
	$actualProcesses = Get-Content -Path "$reportDir\processes.txt" -Encoding $AlyaUtf8Encoding

	if (Test-Path "$firstReportDir\hadDefenderEndpoint.txt")
	{
		Write-Host "Defender for Endpoint was previously installed. Reinstalling!" -ForegroundColor Cyan
		if (-Not (Test-Path "$scriptsDir\WindowsDefenderATPLocalOnboardingScript.cmd"))
		{
			Write-Warning "You need to provide the Onboarding script for Defender for Endpoint!"
			Write-Warning "Please go to https://security.microsoft.com/preferences2/onboarding and download the scripts."
			Write-Warning "Save it to:"
			Write-Warning "$scriptsDir\WindowsDefenderATPLocalOnboardingScript.cmd"
			Write-Warning ""
			Write-Warning "Please relaunch this script with:"
			Write-Warning "$mypath -reattachToReportsDir $reportDir"
			Stop-Transcript; exit
		}
        Write-Host "Please start an elevated command prompt and run following command:" -ForegroundColor Green
		Write-Host "$scriptsDir\WindowsDefenderATPLocalOnboardingScript.cmd" -ForegroundColor Green
        pause
	}

	if ($isDc)
	{
		#Move dc roles back
		Write-Host "Checking domain controller roles" -ForegroundColor Cyan
		$movedRoles = Get-Content -Path "$firstReportDir\domainControllerRolesMoved.txt" -Encoding $AlyaUtf8Encoding -ErrorAction SilentlyContinue
		foreach($movedRole in $movedRoles)
		{
			switch($movedRole) #TODO check if a move from remote works
			{
				"InfrastructureMaster" {
					Move-ADDirectoryServerOperationMasterRole -OperationMasterRole InfrastructureMaster -Identity $compName -Force -Confirm:$false
				}
				"RIDMaster" {
					Move-ADDirectoryServerOperationMasterRole -OperationMasterRole RIDMaster -Identity $compName -Force -Confirm:$false
				}
				"PDCEmulator" {
					Move-ADDirectoryServerOperationMasterRole -OperationMasterRole PDCEmulator -Identity $compName -Force -Confirm:$false
				}
				"SchemaMaster" {
					Move-ADDirectoryServerOperationMasterRole -OperationMasterRole SchemaMaster -Identity $compName -Force -Confirm:$false
				}
				"DomainNamingMaster" {
					Move-ADDirectoryServerOperationMasterRole -OperationMasterRole DomainNamingMaster -Identity $compName -Force -Confirm:$false
				}
			}
		}
		Get-ADDomainController -Filter * | Select-Object Name, Domain, Forest, OperationMasterRoles
	}

	# Checking services
	Write-Host "Checking services" -ForegroundColor Cyan
	foreach($firstService in $firstServices)
	{
		$firstParts = $firstService.Split(" ", [StringSplitOptions]::RemoveEmptyEntries)
		$fnd = $false
		$ste = $true
		foreach($actualService in $actualServices)
		{
			$actualParts = $actualService.Split(" ", [StringSplitOptions]::RemoveEmptyEntries)
			if ($actualParts[1] -eq $firstParts[1])
			{
				$fnd = $true
				if ($actualParts[0] -ne $firstParts[0]) { $ste = $false }
				break
			}
		}
		if (-Not $fnd)
		{
			$ignore = ""
			if ($firstParts[1] -eq "AeLookupSvc") {$ignore = " CAN BE IGNROED!"}
			Write-Warning "Service $($firstParts[1]) not found after migration$ignore"
		}
		else
		{
			if (-Not $ste)
			{
				$serv = Get-Service -Name $firstParts[1]
				if ($serv.StartType -eq "Automatic")
				{
					$ignore = ""
					if ($firstParts[1] -eq "blabla") {$ignore = " CAN BE IGNROED!"}
					Write-Warning "Service $($firstParts[1]) does not have correct run state after migration$ignore"
				}
			}
		}
		if ($firstParts[1] -eq "COMSysApp") { break }
	}

    # Checking processes
	Write-Host "Checking processes" -ForegroundColor Cyan
	$firstProcs = @()
	foreach($firstProcesse in $firstProcesses)
	{
		$tmp = $firstProcesse.Split(" ", [StringSplitOptions]::RemoveEmptyEntries)
		if ($tmp.Count -gt 0)
		{
			$firstProcs += $tmp[$tmp.Count - 1]
		}
	}
	$firstProcs = $firstProcs | Select-Object -Unique
	$actualProcs = @()
	foreach($actualProcesse in $actualProcesses)
	{
		$tmp = $actualProcesse.Split(" ", [StringSplitOptions]::RemoveEmptyEntries)
		if ($tmp.Count -gt 0)
		{
			$actualProcs += $tmp[$tmp.Count - 1]
		}
	}
	$actualProcs = $actualProcs | Select-Object -Unique
	foreach($firstProc in $firstProcs)
	{
		if ($actualProcs -notcontains $firstProc)
		{
			Write-Warning "Process $($firstProc) not found after migration"
		}
	}
	
	# DONE
	Write-Host "Update to 2022 DONE!" -ForegroundColor Green
	"" | Set-Content -Path "$reportServerDir\Done.txt"
}

Stop-Transcript

# SIG # Begin signature block
# MIIvGwYJKoZIhvcNAQcCoIIvDDCCLwgCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDb0kJGOBoaMW07
# GLVT2D+zSQ4iruypuRLG73FQCgTL1KCCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
# Qc9vAbjutKlUMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24g
# Um9vdCBDQSAtIFIzMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9i
# YWxTaWduMB4XDTIwMDcyODAwMDAwMFoXDTI5MDMxODAwMDAwMFowUzELMAkGA1UE
# BhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2Jh
# bFNpZ24gQ29kZSBTaWduaW5nIFJvb3QgUjQ1MIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAti3FMN166KuQPQNysDpLmRZhsuX/pWcdNxzlfuyTg6qE9aND
# m5hFirhjV12bAIgEJen4aJJLgthLyUoD86h/ao+KYSe9oUTQ/fU/IsKjT5GNswWy
# KIKRXftZiAULlwbCmPgspzMk7lA6QczwoLB7HU3SqFg4lunf+RuRu4sQLNLHQx2i
# CXShgK975jMKDFlrjrz0q1qXe3+uVfuE8ID+hEzX4rq9xHWhb71hEHREspgH4nSr
# /2jcbCY+6R/l4ASHrTDTDI0DfFW4FnBcJHggJetnZ4iruk40mGtwEd44ytS+ocCc
# 4d8eAgHYO+FnQ4S2z/x0ty+Eo7+6CTc9Z2yxRVwZYatBg/WsHet3DUZHc86/vZWV
# 7Z0riBD++ljop1fhs8+oWukHJZsSxJ6Acj2T3IyU3ztE5iaA/NLDA/CMDNJF1i7n
# j5ie5gTuQm5nfkIWcWLnBPlgxmShtpyBIU4rxm1olIbGmXRzZzF6kfLUjHlufKa7
# fkZvTcWFEivPmiJECKiFN84HYVcGFxIkwMQxc6GYNVdHfhA6RdktpFGQmKmgBzfE
# ZRqqHGsWd/enl+w/GTCZbzH76kCy59LE+snQ8FB2dFn6jW0XMr746X4D9OeHdZrU
# SpEshQMTAitCgPKJajbPyEygzp74y42tFqfT3tWbGKfGkjrxgmPxLg4kZN8CAwEA
# AaOCAXcwggFzMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzAP
# BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQfAL9GgAr8eDm3pbRD2VZQu86WOzAf
# BgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpjmove4t0bvDB6BggrBgEFBQcBAQRuMGww
# LQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL3Jvb3RyMzA7
# BggrBgEFBQcwAoYvaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# cm9vdC1yMy5jcnQwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxz
# aWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggrBgEF
# BQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJ
# KoZIhvcNAQEMBQADggEBAKz3zBWLMHmoHQsoiBkJ1xx//oa9e1ozbg1nDnti2eEY
# XLC9E10dI645UHY3qkT9XwEjWYZWTMytvGQTFDCkIKjgP+icctx+89gMI7qoLao8
# 9uyfhzEHZfU5p1GCdeHyL5f20eFlloNk/qEdUfu1JJv10ndpvIUsXPpYd9Gup7EL
# 4tZ3u6m0NEqpbz308w2VXeb5ekWwJRcxLtv3D2jmgx+p9+XUnZiM02FLL8Mofnre
# kw60faAKbZLEtGY/fadY7qz37MMIAas4/AocqcWXsojICQIZ9lyaGvFNbDDUswar
# AGBIDXirzxetkpNiIHd1bL3IMrTcTevZ38GQlim9wX8wggboMIIE0KADAgECAhB3
# vQ4Ft1kLth1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENv
# ZGUgU2lnbmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAw
# MDBaMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIw
# MAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAy
# MDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj
# /SBerjgSi8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlM
# g7BKRFAEeIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRV
# X5YLEeWatSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV
# 0xHK5s2zBZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEz
# IHXMsdXtHQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMk
# oog28vmfvpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq
# 7rfYrWGlr3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult
# 5a/dm2tjIF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNu
# twFsDeCXpxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYy
# AjIwfLWTyCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofn
# GrhO7izB36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
# FgQUJZ3Q/FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0
# Q9lWULvOljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8v
# b2NzcC5nbG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUH
# MAKGOmh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWdu
# aW5ncm9vdHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJ
# KwYBBAGgMgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24u
# Y29tL3JlcG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJ
# yTm6t6E5iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbV
# YQLFY4/UovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQt
# pFg6bBNJ+KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSX
# hndGKj0jfShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6
# bs+XYXvfcXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nO
# ZNm9/Lws80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOH
# X5OKSBoRHeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dq
# cYC/lt5yA9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0i
# xxnJpsoOqHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7
# qWPLd0jV+mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g6
# 04YfM/tV5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD
# 4ED6gVYDU/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S
# /gJXhZrh0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp
# 8nKmrVa46Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqt
# f2phU7+yR2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJ
# QWTEE/bP0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKX
# vYkPbEdx+QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4
# yMYgcMKb9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmY
# F8T4xO2k6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2
# mMIVpqWCZ1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7
# spNY6rQb3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd
# 2jANBgkqhkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy
# /fAHsVv1RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW
# 2H3Bh6zNXULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0
# MP6pBPKOL6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/
# pFL9zlcctWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcex
# U0bcV0hLQ4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf
# 6AMOGaM56A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzEC
# p9LnR+34c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9m
# UF5qE6YwQqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+Ku
# aJRsz+cnZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/Jl
# N6m6GM1jEhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutof
# dgNBzMUxghnmMIIZ4gIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJdAMqVJ
# 5BFAONJCfanmQVM+bJtrnepw0d7D66e9o84AMA0GCSqGSIb3DQEBAQUABIICAFXG
# kbgdrCemsTj8PUcxZPCDOaPiDLvqmEGgaRFYzIXLPCu2zWBSPCN4Q4m7l/S6ptl8
# vVIlVP6k2+D1aWAMqeTP2TV4b2GAIIsZ2VfqQiHN1DRQ0tXNXJYlOk58rVH5WXiG
# 63/xfug17beBWDUUc3CBOZNqFhOBpzQZrrcasq3fNB/qO9g3ev8ztnd1wVdq8dWx
# yCYqb6rY55Lp2tGVI559P/gB1b0JhfpXsyLT+I81X7fzltAY43y+n1hQ7mfXEysY
# 6vnBuiWCqOD0BJ2QplVKiaA2GLgW9zRK6Fdh0Ii1RzyZAbelbLCW2fPfieyzoXQf
# r+mlJuAZ91qZpVnh0jWYBA1NdvGlWMNrsWxteIc3Gjq3leiigAJJCy5QMCBCF2JF
# /tEdituBOGCn9WAUQe6hQVr88n/5AILd0idELr34gnKOdgI3WS72ftrSdVD5MFrN
# QjALrNUoBLGG7VFbnRLO6Kk98XuzBdaUuZ0IOqFjgWgIQus8YUOhJwEL2TpyHI4I
# RDiQgA5vAOOYQN/g26hiUfYz8QoEJA2HPiNyD7Jto2NRCNB9IO8t8NFWvDt0yMKs
# BWTLOCrgws/n+L5OyG7wDTnU7eX3fe97BkPhd+HKN1IzxLS8HsDS0RJc2sBl9dI9
# ydgMdgzCjOqoR6HUT/B64atwlRAvD+P6KLM8wLaooYIWzTCCFskGCisGAQQBgjcD
# AwExgha5MIIWtQYJKoZIhvcNAQcCoIIWpjCCFqICAQMxDTALBglghkgBZQMEAgEw
# gegGCyqGSIb3DQEJEAEEoIHYBIHVMIHSAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCG
# SAFlAwQCAQUABCCrfg3579RVrIqbYpFfEeSY6LkwvWRtnqnNYudSo2p+2gIUQ1Ib
# 8uTHt6Yz8sCqo084nwaJAzQYDzIwMjUwMjA2MTkyOTU5WjADAgEBoGGkXzBdMQsw
# CQYDVQQGEwJCRTEZMBcGA1UECgwQR2xvYmFsU2lnbiBudi1zYTEzMDEGA1UEAwwq
# R2xvYmFsc2lnbiBUU0EgZm9yIENvZGVTaWduMSAtIFI2IC0gMjAyMzExoIISVDCC
# BmwwggRUoAMCAQICEAGb6t7ITWuP92w6ny4BJBYwDQYJKoZIhvcNAQELBQAwWzEL
# MAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMT
# KEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQwHhcNMjMx
# MTA3MTcxMzQwWhcNMzQxMjA5MTcxMzQwWjBdMQswCQYDVQQGEwJCRTEZMBcGA1UE
# CgwQR2xvYmFsU2lnbiBudi1zYTEzMDEGA1UEAwwqR2xvYmFsc2lnbiBUU0EgZm9y
# IENvZGVTaWduMSAtIFI2IC0gMjAyMzExMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A
# MIIBigKCAYEA6oQ3UGg8lYW1SFRxl/OEcsmdgNMI3Fm7v8tNkGlHieUs2PGoan5g
# N0lzm7iYsxTg74yTcCC19SvXZgV1P3qEUKlSD+DW52/UHDUu4C8pJKOOdyUn4Ljz
# fWR1DJpC5cad4tiHc4vvoI2XfhagxLJGz2DGzw+BUIDdT+nkRqI0pz4Yx2u0tvu+
# 2qlWfn+cXTY9YzQhS8jSoxMaPi9RaHX5f/xwhBFlMxKzRmUohKAzwJKd7bgfiWPQ
# HnssW7AE9L1yY86wMSEBAmpysiIs7+sqOxDV8Zr0JqIs/FMBBHkjaVHTXb5zhMub
# g4htINIgzoGraiJLeZBC5oJCrwPr1NDag3rDLUjxzUWRtxFB3RfvQPwSorLAWapU
# l05tw3rdhobUOzdHOOgDPDG/TDN7Q+zw0P9lpp+YPdLGulkibBBYEcUEzOiimLAd
# M9DzlR347XG0C0HVZHmivGAuw3rJ3nA3EhY+Ao9dOBGwBIlni6UtINu41vWc9Q+8
# iL8nLMP5IKLBAgMBAAGjggGoMIIBpDAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/
# BAwwCgYIKwYBBQUHAwgwHQYDVR0OBBYEFPlOq764+Fv/wscD9EHunPjWdH0/MFYG
# A1UdIARPME0wCAYGZ4EMAQQCMEEGCSsGAQQBoDIBHjA0MDIGCCsGAQUFBwIBFiZo
# dHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAMBgNVHRMBAf8E
# AjAAMIGQBggrBgEFBQcBAQSBgzCBgDA5BggrBgEFBQcwAYYtaHR0cDovL29jc3Au
# Z2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNoYTM4NGc0MEMGCCsGAQUFBzAChjdo
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9nc3RzYWNhc2hhMzg0
# ZzQuY3J0MB8GA1UdIwQYMBaAFOoWxmnn48tXRTkzpPBAvtDDvWWWMEEGA1UdHwQ6
# MDgwNqA0oDKGMGh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vY2EvZ3N0c2FjYXNo
# YTM4NGc0LmNybDANBgkqhkiG9w0BAQsFAAOCAgEAlfRnz5OaQ5KDF3bWIFW8if/k
# X7LlFRq3lxFALgBBvsU/JKAbRwczBEy0tGL/xu7TDMI0oJRcN5jrRPhf+CcKAr4e
# 0SQdI8svHKsnerOpxS8M5OWQ8BUkHqMVGfjvg+hPu2ieI299PQ1xcGEyfEZu8o/R
# nOhDTfqD4f/E4D7+3lffBmvzagaBaKsMfCr3j0L/wHNp2xynFk8mGVhz7ZRe5Bqi
# EIIHMjvKnr/dOXXUvItUP35QlTSfkjkkUxiDUNRbL2a0e/5bKesexQX9oz37obDz
# K3kPsUusw6PZo9wsnCsjlvZ6KrutxVe2hLZjs2CYEezG1mZvIoMcilgD9I/snE7Q
# 3+7OYSHTtZVUSTshUT2hI4WSwlvyepSEmAqPJFYiigT6tJqJSDX4b+uBhhFTwJN7
# OrTUNMxi1jVhjqZQ+4h0HtcxNSEeEb+ro2RTjlTic2ak+2Zj4TfJxGv7KzOLEcN0
# kIGDyE+Gyt1Kl9t+kFAloWHshps2UgfLPmJV7DOm5bga+t0kLgz5MokxajWV/vbR
# /xeKriMJKyGuYu737jfnsMmzFe12mrf95/7haN5EwQp04ZXIV/sU6x5a35Z1xWUZ
# 9/TVjSGvY7br9OIXRp+31wduap0r/unScU7Svk9i00nWYF9A43aZIETYSlyzXRrZ
# 4qq/TVkAF55gZzpHEqAwggZZMIIEQaADAgECAg0B7BySQN79LkBdfEd0MA0GCSqG
# SIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMw
# EQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMB4XDTE4MDYy
# MDAwMDAwMFoXDTM0MTIxMDAwMDAwMFowWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1w
# aW5nIENBIC0gU0hBMzg0IC0gRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQDwAuIwI/rgG+GadLOvdYNfqUdSx2E6Y3w5I3ltdPwx5HQSGZb6zidiW64H
# iifuV6PENe2zNMeswwzrgGZt0ShKwSy7uXDycq6M95laXXauv0SofEEkjo+6xU//
# NkGrpy39eE5DiP6TGRfZ7jHPvIo7bmrEiPDul/bc8xigS5kcDoenJuGIyaDlmeKe
# 9JxMP11b7Lbv0mXPRQtUPbFUUweLmW64VJmKqDGSO/J6ffwOWN+BauGwbB5lgirU
# IceU/kKWO/ELsX9/RpgOhz16ZevRVqkuvftYPbWF+lOZTVt07XJLog2CNxkM0Kvq
# WsHvD9WZuT/0TzXxnA/TNxNS2SU07Zbv+GfqCL6PSXr/kLHU9ykV1/kNXdaHQx50
# xHAotIB7vSqbu4ThDqxvDbm19m1W/oodCT4kDmcmx/yyDaCUsLKUzHvmZ/6mWLLU
# 2EESwVX9bpHFu7FMCEue1EIGbxsY1TbqZK7O/fUF5uJm0A4FIayxEQYjGeT7BTRE
# 6giunUlnEYuC5a1ahqdm/TMDAd6ZJflxbumcXQJMYDzPAo8B/XLukvGnEt5CEk3s
# qSbldwKsDlcMCdFhniaI/MiyTdtk8EWfusE/VKPYdgKVbGqNyiJc9gwE4yn6S7Ac
# 0zd0hNkdZqs0c48efXxeltY9GbCX6oxQkW2vV4Z+EDcdaxoU3wIDAQABo4IBKTCC
# ASUwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYE
# FOoWxmnn48tXRTkzpPBAvtDDvWWWMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMD4GCCsGAQUFBwEBBDIwMDAuBggrBgEFBQcwAYYiaHR0cDovL29jc3Ay
# Lmdsb2JhbHNpZ24uY29tL3Jvb3RyNjA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8v
# Y3JsLmdsb2JhbHNpZ24uY29tL3Jvb3QtcjYuY3JsMEcGA1UdIARAMD4wPAYEVR0g
# ADA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxzaWduLmNvbS9yZXBv
# c2l0b3J5LzANBgkqhkiG9w0BAQwFAAOCAgEAf+KI2VdnK0JfgacJC7rEuygYVtZM
# v9sbB3DG+wsJrQA6YDMfOcYWaxlASSUIHuSb99akDY8elvKGohfeQb9P4byrze7A
# I4zGhf5LFST5GETsH8KkrNCyz+zCVmUdvX/23oLIt59h07VGSJiXAmd6FpVK22LG
# 0LMCzDRIRVXd7OlKn14U7XIQcXZw0g+W8+o3V5SRGK/cjZk4GVjCqaF+om4VJuq0
# +X8q5+dIZGkv0pqhcvb3JEt0Wn1yhjWzAlcfi5z8u6xM3vreU0yD/RKxtklVT3Wd
# rG9KyC5qucqIwxIwTrIIc59eodaZzul9S5YszBZrGM3kWTeGCSziRdayzW6CdaXa
# jR63Wy+ILj198fKRMAWcznt8oMWsr1EG8BHHHTDFUVZg6HyVPSLj1QokUyeXgPpI
# iScseeI85Zse46qEgok+wEr1If5iEO0dMPz2zOpIJ3yLdUJ/a8vzpWuVHwRYNAqJ
# 7YJQ5NF7qMnmvkiqK1XZjbclIA4bUaDUY6qD6mxyYUrJ+kPExlfFnbY8sIuwuRwx
# 773vFNgUQGwgHcIt6AvGjW2MtnHtUiH+PvafnzkarqzSL3ogsfSsqh3iLRSd+pZq
# HcY8yvPZHL9TTaRHWXyVxENB+SXiLBB+gfkNlKd98rUJ9dhgckBQlSDUQ0S++qCV
# 5yBZtnjGpGqqIpswggWDMIIDa6ADAgECAg5F5rsDgzPDhWVI5v9FUTANBgkqhkiG
# 9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjETMBEG
# A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAw
# MDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9v
# dCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9iYWxT
# aWduMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlQfoc8pm+ewUyns8
# 9w0I8bRFCyyCtEjG61s8roO4QZIzFKRvf+kqzMawiGvFtonRxrL/FM5RFCHsSt0b
# WsbWh+5NOhUG7WRmC5KAykTec5RO86eJf094YwjIElBtQmYvTbl5KE1SGooagLcZ
# gQ5+xIq8ZEwhHENo1z08isWyZtWQmrcxBsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ
# 3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQBzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2M
# sonP0KBhd8hYdLDUIzr3XTrKotudCd5dRC2Q8YHNV5L6frxQBGM032uTGL5rNrI5
# 5KwkNrfw77YcE1eTtt6y+OKFt3OiuDWqRfLgnTahb1SK8XJWbi6IxVFCRBWU7qPF
# OJabTk5aC0fzBjZJdzC8cTflpuwhCHX85mEWP3fV2ZGXhAps1AJNdMAU7f05+4Py
# XhShBLAL6f7uj+FuC7IIs2FmCWqxBjplllnA8DX9ydoojRoRh3CBCqiadR2eOoYF
# AJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R/98wEfmFzzNI9cptZBQselhP00sIScWV
# ZBpjDnk99bOMylitnEJFeW4OhxlcVLFltr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlw
# g3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8G
# A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8G
# A1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4IC
# AQCDJe3o0f2VUs2ewASgkWnmXNCE3tytok/oR3jWZZipW6g8h3wCitFutxZz5l/A
# VJjVdL7BzeIRka0jGD3d4XJElrSVXsB7jpl4FkMTVlezorM7tXfcQHKso+ubNT6x
# CCGh58RDN3kyvrXnnCxMvEMpmY4w06wh4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc
# 053y/0QMRGby0uO9RgAabQK6JV2NoTFR3VRGHE3bmZbvGhwEXKYV73jgef5d2z6q
# TFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvd
# OxOPEoziQRpIenOgd2nHtlx/gsge/lgbKCuobK1ebcAF0nu364D+JTf+AptorEJd
# w+71zNzwUHXSNmmc5nsE324GabbeCglIWYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ
# 4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Qv4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4Z
# sRg01Uyduu33H68klQR4qAO77oHl2l98i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3
# nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU4fVmR3l31VRbH60kN8tFWk6gREjI2LCZ
# xRWECfbWSUnAZbjmGnFuoKjxguhFPmzWAtcKZ4MFWsmkEDGCA0kwggNFAgEBMG8w
# WzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNV
# BAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb
# 6t7ITWuP92w6ny4BJBYwCwYJYIZIAWUDBAIBoIIBLTAaBgkqhkiG9w0BCQMxDQYL
# KoZIhvcNAQkQAQQwKwYJKoZIhvcNAQk0MR4wHDALBglghkgBZQMEAgGhDQYJKoZI
# hvcNAQELBQAwLwYJKoZIhvcNAQkEMSIEIDYAxXYzm01z6bKmcg3TuPI0046eFlXN
# WzIfWhRnYh2kMIGwBgsqhkiG9w0BCRACLzGBoDCBnTCBmjCBlwQgOoh6lRteuSpe
# 4U9su3aCN6VF0BBb8EURveJfgqkW0egwczBfpF0wWzELMAkGA1UEBhMCQkUxGTAX
# BgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExMTAvBgNVBAMTKEdsb2JhbFNpZ24gVGlt
# ZXN0YW1waW5nIENBIC0gU0hBMzg0IC0gRzQCEAGb6t7ITWuP92w6ny4BJBYwDQYJ
# KoZIhvcNAQELBQAEggGA1jl0VOWFXI6hlH9GFT5zlklpKlp+mVz3cbrb/leAM0Dj
# OzD7Fr++Pyj9eNEvpoT8jksoU1pdHidWeEptx0YsQhHq2C/jAQ5cyB0JJ0MIs3lp
# aFwWpPfEJTcmRhQXLCAeSfUwUF0fVJGCfbbDAWtiz2XkzpiO2WFJtNyjHIRp74SJ
# v8B0yeB7ovwktEt1wjksPAb2Ir6BuUUPr0maz+an6TX2ish+8Qvomr3xE08FW4J7
# RJ2xwG9evYOY/NMSvNIEyd5IHC0LRDJT477sLjU/NWZNbhPobxEobYxSIvEYgVhW
# zB+xY1FPvhV/NQ8UrBKOg3Hanv5g4LUKMinz5L8xb0gWStPvbOGud9027sSw7tG+
# k3Mz60jzAFY3HRKqhOOJ+briWvJR4cEvzKOdShdn5FIxIn0m3GfGjREBYa21ti1J
# GpgwOVAho1eQnMqzdLr+kI6cODgBu4I5AzUQlQobSE9cR93KlXzN02yknEE4Wsqj
# w38pyLsXY08UjsIiCwkQ
# SIG # End signature block
