#Requires -Version 4.0
#Requires -RunAsAdministrator

<#
    Copyright (c) Alya Consulting, 2022

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
	$check = (Get-Content -Path "$reportDir\sfcscan.txt" -Encoding UTF8 -Raw).Replace("`0", "")
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
	$check = Get-Content -Path "$reportDir\dismScanHealth.txt" -Encoding UTF8 -Raw
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
	$check = Get-Content -Path "$reportDir\dismCheckHealth.txt" -Encoding UTF8 -Raw
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
$sysInfo = Get-Content -Path "$reportDir\systeminfo.txt" -Encoding UTF8
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
	$firstServices = Get-Content -Path "$firstReportDir\services.txt" -Encoding utf8
	$firstProcesses = Get-Content -Path "$firstReportDir\processes.txt" -Encoding utf8
	$actualServices = Get-Content -Path "$reportDir\services.txt" -Encoding utf8
	$actualProcesses = Get-Content -Path "$reportDir\processes.txt" -Encoding utf8

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
		$movedRoles = Get-Content -Path "$firstReportDir\domainControllerRolesMoved.txt" -Encoding UTF8 -ErrorAction SilentlyContinue
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
