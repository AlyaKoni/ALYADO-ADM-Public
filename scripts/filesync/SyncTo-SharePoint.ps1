#Requires -Version 2.0
#Requires -RunAsAdministrator

<#
    Copyright (c) Alya Consulting, 2019-2026

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
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
    13.03.2019 Konrad Brunner       Initial Version


ATTENTION:
MFA is not yet supported. You need user credentials without MFA enabled!

    06.02.2026 Konrad Brunner       Added powershell documentation

#>

<#
.SYNOPSIS
Synchronizes a local folder with a SharePoint document library or catalog, monitoring local file system changes in real-time and reflecting them on SharePoint.

.DESCRIPTION
The SyncTo-SharePoint.ps1 script establishes synchronization between a specified local folder and a SharePoint site, either On-Premises or Online. It monitors the local file system using FileSystemWatcher, automatically uploading, deleting, renaming, and managing folders and files based on local changes. The script supports document libraries or catalogs such as the Master Page Gallery. It performs SharePoint authentication using stored or prompted credentials (non-MFA) and leverages CSOM libraries for performing SharePoint operations. The script logs activities and provides commands for manually managing watchers and check-ins.

.PARAMETER syncType
Specifies the SharePoint target type. Valid values are OnPremises or Online.

.PARAMETER srcFolder
Specifies the local source folder to be synchronized with SharePoint.

.PARAMETER siteUrl
Specifies the full URL of the SharePoint site.

.PARAMETER docLibName
Specifies the name of the SharePoint document library to synchronize with.

.PARAMETER catalogName
Specifies the name of the SharePoint catalog to synchronize with. Supported value: masterpage.

.PARAMETER fileFilter
Specifies a file name pattern to include during synchronization. Default is '*'.

.PARAMETER dirFilter
Specifies a directory name pattern to include during synchronization. Default is '*'.

.INPUTS
None. You cannot pipe input to this script.

.OUTPUTS
None. The script creates a background file system monitor and outputs status messages to the console and log files.

.EXAMPLE
PS> .\SyncTo-SharePoint.ps1 -syncType Online -siteUrl "https://tenant.sharepoint.com/sites/Example" -docLibName "Documents" -srcFolder "C:\LocalFiles"

.NOTES
Copyright          : (c) Alya Consulting, 2019-2026
Author             : Konrad Brunner
License            : GNU General Public License v3.0 or later (https://www.gnu.org/licenses/gpl-3.0.txt)
Base Configuration : https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration.
#>

[CmdletBinding()] 
Param  
(
    [Parameter(Mandatory=$true)]
    [ValidateSet("OnPremises","Online")] 
    [string]$syncType,
    [Parameter(Mandatory=$false)]
    [string]$srcFolder,
    [Parameter(Mandatory=$false)]
    [string]$siteUrl,
    [Parameter(Mandatory=$false, ParameterSetName="doclib")]
    [string]$docLibName,
    [Parameter(Mandatory=$false, ParameterSetName="catalog")]
    [ValidateSet('masterpage')]
    [string]$catalogName,
    [Parameter(Mandatory=$false)]
    [string]$fileFilter = "*",
    [Parameter(Mandatory=$false)]
    [string]$dirFilter = "*"
)

$global:syncType = $syncType
$global:srcFolder = $srcFolder
$global:siteUrl = $siteUrl
$global:docLibName = $docLibName
$global:catalogName = $catalogName
$global:fileFilter = $fileFilter
$global:dirFilter = $dirFilter
$global:paramSetName = $PSCmdlet.ParameterSetName


#Exporting dynamic module
New-Module -Script {

    # Reading configuration
    . $PSScriptRoot\..\..\01_ConfigureEnv.ps1

    # Starting Transcript
    Start-Transcript -Path "$($AlyaLogs)\scripts\filesync\SyncTo-SharePoint-$($AlyaTimeString).log" | Out-Null

    # Members
    if ([string]::IsNullOrEmpty($global:siteUrl)) { 
        if ($global:syncType -eq "Online")
        {
            $global:siteUrl = $defaultOnlineWebAppUrl
        }
        else
        {
            $global:siteUrl = $defaultOnPremWebAppUrl
        }
    }
    if ($global:paramSetName -eq "doclib")
    {
        $dstUrl = "$global:siteUrl/$global:docLibName"
        $dirName = $global:docLibName.Replace(" ","")
        if ([string]::IsNullOrEmpty($global:srcFolder)) { $global:srcFolder = "$($AlyaData)\sharepoint\SpFileSync\$($global:syncType)\$($dirName)" }
    }
    else
    {
        if ($global:paramSetName -eq "catalog")
        {
            $dstUrl = "$global:siteUrl/_catalogs/$global:catalogName"
            if ([string]::IsNullOrEmpty($global:srcFolder)) { $global:srcFolder = "$($AlyaData)\sharepoint\SpFileSync\$($global:syncType)\$($global:catalogName)" }
            if ($global:catalogName.ToLower() -eq "masterpage")
            {
                $global:docLibName = "Master Page Gallery"
            }
        }
        else
        {
            throw "Please use at least one of the parameters docLibName or catalogName"
        }
    }

    #Preparing directories
    if (-Not (Test-Path -Path $global:srcFolder -PathType Container))
    {
        New-Item -ItemType Directory -Force -Path $global:srcFolder
    }
    Write-Host "Syncing directory $($global:srcFolder)"
    Write-Host "               to $($dstUrl)"

    # Adding csom types
    if ($global:syncType -eq "Online")
    {
        Install-PackageIfNotInstalled "Microsoft.SharePointOnline.CSOM"
        Add-Type -Path "$($AlyaTools)\Packages\Microsoft.SharePointOnline.CSOM\lib\net45\Microsoft.SharePoint.Client.dll"
        Add-Type -Path "$($AlyaTools)\Packages\Microsoft.SharePointOnline.CSOM\lib\net45\Microsoft.SharePoint.Client.Runtime.dll"
    }
    else
    {
        Install-PackageIfNotInstalled "Microsoft.SharePoint$($AlyaSharePointOnPremVersion).CSOM"
        Add-Type -Path "$($AlyaTools)\Packages\Microsoft.SharePoint$($AlyaSharePointOnPremVersion).CSOM\lib\net45\Microsoft.SharePoint.Client.dll"
        Add-Type -Path "$($AlyaTools)\Packages\Microsoft.SharePoint$($AlyaSharePointOnPremVersion).CSOM\lib\net45\Microsoft.SharePoint.Client.Runtime.dll"
    }

    $global:regGuid = [guid]::NewGuid()
    [System.Collections.ArrayList]$global:checkedOut = @()
    [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Login
    Write-Host "Login to SharePoint site: $($global:siteUrl)"
    #TODO MFA enabled login
    if (-not $global:credLS4D) { $global:credLS4D = Get-Credential -Message "Enter Sharepoint $($global:syncType) password:" }
    if ($global:syncType -eq "Online")
    {
        $creds = New-Object Microsoft.SharePoint.Client.SharePointOnlineCredentials($global:credLS4D.UserName, $global:credLS4D.Password)
    }
    else
    {
        $creds = New-Object Microsoft.SharePoint.Client.SharePointCredentials($global:credLS4D.UserName, $global:credLS4D.Password)
    }
    $ctx = New-Object Microsoft.SharePoint.Client.ClientContext($global:siteUrl)
    $ctx.credentials = $creds
    $ctx.load($ctx.Web)
    $docLib = $ctx.Web.Lists.GetByTitle($global:docLibName)
    $ctx.Load($docLib)
    $ctx.Load($docLib.RootFolder)
    $ctx.executeQuery()

    # Functions
    function Handle-Upload($eventArgs)
    {
        try
        {
            $path = $eventArgs.SourceEventArgs.FullPath
            if (Test-Path $path -pathType container) { break }
            #$name = $eventArgs.SourceEventArgs.Name
            $changeType = $eventArgs.SourceEventArgs.ChangeType
            $timeStamp = $eventArgs.TimeGenerated
            $relPath = $path.substring($global:srcFolder.length, $path.length-$global:srcFolder.length)
            $relUrl = $relPath.replace("\", "/")
            Write-Host "The file '$relPath' was $changeType at $timeStamp" -ForegroundColor $accentColor
            Write-Host "  Checking existing file"
            $scope = New-Object Microsoft.SharePoint.Client.ExceptionHandlingScope -ArgumentList @(,$ctx)
            $scopeStart = $scope.StartScope()
            $scopeTry = $scope.StartTry()
            $spUrl = ($dstUrl.Trim("/") + "/" + $relUrl.Trim("/")).Replace($global:siteUrl, "")
            if (-not $global:checkedOut.Contains($spUrl)) { $null = $global:checkedOut.Add($spUrl) }
            $file = $ctx.Web.GetFileByServerRelativeUrl($spUrl)
            $ctx.Load($file)
            $ctx.Load($file.ListItemAllFields)
            $scopeTry.Dispose()
            $scopeCatch = $scope.StartCatch()
            $scopeCatch.Dispose()
            $scopeStart.Dispose()
            $ctx.ExecuteQuery()
            if ($file.Exists)
            {
                if ($file.CheckOutType -eq "None")
                {
                    Write-Host "  Checkout file"
                    $file.CheckOut()
                    $ctx.ExecuteQuery()
                }
            }
            else
            {
                Write-Host "  Checking folders"
                $fileDir = Split-Path -parent $path
                if ($fileDir.length -gt $global:srcFolder.length)
                {
                    $relDir = $fileDir.substring($global:srcFolder.length+1, $fileDir.length-$global:srcFolder.length-1)
                    $dirs = $relDir.Split("\")
                    $relDir = $dstUrl
                    foreach($dir in $dirs)
                    {
                        #TODO how to cleanup created folders?
                        $parentFolder = $ctx.Web.GetFolderByServerRelativeUrl($relDir)
                        $ctx.Load($parentFolder)
                        $ctx.Load($parentFolder.Folders)
                        $ctx.ExecuteQuery()
                        $folderNames = $parentFolder.Folders | Select-Object -ExpandProperty Name
                        if($folderNames -notcontains $folderNames)
                        {
                            $null = $parentFolder.Folders.Add($dir)
                            $ctx.ExecuteQuery()
                        }
                        $relDir = $relDir + "/" + $dir
                    }
                }
            }
            Write-Host "  Uploading the file"
            $fileStream = New-Object IO.FileStream($path, "Open", "Read", "Read")
            $fileCreationInfo = New-Object Microsoft.SharePoint.Client.FileCreationInformation
            $fileCreationInfo.Overwrite = $true
            $fileCreationInfo.ContentStream = $fileStream
            $fileCreationInfo.URL = $spUrl
            $file = $docLib.RootFolder.Files.Add($fileCreationInfo)
            $ctx.Load($file)
            $ctx.Load($file.ListItemAllFields)
            $ctx.ExecuteQuery()
            $fileStream.Close()
            Write-Host "  Done"
        }
        finally
        {
            if ($fileStream) { $fileStream.Close() }
        }
    }

    function Handle-FileRename($eventArgs)
    {
        $path = $eventArgs.SourceEventArgs.FullPath
        $oldpath = $eventArgs.SourceEventArgs.OldFullPath
        $name = $eventArgs.SourceEventArgs.Name
        $oldname = $eventArgs.SourceEventArgs.OldName
        $changeType = $eventArgs.SourceEventArgs.ChangeType
        $timeStamp = $eventArgs.TimeGenerated
        Write-Host "The file '$oldname' was $changeType to '$name' at $timeStamp" -ForegroundColor $accentColor
        Write-Host "  Moving file"
        $relPath = $oldpath.substring($global:srcFolder.length, $oldpath.length-$global:srcFolder.length)
        $relUrlOld = $relPath.replace("\", "/")
        $relPath = $path.substring($global:srcFolder.length, $path.length-$global:srcFolder.length)
        $relUrlNew = $relPath.replace("\", "/")
        $scope = New-Object Microsoft.SharePoint.Client.ExceptionHandlingScope -ArgumentList @(,$ctx)
        $scopeStart = $scope.StartScope()
        $scopeTry = $scope.StartTry()
        $spUrl = ($dstUrl.Trim("/") + "/" + $relUrlOld.Trim("/")).Replace($global:siteUrl, "")
        if ($global:checkedOut.Contains($spUrl)) { $null = $global:checkedOut.Remove($spUrl) }
        $file = $ctx.Web.GetFileByServerRelativeUrl($spUrl)
        $ctx.Load($file)
        $ctx.Load($file.ListItemAllFields)
        $scopeTry.Dispose()
        $scopeCatch = $scope.StartCatch()
        $scopeCatch.Dispose()
        $scopeStart.Dispose()
        $ctx.ExecuteQuery()
        if ($file.Exists)
        {
            $spUrl = ($dstUrl.Trim("/") + "/" + $relUrlNew.Trim("/")).Replace($global:siteUrl, "")
            if (-not $global:checkedOut.Contains($spUrl)) { $null = $global:checkedOut.Add($spUrl) }
            $file.MoveTo($spUrl, [Microsoft.SharePoint.Client.MoveOperations]::Overwrite)
            $ctx.ExecuteQuery()
            Write-Host "  Moved"
        }
    }

    function Handle-FileDelete($eventArgs)
    {
        $path = $eventArgs.SourceEventArgs.FullPath
        $changeType = $eventArgs.SourceEventArgs.ChangeType
        $timeStamp = $eventArgs.TimeGenerated
        $relPath = $path.substring($global:srcFolder.length, $path.length-$global:srcFolder.length)
        $relUrl = $relPath.replace("\", "/")
        Write-Host "The file '$relPath' was $changeType at $timeStamp" -ForegroundColor $errorColor
        Write-Host "  Deleting file"
        $spUrl = ($dstUrl.Trim("/") + "/" + $relUrl.Trim("/")).Replace($global:siteUrl, "")
        $file = $ctx.Web.GetFileByServerRelativeUrl($spUrl)
        $file.DeleteObject()
        $ctx.ExecuteQuery()
        if ($global:checkedOut.Contains($spUrl)) { $null = $global:checkedOut.Remove($spUrl) }
        Write-Host "  Done"
    }

    function Handle-CreateDirectory($eventArgs)
    {
        $path = $eventArgs.SourceEventArgs.FullPath
        #$name = $eventArgs.SourceEventArgs.Name
        $changeType = $eventArgs.SourceEventArgs.ChangeType
        $timeStamp = $eventArgs.TimeGenerated
        $relPath = $path.substring($global:srcFolder.length, $path.length-$global:srcFolder.length)
        Write-Host "The directory '$relPath' was $changeType at $timeStamp" -ForegroundColor $accentColor
        Write-Host "  Creating directory"
        $fileDir = $path
        if ($fileDir.length -gt $global:srcFolder.length)
        {
            $relDir = $fileDir.substring($global:srcFolder.length+1, $fileDir.length-$global:srcFolder.length-1)
            $dirs = $relDir.Split("\")
            $relDir = $dstUrl
            foreach($dir in $dirs)
            {
                #TODO how to cleanup created folders?
                $parentFolder = $ctx.Web.GetFolderByServerRelativeUrl($relDir)
                $ctx.Load($parentFolder)
                $ctx.Load($parentFolder.Folders)
                $ctx.ExecuteQuery()
                $folderNames = $parentFolder.Folders | Select-Object -ExpandProperty Name
                if($folderNames -notcontains $folderNames)
                {
                    $null = $parentFolder.Folders.Add($dir)
                    $ctx.ExecuteQuery()
                }
                $relDir = $relDir + "/" + $dir
            }
        }
        Write-Host "  Done"
    }

    function Handle-DirectoryDelete($eventArgs)
    {
        $path = $eventArgs.SourceEventArgs.FullPath
        $changeType = $eventArgs.SourceEventArgs.ChangeType
        $timeStamp = $eventArgs.TimeGenerated
        $relPath = $path.substring($global:srcFolder.length, $path.length-$global:srcFolder.length)
        $relUrl = $relPath.replace("\", "/")
        Write-Host "The directory '$relPath' was $changeType at $timeStamp" -ForegroundColor $errorColor
        Write-Host "  Deleting directory"
        $spUrl = ($dstUrl.Trim("/") + "/" + $relUrl.Trim("/")).Replace($global:siteUrl, "")
        $folder = $ctx.Web.GetFolderByServerRelativeUrl($spUrl)
        $folder.DeleteObject()
        $ctx.ExecuteQuery()
        Write-Host "  Done"
    }

    function Handle-DirectoryRename($eventArgs)
    {
        $path = $eventArgs.SourceEventArgs.FullPath
        $oldpath = $eventArgs.SourceEventArgs.OldFullPath
        $name = $eventArgs.SourceEventArgs.Name
        $oldname = $eventArgs.SourceEventArgs.OldName
        $changeType = $eventArgs.SourceEventArgs.ChangeType
        $timeStamp = $eventArgs.TimeGenerated
        Write-Host "The folder '$oldname' was $changeType to '$name' at $timeStamp" -ForegroundColor $accentColor
        Write-Host "  Renaming folder"
        $relPath = $oldpath.substring($global:srcFolder.length, $oldpath.length-$global:srcFolder.length)
        $relUrlOld = $relPath.replace("\", "/")
        $scope = New-Object Microsoft.SharePoint.Client.ExceptionHandlingScope -ArgumentList @(,$ctx)
        $scopeStart = $scope.StartScope()
        $scopeTry = $scope.StartTry()
        $spUrl = ($dstUrl.Trim("/") + "/" + $relUrlOld.Trim("/")).Replace($global:siteUrl, "")
        $folder = $ctx.Web.GetFolderByServerRelativeUrl($spUrl)
        $ctx.Load($folder)
        $ctx.Load($folder.ListItemAllFields)
        $scopeTry.Dispose()
        $scopeCatch = $scope.StartCatch()
        $scopeCatch.Dispose()
        $scopeStart.Dispose()
        $ctx.ExecuteQuery()
        if ($folder.Exists)
        {
            $folderItem = $folder.ListItemAllFields
            $name = Split-Path -Path $path -Leaf
            $folderItem["Title"] = $name
            $folderItem["FileLeafRef"] = $name
            $folderItem.Update()
            $ctx.ExecuteQuery()
        }
    }

    function Reset-Watcher()
    {
        Write-Host "Reset"
        $global:fsw.EnableRaisingEvents = $false
        for( $attempt = 1; $attempt -le 120; $attempt++ )
        {
            try
            {
                $global:fsw.EnableRaisingEvents = $true
                Write-Error "FileSystemWatcher reactivated" -ErrorAction Continue
                break
            }
            catch
            {
                Start-Sleep -Seconds 1
            }
        }
        if ($attempt -ge 120)
        {
            throw "Was not able to reactivate FileSystemWatcher, giving up"
        }
    }

    function Handle-Error($eventArgs)
    {
        Write-Error "FileSystemWatcher Error" -ErrorAction Continue
        #TODO error message
        Reset-Watcher
    }

    function Checkin
    {
        Write-Host "File checkin" -ForegroundColor $informationColor
        foreach($spUrl in $global:checkedOut)
        {
            $file = $ctx.Web.GetFileByServerRelativeUrl($spUrl)
            $file.CheckIn("Checked in by FileSystemWatcher",[Microsoft.SharePoint.Client.CheckinType]::MinorCheckIn)
            $ctx.ExecuteQuery()
        }
        [System.Collections.ArrayList]$global:checkedOut = @()
        Write-Host "  Done"
    }

    function CheckinAndPublish
    {
        Write-Host "File checkin and publish" -ForegroundColor $informationColor
        foreach($spUrl in $global:checkedOut)
        {
            $file = $ctx.Web.GetFileByServerRelativeUrl($spUrl)
            $file.CheckIn("Checked in by FileSystemWatcher",[Microsoft.SharePoint.Client.CheckinType]::MajorCheckIn)
            $ctx.ExecuteQuery()
        }
        [System.Collections.ArrayList]$global:checkedOut = @()
        Write-Host "  Done"
    }

    function Unregister
    {
        Write-Host "Unregistering watchers" -ForegroundColor $informationColor
        Unregister-Event "FileCreated-$($global:regGuid)" -ErrorAction SilentlyContinue
        Unregister-Event "FileDeleted-$($global:regGuid)" -ErrorAction SilentlyContinue
        Unregister-Event "FileChanged-$($global:regGuid)" -ErrorAction SilentlyContinue
        Unregister-Event "FileRenamed-$($global:regGuid)" -ErrorAction SilentlyContinue
        Unregister-Event "FileError-$($global:regGuid)" -ErrorAction SilentlyContinue
        Unregister-Event "DirectoryDeleted-$($global:regGuid)" -ErrorAction SilentlyContinue
        Unregister-Event "DirectoryCreated-$($global:regGuid)" -ErrorAction SilentlyContinue
        Unregister-Event "DirectoryRenamed-$($global:regGuid)" -ErrorAction SilentlyContinue
        Write-Host "  Done"
    }

    function Reregister
    {
        Unregister
        Register
    }

    function Register
    {
        Write-Host "Registering on"
        Write-Host "  '$($global:srcFolder)'"
        Write-Host "a FileSystemWatcher for"
        Write-Host "  - file changes with filter '$($global:fileFilter)'" 
        Write-Host "  - directory changes with filter '$($global:dirFilter)'" 
        try
        {
            $global:fsw = New-Object IO.FileSystemWatcher "$global:srcFolder", $global:fileFilter -Property @{IncludeSubdirectories = $true; NotifyFilter = [IO.NotifyFilters]'FileName, LastWrite'}
            $global:dsw = New-Object IO.FileSystemWatcher "$global:srcFolder", $global:dirFilter -Property @{IncludeSubdirectories = $true; NotifyFilter = [IO.NotifyFilters]'DirectoryName'}

            Write-Host "Registering FileCreated-$($global:regGuid)"
            $null = Register-ObjectEvent $global:fsw Created -SourceIdentifier "FileCreated-$($global:regGuid)" -Action {
                try
                {
                    Handle-Upload $Event
                }
                catch
                {
                    Write-Error "Exception in FileSystemWatcher event: FileCreated" -ErrorAction Continue
                    Write-Host "ItemName: $($_.Exception.ItemName), Message: $($_.Exception.Message), InnerException: $($_.Exception.InnerException), ErrorRecord: $($_.Exception.ErrorRecord), StackTrace: $($_.Exception.StackTrace)"
                }
            }

            Write-Host "Registering DirectoryCreated-$($global:regGuid)"
            $null = Register-ObjectEvent $global:dsw Created -SourceIdentifier "DirectoryCreated-$($global:regGuid)" -Action {
                try
                {
                    Handle-CreateDirectory $Event
                }
                catch
                {
                    Write-Error "Exception in FileSystemWatcher event: DirectoryCreated" -ErrorAction Continue
                    Write-Host "ItemName: $($_.Exception.ItemName), Message: $($_.Exception.Message), InnerException: $($_.Exception.InnerException), ErrorRecord: $($_.Exception.ErrorRecord), StackTrace: $($_.Exception.StackTrace)"
                }
            }

            Write-Host "Registering FileDeleted-$($global:regGuid)"
            $null = Register-ObjectEvent $global:fsw Deleted -SourceIdentifier "FileDeleted-$($global:regGuid)" -Action {
                try
                {
                    Handle-FileDelete $Event
                }
                catch
                {
                    Write-Error "Exception in FileSystemWatcher event: FileDeleted" -ErrorAction Continue
                    Write-Host "ItemName: $($_.Exception.ItemName), Message: $($_.Exception.Message), InnerException: $($_.Exception.InnerException), ErrorRecord: $($_.Exception.ErrorRecord), StackTrace: $($_.Exception.StackTrace)"
                }
            }

            Write-Host "Registering DirectoryDeleted-$($global:regGuid)"
            $null = Register-ObjectEvent $global:dsw Deleted -SourceIdentifier "DirectoryDeleted-$($global:regGuid)" -Action {
                try
                {
                    Handle-DirectoryDelete $Event
                }
                catch
                {
                    Write-Error "Exception in FileSystemWatcher event: DirectoryDelete" -ErrorAction Continue
                    Write-Host "ItemName: $($_.Exception.ItemName), Message: $($_.Exception.Message), InnerException: $($_.Exception.InnerException), ErrorRecord: $($_.Exception.ErrorRecord), StackTrace: $($_.Exception.StackTrace)"
                }
            }

            Write-Host "Registering FileRenamed-$($global:regGuid)"
            $null = Register-ObjectEvent $global:fsw Renamed -SourceIdentifier "FileRenamed-$($global:regGuid)" -Action {
                try
                {
                    Handle-FileRename $Event
                }
                catch
                {
                    Write-Error "Exception in FileSystemWatcher event: FileRenamed" -ErrorAction Continue
                    Write-Host "ItemName: $($_.Exception.ItemName), Message: $($_.Exception.Message), InnerException: $($_.Exception.InnerException), ErrorRecord: $($_.Exception.ErrorRecord), StackTrace: $($_.Exception.StackTrace)"
                }
            }

            Write-Host "Registering DirectoryRenamed-$($global:regGuid)"
            $null = Register-ObjectEvent $global:dsw Renamed -SourceIdentifier "DirectoryRenamed-$($global:regGuid)" -Action {
                try
                {
                    Handle-DirectoryRename $Event
                }
                catch
                {
                    Write-Error "Exception in FileSystemWatcher event: DirectoryRenamed" -ErrorAction Continue
                    Write-Host "ItemName: $($_.Exception.ItemName), Message: $($_.Exception.Message), InnerException: $($_.Exception.InnerException), ErrorRecord: $($_.Exception.ErrorRecord), StackTrace: $($_.Exception.StackTrace)"
                }
            }

            Write-Host "Registering FileChanged-$($global:regGuid)"
            $null = Register-ObjectEvent $global:fsw Changed -SourceIdentifier "FileChanged-$($global:regGuid)" -Action {
                try
                {
                    Handle-Upload $Event
                }
                catch
                {
                    Write-Error "Exception in FileSystemWatcher event: FileChanged" -ErrorAction Continue
                    Write-Host "ItemName: $($_.Exception.ItemName), Message: $($_.Exception.Message), InnerException: $($_.Exception.InnerException), ErrorRecord: $($_.Exception.ErrorRecord), StackTrace: $($_.Exception.StackTrace)"
                }
            }

            Write-Host "Registering FileError-$($global:regGuid)"
            $null = Register-ObjectEvent $global:fsw Error -SourceIdentifier "FileError-$($global:regGuid)" -Action {
                try
                {
                    Handle-Error $Event
                }
                catch
                {
                    Write-Error "Exception in FileSystemWatcher event: FileError" -ErrorAction Continue
                    Write-Host "ItemName: $($_.Exception.ItemName), Message: $($_.Exception.Message), InnerException: $($_.Exception.InnerException), ErrorRecord: $($_.Exception.ErrorRecord), StackTrace: $($_.Exception.StackTrace)"
                }
            }
        }
        catch
        {
            Write-Error "Exception in registering FileSystemWatcher" -ErrorAction Continue
            Write-Host "ItemName: $($_.Exception.ItemName), Message: $($_.Exception.Message), InnerException: $($_.Exception.InnerException), ErrorRecord: $($_.Exception.ErrorRecord), StackTrace: $($_.Exception.StackTrace)"
        }
    }

    # Register watcher
    Register

    # Show commands
    Write-Host "---------------------------------------------------" -ForegroundColor $informationColor
    Write-Host "Type Unregister to stop watching folders" -ForegroundColor $informationColor
    Write-Host "Type Register to start watching folders again" -ForegroundColor $informationColor
    Write-Host "Type Reregister to stop and start watcher at once" -ForegroundColor $informationColor
    Write-Host "Type Checkin to checkin all your changes" -ForegroundColor $informationColor
    Write-Host "Type CheckinAndPublish to publish all your changes" -ForegroundColor $informationColor
    Write-Host "---------------------------------------------------" -ForegroundColor $informationColor

    # Exports
    Export-ModuleMember -Function Unregister | Out-Null
    Export-ModuleMember -Function Register | Out-Null
    Export-ModuleMember -Function Reregister | Out-Null
    Export-ModuleMember -Function Checkin | Out-Null
    Export-ModuleMember -Function CheckinAndPublish | Out-Null
    Export-ModuleMember -Function Handle-Upload | Out-Null
    Export-ModuleMember -Function Handle-FileRename | Out-Null
    Export-ModuleMember -Function Handle-FileDelete | Out-Null
    Export-ModuleMember -Function Handle-CreateDirectory | Out-Null
    Export-ModuleMember -Function Handle-DirectoryDelete | Out-Null
    Export-ModuleMember -Function Handle-DirectoryRename | Out-Null
    Export-ModuleMember -Function Handle-Error | Out-Null
    Export-ModuleMember -Function Reset-Watcher | Out-Null

    
    # Stopping Transcript
    Stop-Transcript

} | Out-Null

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBpG/OqJoZHj0bS
# s4j6mEOUe3SYM3Gn6HDA/ahJHFhUm6CCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
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
# dgNBzMUxgiEGMIIhAgIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIJxJOv9C
# Ud/Tjybhy1teRKGOodkCfmifVEzMWghBojxBMA0GCSqGSIb3DQEBAQUABIICALy6
# gQQwrCyZhmOfLMiMh708v6A4rnH3OKCoLMVKWVR8lsukmAWf+C7f92O2JISB+WiL
# zz2YCqcU/TeP4KuDCCaNURwpeuIJMV0gS5P30txXOltXmVytx9SNW4XIIaNbbkvX
# rlzdIMqaEsS/mz2+K3Kyl/k9iBvRvLFzNxqCtF9cTNuXnZbawzZIV+XxmKdH6Nmk
# 2ujNqDtU98OPh2d+WP/hUpGj6iA2dHp0TbLf0LPW2pF4VkRRPMm8whc7AEL0TITr
# 3YONQ85z0ESJKJvSIL1xLphHlLKTJJwrQ5OlGu3ws5Qh/3TAy7ysPKMquRhSdf0r
# NCZnOjn3P26KS4rde0JQT6cZvp4cLOlqeDLe3Sw62lwgnF8YQm9+/wG2EfSGSFLC
# OF2pb2UI0mkbqxBvUwP841qTa2WsqW+5icpPfKbkR27DHvvdi9afbyIlJOaNFE+b
# GGWaC8HXqk1zy+/da6j3VCITMpe//cyXIEVVY0IQfx8wd1ARRMs2nI8v1qK6tPC0
# iiCTmKXJnPjXT0iKM5KKLOj1+A2cG7u3mdoJlmm+yVcXtvZQf7W7fclJ0wrju/55
# jMJzAzOWtskDckjgmnWjrnBQhVJN/j3kJyWRi5RViF+Cp1xpoU9eIxpVZLl66/BU
# 6Qi+AxKUl331BTxzzCfKJWd2CHO1wfLOCGYvI4sFoYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCAD+5TzBUbGFJvdq12TYdgDr0nz1A5iPX+98HkYYfljQgIUA9CO
# 6DgTbHooT4G4p5oAZSZuJk8YDzIwMjYwODI5MTUyMjQzWjADAgEBoF2kWzBZMQsw
# CQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMm
# R2xvYmFsc2lnbiBSNDUgVFNBIGZvciBDb2RlU2lnbiAyMDI1MTCgghlgMIIGijCC
# BHKgAwIBAgIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcNAQEMBQAwXjELMAkG
# A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0ds
# b2JhbFNpZ24gT2ZmbGluZSBSNDUgVGltZXN0YW1waW5nIENBIDIwMjUwHhcNMjUx
# MDE1MDcyNTA0WhcNMzcwMTEwMDAwMDAwWjBZMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFsc2lnbiBSNDUgVFNB
# IGZvciBDb2RlU2lnbiAyMDI1MTAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQDRSo2hjYZASCijCQSc2RMQPPKojE/xf4Uija2JnsJ7Snl2gDoxKjQ9HcU6
# rVD8pgy1sBKdVxtLLFhY3gzY/PA2iwIs6ZzCnxshtjShsN1RyzRrzc4Fq+0xQx6q
# ADUMn96mqHE/0ok53DPbmpBkkUDytGM79nQfw9WVymYgA+TkbA0/QOmPNNJIZ6Cj
# X0t3wJfhL0caiXthBBMEWKxT5v2U7ZRbCq/DVDXA9oX1iFVBVaBpx57MLL00nyHu
# x0InYS7Rr54M3tNhm7+0maxpyTFa51uY1PHtTJMup/l3RGooQ5YweCH2hDoUNwKO
# C7QkFbklhPdq27EXkueg8qLOnRDmVO1r+B1yMAbl6QuV0L+OPB1SKBAPpmIFklmJ
# 0SoibbUqxsTzejjdI+ywQLUcXilogwKWsJ46h6wjlU5AVqT7FEBYzWCTt6hf7SLQ
# bPGs02Ba8oaaNfo0SL+aApN94luEB/wuE1lgptrckLzbQlCp56OgkAJYpqYuui+T
# fueCIU0CAwEAAaOCAcYwggHCMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAK
# BggrBgEFBQcDCDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQy+tPhB2gnkGsI0j8d
# PIxlNigGGTAfBgNVHSMEGDAWgBR3AjsBMQ8edHfDSMjDB2NViKU7ojCBpQYIKwYB
# BQUHAQEEgZgwgZUwQgYIKwYBBQUHMAGGNmh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24u
# Y29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNTBPBggrBgEFBQcwAoZDaHR0
# cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NvZmZsaW5lcjQ1dGlt
# ZXN0YW1wY2EyMDI1LmNydDBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLmds
# b2JhbHNpZ24uY29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNS5jcmwwVgYD
# VR0gBE8wTTAIBgZngQwBBAIwQQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0
# dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEB
# DAUAA4ICAQCOrnCmj0eGkYpuniz6/WFm91s6KjnhkMKYlbcftgpMBtlhysVniEOf
# BvhcvoFQw4AOHG9NRVvZpkBnag5Dt1HM3Jg21gRVCBwFyP1ET8IDxoflYx5OD4SC
# NLHs6vCg6rFkNT81v9Zy8u0xXy3WboN5iK/SbTmLGqCrAGJihLLrfIhvddwVrdBy
# iHteLxgjugT6JQogCSoBF2JqmH0ZBCl515btbTuWZLrQUs5vvl2o98Mdju9yyJRW
# LzPVcUkRk9d8xBBi638FBOAuo3fcyThGcne7wUOa+TghhwIHbZ3pxTYpgo5cCxEZ
# sH8EXwiTUTwHf0qesssg/2XdcGH7s0AR4TyOJ2QnAayYOAM/XOBxNzURQg4mhMdP
# L/F8VCMKj3koJaVcx2akh0B82le/aBU8q2Oa++OwOwiHF5e+f9m+yhyYbwGSogWI
# V3hgRl+VyKrch8gv35FHr/cVz8n0/CPGRXGiYJZ7P1wOOgYdkMD2iDKVYQby5Ix/
# xCB0/lSKLnqEoFezfmnCJbGgACVswMsxhJEUjtxEcQc9afalne+IOts0v/yCRikJ
# snmVbS0x50Dk2OH+VCiU9s/XyzgfC7WzrtQ5diIdc2Ksi3JMTJm4a0LiEIZWitD5
# +6PokOkQ8+35TsHOwUhs87I/yyJjlIZpAV4Of1/JN8bWVB3Edm4WzjCCBqAwggSI
# oAMCAQICEQCD2oY3t58MhAyUe4QKUngfMA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNV
# BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9i
# YWxTaWduIFRpbWVzdGFtcGluZyBSb290IFI0NTAeFw0yNTA3MTYwMzA1MDRaFw00
# MTA3MTYwMDAwMDBaMF4xCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTQwMgYDVQQDEytHbG9iYWxTaWduIE9mZmxpbmUgUjQ1IFRpbWVzdGFt
# cGluZyBDQSAyMDI1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApHcW
# +O19i+LdAoZFYzS+5X+WYvnWoFqXAfir1hynhUTdH4RW1Db+yOmrQ275jlsQ6bzo
# Z3nN0CMncZX4E0Qhpp6Qvx27+flpfzeMQacD7VciWUiF3TLiu7wT2bBCSENUn3hf
# GMG4PJvYFvO5o4DA1iNvHhG4oSzctodoJfb4c8EjVahCw/NLizB3ra+NWe2gZBSa
# ZKraMxFt676yqx7RcQnjbF4R0OLGovsZt23vU69A5BdoPxdA9zu9rM+qTBsPDVUJ
# exYwEVU0GY7BJ5mUWWniyAPHW0Wv4Azk5t7I0XUIjA3+2OGkr0dVBXVBDyEeGBVr
# YXEdhfVLwuh6HBGJFdIrEY5KoGlpoT+4BBQe4XCH5sv15Uo+M72VKWjPA5Ex3nfF
# JC4P5FW1SR6olCSaIrtnZzc+zgmpSyiD+GcE2udQRQHbDi74enXgazk0+ktpHZ1Z
# 8oTvSaSIREovXSLbH3KC8uFIkXucl7XPH7ZGIrmF9eF4zuoo5FIUnsvV60kLqFDz
# Pk+UbLmgZDUCPlFFBBehaaNvixEymx9ON2KXev+MfK6OZChqGbrOC2wvvAFHyKlT
# ZbVHdqNiu0u5a2T1C9dSTRny1/hxLwcxL9BWPzQLwhsiyXqUzM7uD0lD9+PYMaxU
# YgoVSxqb4xvPCiVqLNabI+WtjEzYfQ0P+6tBTFsCAwEAAaOCAWIwggFeMA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDASBgNVHRMBAf8ECDAGAQH/
# AgEAMB0GA1UdDgQWBBR3AjsBMQ8edHfDSMjDB2NViKU7ojAfBgNVHSMEGDAWgBRG
# shx34XsV8KU5oXDe0cQu6m2y3jCBjgYIKwYBBQUHAQEEgYEwfzA3BggrBgEFBQcw
# AYYraHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vdGltZXN0YW1wcm9vdHI0NTBE
# BggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# dGltZXN0YW1wcm9vdHI0NS5jcnQwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2Ny
# bC5nbG9iYWxzaWduLmNvbS90aW1lc3RhbXByb290cjQ1LmNybDARBgNVHSAECjAI
# MAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggIBADKj7n7RbuRmMZZYXqlMPRJoR6X1
# n//quXGLVfOpFoR9Ya05L94w0ywBjelyGGf+nAB+CZFQ7gUOd2a2bpfpW8Xw5ArM
# +YjPEf8AtC4E6Yr105U1YNjlTSERoWJKc1hkSN5m4dpsYteFykzFQVwX50hYKH3y
# Z6Vcu6Ha0EA5ofzLpi2jK2jbRDCXbFNLi5mO1xKRdB2AzAF0f5C00b4H3d5sCOB8
# njTvAwaTMGEMeTkLWM4Z9Y+3UOtOpo1QuxXbDpXVkLXraG25iL1VtvjxEAy4534n
# UINB9whORicJJSTLba6fOK2f/1QGWEdewWLHAzE+N5oH0QoNRALpJ5JjIfeInvO+
# sQdBidnPuLKJ95HTj7XyMvJhFZjtbHJGlEWx4UgKcuNKLDLXWALfwQDN2Dey3kTf
# d4yw4nQdk1PctLLK3F4L2nnLv94BMkpY+Rfl53oOEN4yTvtwCYP+VDuZrktc7Nac
# oTVxZnKGkv8a1akckdOwQZC+i8Ay1VyzMAX/Tb4+r3c65B7cpAtq3OoUijXUJgvZ
# xci6TX78smL2TYy2tWn+8G4krnXvy2ELR2XYnKEOS4MVmrSCsjM5nxSrghE10VDX
# QbEfa93lhikfFoIuINKzWDLqvu8ZucmxEufxpHjNnnRVXX/Zv5KQq8pu/MQoOz6D
# C74n5+O5bSwvT5sgMIIGozCCBIugAwIBAgIQeEqqgXNmnJAJVOQhyUfrwDANBgkq
# hkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjET
# MBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMDEy
# MDkwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIFRpbWVzdGFt
# cGluZyBSb290IFI0NTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALp0
# M+wn3BI4IRvF02Eo1lq8T9+LzJGEQyRXvGQhvDscHz1PjK0Ht/PF1wLpERSCmqq0
# lHI7cQ0a72hrhXmOr2bqWJgNusF8edL/zbNvMUXQBXQEAHJqJ364Nz86iO2Xg/Wr
# NU0Pn1k79S/fWcV8pTJ2YJbI7e74BH4ZUXKov0RBerx7HjsAm7y64Ja/kP6Nm8Ny
# iwAS+CA6YDj3wcyFivuHeS6hKyDmy6CFkSO2xCgHVCje7BAxT4ryzRQfHt1VHOoo
# MUz5IWqozfOWZ/oBQZvNDwtof7ve8UPqF+Ww3HAis2k2WXRrxuWJKnzlC4Fdqz+P
# uNF2cvN8oqnil0G/zIxF/mHJ9mwHCwAE6BUjT4IqLfbvw/oRNkih0f16OTo0XaMs
# Dpt3UCA0QN2xAzGtX+lih3OWA2H3lLDZXGxP5xTF4fF7DSOczXCMHWreSi2LKrvb
# QhQFB6r7FNwx0/YfbMu+aGZEcE1tF/lx6wVzjpGSdetoXB72RGEYKWLdF2aI7Ci6
# SW/bPnf+uTEfdRwYoqZHvdjuSIU7/bPiDz8qmMaa+oJvsaWlhh1aOvqkbHQPd1Jh
# an+HKd45m4vus0VgMCSXFRIqhTCTJqyWpi3ocG0LqTKtLJsoCnZC8lVhUZiU3u32
# xRdvPBUQsA6tsN7FFvRl0cwvWlYIz5nE8FWRwix5AgMBAAGjggF4MIIBdDAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDwYDVR0TAQH/BAUwAwEB
# /zAdBgNVHQ4EFgQURrIcd+F7FfClOaFw3tHELuptst4wHwYDVR0jBBgwFoAUrmwF
# o5MT4qLn4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEEbzBtMC4GCCsGAQUFBzABhiJo
# dHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsGAQUFBzAChi9o
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAi0i6Nlc8csXadfnvMvWGvdwSKOOILk82XyaZ7A8BIRCWkjjGcGtt867UDr0l
# 74Z/4omNlaV+KUQDTaqYqPG33OopYyHc7c2ICssQaWF5KUIMI7zpxe9SHi8zN9VP
# ZnpmqUdUM7HdFvLYZHGjMZTlb/ZNS+KEbNDJJWdPyEvQzksF1j37fUH6irHAIeB+
# CLDZZCv56vLHCvTPLgw0YO5su5LwP/F7UhJod1mB9RwupDqMOQMN7eXMr2ZIeWPV
# Sbj/S9IlT0hOkzuTd7CaSGy2oB2zdJ5fvSIEO3w3DYW1w5q73ZxaA420DZ9MdjTV
# ha1Fe7Wfuy6Ju6zIv5JjSMY/yheqDbwAEV+L6ONDhIpDNM39O8Cie9sfuGfIjBXe
# P6Z/xyjvoW9vskHPAiLrAfhLyNJ2byXfXtpoaD17RATCQW5JO6eYVgTt0SYrBJTb
# 5O1mjj2AnaSkVXlQXuP4Gh/AFm+QFTyKpkihDHu6KuCxqYcFRpvtJVU9N2mY7UaZ
# mIVHCh5i2/2c5cFDQo69z2/2jJH9guSf7K3jlVUF80kvbTT3/2fumUC705qAQkDa
# I4lgH4NxkrXp5soK+d3HbLJYQZxmjZsqbx9vVwRDXINdO2mc3jn6hE0183sbbYvx
# bwPBKVLilL97VIvfQHoLcAJ3Py+IBwIAddKvxtYiMhmjO+gwggWDMIIDa6ADAgEC
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
# AtcKZ4MFWsmkEDGCA2EwggNdAgEBMHMwXjELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNpZ24gT2ZmbGluZSBS
# NDUgVGltZXN0YW1waW5nIENBIDIwMjUCEQCEcj/BlcwW8dsrovZg3yvkMAsGCWCG
# SAFlAwQCAqCCAUEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMCsGCSqGSIb3
# DQEJNDEeMBwwCwYJYIZIAWUDBAICoQ0GCSqGSIb3DQEBDAUAMD8GCSqGSIb3DQEJ
# BDEyBDBu6ru02CmgEr657P4cU5jy9EYdUPzuQPXSwiUz6SuPIL8E1YhxkvXd1AoW
# D0v64vIwgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGAtaFVYD9UDeYSFG2RE8Ee61h9s98Xa2XKCcJEaAr3JI0U
# cb6Cr61YbPzFQ1IQfi+cYbB3rY+gSg+5z49xBiPDNPx6K5WxjdBNYAXDkIh+irs7
# 8qB7WJoLSqP8VECzL+YALBrmj1B8wumjnGWUv3JERqVLpwkwo9WsmTRlgWqI1e8R
# t7EvK3LTEor9Ba1coy5jTM3yQXjU3RL0GEWfov6DGUVA9wgrDCIHedAs/g7uHU4A
# clUcYOrGO4yzwHpe+XoKHIy9r9LtxfubvsmMahQUxzEILVkG1oz2iQL/9zm09OYj
# +1WU6y/FKJoL8F33IN/klJ+6J9EGRBfnTY4XqkfYLCfPNAMAkMQh0lKnxSSXkE8a
# KZioXTUOE5aohZP+oaTuCPUoLOppJjyXMITaiklbi38jhlqCpPms3R87dVlD9Cny
# bV47J8NecN1i1mEe8SsYOVyBvKiaoFsr+nb6P37LvMNkntrPo+A3Cqkol9RS7elw
# JtkrmKB3rbgzAXboxPLM
# SIG # End signature block
