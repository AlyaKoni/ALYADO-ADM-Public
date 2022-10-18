#Requires -Version 2.0
#Requires -RunAsAdministrator

<#
    Copyright (c) Alya Consulting, 2019-2021

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
    Date       Author     Description
    ---------- -------------------- ----------------------------
    13.03.2019 Konrad Brunner       Initial Version


ATTENTION:
MFA is not yet supported. You need user credentials without MFA enabled!


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

    #Reading configuration
    . $PSScriptRoot\..\..\01_ConfigureEnv.ps1

    #Starting Transscript
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
            if (-not $global:checkedOut.Contains($spUrl)) { $tmp = $global:checkedOut.Add($spUrl) }
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
                            $tmp = $parentFolder.Folders.Add($dir)
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
        if ($global:checkedOut.Contains($spUrl)) { $tmp = $global:checkedOut.Remove($spUrl) }
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
            if (-not $global:checkedOut.Contains($spUrl)) { $tmp = $global:checkedOut.Add($spUrl) }
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
        if ($global:checkedOut.Contains($spUrl)) { $tmp = $global:checkedOut.Remove($spUrl) }
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
                $folderNames = $parentFolder.Folders | Select -ExpandProperty Name
                if($folderNames -notcontains $folderNames)
                {
                    $tmp = $parentFolder.Folders.Add($dir)
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
            $tmp = Register-ObjectEvent $global:fsw Created -SourceIdentifier "FileCreated-$($global:regGuid)" -Action {
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
            $tmp = Register-ObjectEvent $global:dsw Created -SourceIdentifier "DirectoryCreated-$($global:regGuid)" -Action {
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
            $tmp = Register-ObjectEvent $global:fsw Deleted -SourceIdentifier "FileDeleted-$($global:regGuid)" -Action {
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
            $tmp = Register-ObjectEvent $global:dsw Deleted -SourceIdentifier "DirectoryDeleted-$($global:regGuid)" -Action {
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
            $tmp = Register-ObjectEvent $global:fsw Renamed -SourceIdentifier "FileRenamed-$($global:regGuid)" -Action {
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
            $tmp = Register-ObjectEvent $global:dsw Renamed -SourceIdentifier "DirectoryRenamed-$($global:regGuid)" -Action {
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
            $tmp = Register-ObjectEvent $global:fsw Changed -SourceIdentifier "FileChanged-$($global:regGuid)" -Action {
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
            $tmp = Register-ObjectEvent $global:fsw Error -SourceIdentifier "FileError-$($global:regGuid)" -Action {
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

    
    #Stopping Transscript
    Stop-Transcript

} | Out-Null
