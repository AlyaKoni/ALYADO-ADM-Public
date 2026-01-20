#Requires -Version 2.0
#Requires -RunAsAdministrator

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

    
    #Stopping Transscript
    Stop-Transcript

} | Out-Null

# SIG # Begin signature block
# MIIpYwYJKoZIhvcNAQcCoIIpVDCCKVACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDGBmtThKPI8IyN
# 2lwbnCNOGehus+uyEr5RIwKmiUvk/KCCDuUwggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIIFoySkgqJz8wbJH
# bmsQm23frJLr+ExaUqJKCQclq9hOMA0GCSqGSIb3DQEBAQUABIICAEDPRv3Y41iO
# DrSFw8edJR0SclvxTwsFXvaoC2eAkVf7DxKGhWXgh1SVIEf7hY4me+Q+TwfcQ5Mb
# qg1zGmp7f/KbWZGMhLt+WXJbFtD3Iq3MylyvuD3s98T44x/1kk1tuRG073M1TCUD
# LzcpxT/XOIbSj/hcYY/sFBaSrWebUvCFdBFZVomlx/UMLFEgpvK+JLMVwDrFMiu3
# BNIDSuiMZLKNJn61F1oM9C8FolqyYN3K54rvAJPCrgq+alI3UCeHGvwXUiA1nrNo
# t/nti0ftImtt8NMix54iGqy5DBs9gh5+yyfgw5SonpoRURPIV1wDBLLaXP+PVKq3
# +ewKTKSi5u4bDAOMjVV+JuJltBmmNULJogRfebErt70PbzvWZQ9XkZyeHfEhdM0g
# UiDhT4VCIuY/mYvvxHqIskzbxoTJ7LKoyv2D5M5WNwttby0odsycMHVPTGGsXz9H
# rEko0JUY6TMUPl1t2DqwBG5q4UomT09ruWnKOtxVfXLKE9JIjS03yVVb3dqtkkPb
# RZDd05l3m8cpfM9Z+BBwvLapq5Ms2OCqSMZSOaPsbfIYF3b0ANXTZ/mxojTiMIRy
# Erg+Civtqkz+ejjCJDPJU+5WBHKr3MYg8pwRIydECrFAF3TfbtWc0+Irsj0KA9JS
# 7OCSkxqvhGj7lODCeOIUPvl5W/7HoZlboYIWuzCCFrcGCisGAQQBgjcDAwExghan
# MIIWowYJKoZIhvcNAQcCoIIWlDCCFpACAQMxDTALBglghkgBZQMEAgEwgd8GCyqG
# SIb3DQEJEAEEoIHPBIHMMIHJAgEBBgsrBgEEAaAyAgMBAjAxMA0GCWCGSAFlAwQC
# AQUABCBU+fiGsdzhKaIzf4xzg1yr4QKG9n9F5vaYnJPeCJYH8AIUfYFeZnJ9GxiN
# vwlbSDWxvlgmIKEYDzIwMjYwMTIwMDk1MzQ5WjADAgEBoFikVjBUMQswCQYDVQQG
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
# IHUSMDPMaUy8D9xVIkeCv6OYXHDglAyqZlARJnIkPxqgMIGwBgsqhkiG9w0BCRAC
# LzGBoDCBnTCBmjCBlwQgcl7yf0jhbmm5Y9hCaIxbygeojGkXBkLI/1ord69gXP0w
# czBfpF0wWzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2Ex
# MTAvBgNVBAMTKEdsb2JhbFNpZ24gVGltZXN0YW1waW5nIENBIC0gU0hBMzg0IC0g
# RzQCEAEACyAFs5QHYts+NnmUm6kwDQYJKoZIhvcNAQELBQAEggGAh3k/L1u4d/zW
# 9CIIpf7BR9U2+j39fHCsruD9eepTuwbbf9uRUGDRlHsOOQvbKd5vGWFeF3zDrjHP
# o8x4KxkaOTbAf5dL/LbVuavEVuhA0C/oa0cB3FoUYY/xVkUHa1JRM5plUeXp0Ins
# fgoi7bF4LHn3PZIbzB7RcLMqH/ZEyf5f4CGXYkRexB69WbDKPTb6IoeaGJ+u4bp0
# ddFWSeapVgr+pBSrbctxrAR28o+Jb6M7kzJBVbTTKNnvNmmXt8CXECENUcT+hwGz
# P3Uac98M7ZRsU+yXpN8ZvSr6TkS/ikffQJTOZWK5Nh6XIXD/85AB7tAX1/jTAsc8
# L8Q8QhiQUy5lYKZXUVkpBKEqe0HHEqunop2Hdw27AhoE1J3btl34OSUK7tll9Y91
# fP5oAPb9tl4pqhG0Bogh3MLA/eUuxrEel2D2RLiKyFfYGLVFm/OeCKYedzQvdOjm
# wOy31V9CCKidU7TABkZ83XWQ7axy9Y+U/YYx+2ufVZjo6sOo6Agt
# SIG # End signature block
