[CmdletBinding()]
Param(
    [bool]$reuseExistingPackages = $false
)

. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

if (-Not ($reuseExistingPackages -and (Test-Path "$($AlyaData)\intune\Win32Apps\RemoteDesktopManager\Package" -PathType Container)))
{
	& "$($AlyaScripts)\intune\Create-IntuneWin32Packages.ps1" -CreateOnlyAppWithName "RemoteDesktopManager"
}
& "$($AlyaScripts)\intune\Upload-IntuneWin32Packages.ps1" -UploadOnlyAppWithName "RemoteDesktopManager"
& "$($AlyaScripts)\intune\Configure-IntuneWin32Packages.ps1" -ConfigureOnlyAppWithName "RemoteDesktopManager"
