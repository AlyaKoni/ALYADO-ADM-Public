[CmdletBinding()]
Param(
    [bool]$reuseExistingPackages = $false
)

. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

if (-Not ($reuseExistingPackages -and (Test-Path "$($AlyaData)\intune\Win32Apps\FileZilla\Package" -PathType Container)))
{
	& "$($AlyaScripts)\intune\Create-IntuneWin32Packages.ps1" -CreateOnlyAppWithName "FileZilla"
}
& "$($AlyaScripts)\intune\Upload-IntuneWin32Packages.ps1" -UploadOnlyAppWithName "FileZilla"
& "$($AlyaScripts)\intune\Configure-IntuneWin32Packages.ps1" -ConfigureOnlyAppWithName "FileZilla"
