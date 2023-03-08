[CmdletBinding()]
Param(
    [bool]$reuseExistingPackages = $false
)

. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

if (-Not ($reuseExistingPackages -and (Test-Path "$($AlyaData)\intune\Win32Apps\7Zip\Package" -PathType Container)))
{
	& "$($AlyaScripts)\intune\Create-IntuneWin32Packages.ps1" -CreateOnlyAppWithName "7Zip"
}
& "$($AlyaScripts)\intune\Upload-IntuneWin32Packages.ps1" -UploadOnlyAppWithName "7Zip"
& "$($AlyaScripts)\intune\Configure-IntuneWin32Packages.ps1" -ConfigureOnlyAppWithName "7Zip"
