[CmdletBinding()]
Param(
    [bool]$reuseExistingPackages = $false
)

. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

if (-Not ($reuseExistingPackages -and (Test-Path "$($AlyaData)\intune\Win32Apps\ICloud\Package" -PathType Container)))
{
	& "$($AlyaScripts)\intune\Create-IntuneWin32Packages.ps1" -CreateOnlyAppWithName "ICloud"
}
& "$($AlyaScripts)\intune\Upload-IntuneWin32Packages.ps1" -UploadOnlyAppWithName "ICloud"
& "$($AlyaScripts)\intune\Configure-IntuneWin32Packages.ps1" -ConfigureOnlyAppWithName "ICloud"