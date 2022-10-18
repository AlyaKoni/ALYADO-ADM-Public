. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

& "$($AlyaScripts)\intune\Create-IntuneWin32Packages.ps1" -CreateOnlyAppWithName "LocalCUS"
& "$($AlyaScripts)\intune\Upload-IntuneWin32Packages.ps1" -UploadOnlyAppWithName "LocalCUS"
& "$($AlyaScripts)\intune\Configure-IntuneWin32Packages.ps1" -ConfigureOnlyAppWithName "LocalCUS"
