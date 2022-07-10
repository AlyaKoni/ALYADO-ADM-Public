. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

& "$($AlyaScripts)\intune\Create-IntuneWin32Packages.ps1" -CreateOnlyAppWithName "BIMxDesktop"
& "$($AlyaScripts)\intune\Upload-IntuneWin32Packages.ps1" -UploadOnlyAppWithName "BIMxDesktop"
& "$($AlyaScripts)\intune\Configure-IntuneWin32Packages.ps1" -ConfigureOnlyAppWithName "BIMxDesktop"
