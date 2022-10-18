. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

& "$($AlyaScripts)\intune\Create-IntuneWin32Packages.ps1" -CreateOnlyAppWithName "Pdf24"
& "$($AlyaScripts)\intune\Upload-IntuneWin32Packages.ps1" -UploadOnlyAppWithName "Pdf24"
& "$($AlyaScripts)\intune\Configure-IntuneWin32Packages.ps1" -ConfigureOnlyAppWithName "Pdf24"
