. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

Write-Host "This package has a dependency to Git"
Write-Host "Please Update first Git"
Write-Host "Otherwise you could have installation failures"
pause

& "$($AlyaScripts)\intune\Create-IntuneWin32Packages.ps1" -CreateOnlyAppWithName "TortoiseGit"
& "$($AlyaScripts)\intune\Upload-IntuneWin32Packages.ps1" -UploadOnlyAppWithName "TortoiseGit"
& "$($AlyaScripts)\intune\Configure-IntuneWin32Packages.ps1" -ConfigureOnlyAppWithName "TortoiseGit"
