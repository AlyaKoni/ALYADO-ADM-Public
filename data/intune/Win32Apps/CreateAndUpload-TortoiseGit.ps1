. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

Write-Warning "This package has a dependency to Git"
Write-Warning "Please Update first Git"
Write-Warning "Otherwise you could have installation failures"
Start-Sleep -Seconds 10

& "$($AlyaScripts)\intune\Create-IntuneWin32Packages.ps1" -CreateOnlyAppWithName "TortoiseGit"
& "$($AlyaScripts)\intune\Upload-IntuneWin32Packages.ps1" -UploadOnlyAppWithName "TortoiseGit"
& "$($AlyaScripts)\intune\Configure-IntuneWin32Packages.ps1" -ConfigureOnlyAppWithName "TortoiseGit"
