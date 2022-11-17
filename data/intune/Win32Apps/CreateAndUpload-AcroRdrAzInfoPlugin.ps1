. $PSScriptRoot\..\..\..\01_ConfigureEnv.ps1

Write-Warning "This package has a dependency to Acrobat Reader DC and AZ Info Protection"
Write-Warning "Please Update first AAcrobat Reader DC and AZ Info Protection"
Write-Warning "Otherwise you will have installation failures"
Start-Sleep -Seconds 10

& "$($AlyaScripts)\intune\Create-IntuneWin32Packages.ps1" -CreateOnlyAppWithName "AcroRdrAzInfoPlugin"
& "$($AlyaScripts)\intune\Upload-IntuneWin32Packages.ps1" -UploadOnlyAppWithName "AcroRdrAzInfoPlugin"
& "$($AlyaScripts)\intune\Configure-IntuneWin32Packages.ps1" -ConfigureOnlyAppWithName "AcroRdrAzInfoPlugin"
