#(Get-AppxPackage).Name

$appsToRemove = @( `
"microsoft.windowscommunicationsapps",
"Microsoft.XboxApp",
"Microsoft.XboxIdentityProvider",
"Microsoft.XboxGameOverlay",
"Microsoft.XboxGamingOverlay",
"Microsoft.YourPhone",
"Microsoft.SkypeApp",
"Microsoft.WindowsCamera",
"Microsoft.Xbox.TCUI",
"Microsoft.Messaging",
"Microsoft.BingWeather",
"Microsoft.ZuneMusic",
"Microsoft.MicrosoftSolitaireCollection",
"Microsoft.MicrosoftStickyNotes",
"Microsoft.ZuneVideo",
"Microsoft.Print3D"
)

foreach ($app in $appsToRemove)
{
    Write-Host "Uninstalling $app"
    Get-AppxPackage -allusers $app | Remove-AppxPackage
}

#Remove-AppxProvisionedPackage