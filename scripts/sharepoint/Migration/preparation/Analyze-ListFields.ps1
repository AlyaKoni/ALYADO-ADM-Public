#Requires -Version 2.0
Add-PSSnapin Microsoft.SharePoint.PowerShell
 
$webAppUrl = "https://PleaseSpecify"

$webApp = Get-SPWebApplication $WebAppUrl
if ($webApp -ne $null)
{
    foreach ($site in $webApp.Sites)
    {
        Write-Host "Site $($site.Url)..." -ForegroundColor Cyan
        foreach ($web in $site.AllWebs)
        {
            Write-Host "Web $($web.Url)" -ForegroundColor Yellow
            foreach ($list in $web.Lists)
            {
                #Write-Host "List $($list.RootFolder.ServerRelativeUrl)" -ForegroundColor Green
                foreach ($field in $list.Fields)
                {
                    #Write-Host "Field $($field.Title)" -ForegroundColor Blue
                    if ($field.TypeAsString -eq "Choice")
                    {
                        $choicesArray = @()
                        foreach ($choice in $field.Choices)
                        {
                            $choicesArray += $choice
                        }
                        if ($field.DefaultValue -And (-Not $choicesArray -contains $field.DefaultValue))
                        {
                            Write-Host "List $($list.RootFolder.ServerRelativeUrl)" -ForegroundColor Green
                            Write-Host "Field $($field.Title)" -ForegroundColor Blue
                            Write-Host "Found Error" -ForegroundColor Red
                        }
                    }
                }
            }

            $web.Dispose()
        }
        $site.Dispose()
    }
}
