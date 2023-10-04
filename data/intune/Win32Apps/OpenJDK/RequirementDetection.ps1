try
{
    $keyPath = "##KEYPATH##"
    $keyName = "##KEYNAME##"
    $keyPath = [Regex]::Replace($keyPath, "Computer\\HKEY_LOCAL_MACHINE", "HKLM:", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $keyPath = [Regex]::Replace($keyPath, "Computer\\HKEY_CURRENT_USER", "HKCU:", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $actVers = [Version](Get-ItemProperty -Path $keyPath -Name $keyName -ErrorAction SilentlyContinue).$keyName
    if (-Not $actVers)
    {
        $keyPath = [Regex]::Replace($keyPath, "\\SOFTWARE\\", "\\SOFTWARE\\WOW6432Node\\", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $actVers = [Version](Get-ItemProperty -Path $keyPath -Name $keyName -ErrorAction SilentlyContinue).$keyName
    }
    if (-Not $actVers)
    {
        Write-Host "Not required"
    }
    else
    {
        $tobeVers = [Version]"##KEYVERSION##"
        if ($actVers -ge $tobeVers)
        {
            Write-Host "Not required"
        }
	    else
        {
            Write-Host "Required"
        }
    }
} catch {
    Write-Host "$($_.Exception.GetType().Name): $($_.Exception.Message)"
    Exit 1
}
