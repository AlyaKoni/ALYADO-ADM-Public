try
{
    $fileDir = "##FILEPATH##"
    $fileName = "##FILENAME##"
	$filePath = "$fileDir\$fileName"
    if (-Not (Test-Path $filePath))
	{
		if ($filePath.StartsWith("$($env:ProgramFiles)\"))
		{
			$filePath = $filePath.Replace("$($env:ProgramFiles)\", "$(${env:ProgramFiles(x86)})\")
		}
		if ($filePath.StartsWith("$(${env:ProgramFiles(x86)})\"))
		{
			$filePath = $filePath.Replace("$(${env:ProgramFiles(x86)})\", "$($env:ProgramFiles)\")
		}
	}
    if (Test-Path $filePath)
    {
        $file = Get-Item -Path $filePath
        $actVers = [Version]$file.VersionInfo.FileVersionRaw
        $tobeVers = [Version]"##FILEVERSION##"
        if ($actVers -ge $tobeVers)
        {
            Write-Host "Not required"
        }
		else
        {
            Write-Host "Required"
        }
    }
    else
    {
        Write-Host "Not required"
    }
} catch {
    Write-Host "$($_.Exception.GetType().Name): $($_.Exception.Message)"
    Exit 1
}
