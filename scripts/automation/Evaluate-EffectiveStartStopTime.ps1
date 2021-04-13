cls
$runAtMinute = 10 # Scheduler Time
$startTime = "05:00" # Start tag definition
$stopTime = "21:55" # Stop tag definition
$midTime = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($(Get-Date), [System.TimeZoneInfo]::Local.Id, 'W. Europe Standard Time')
$midTime = $midTime.AddHours(-$midTime.Hour).AddMinutes(-$midTime.Minute).AddSeconds(-$midTime.Second).AddMilliseconds(-$midTime.Millisecond)
$midTime = $midTime.AddMinutes($runAtMinute)
if ($startTime) { $startTime = [DateTime]::parseexact($startTime,"HH:mm",$null) }
if ($stopTime) { $stopTime = [DateTime]::parseexact($stopTime,"HH:mm",$null) }

for ($runtime = $midTime; $runtime -lt $midTime.AddDays(1); $runtime = $runtime.AddHours(1))
{
    $runtime
	if ($startTime)
	{
	    if ($stopTime)
	    {
		    if ($runTime -lt $stopTime -and $runTime -gt $startTime)
		    {
			    Write-Host "- Starting VM if not running" -ForegroundColor Green
		    }
            else
		    {
			    Write-Host "- Stopping VM if running" -ForegroundColor Red
		    }
	    }
		else
		{
		    if ($runTime -gt $startTime)
		    {
			    Write-Host "- Starting VM if not running" -ForegroundColor Green
		    }
		}
	}
	else
	{
	    if ($stopTime)
	    {
		    if ($runTime -gt $stopTime)
		    {
			    Write-Host "- Stopping VM if running" -ForegroundColor Red
		    }
		    if ($runTime.Hour -eq 0 -and $stopTime.Hour -eq 23)
		    {
			    Write-Host "- Stopping VM if running" -ForegroundColor Red
		    }
	    }
	}
}
