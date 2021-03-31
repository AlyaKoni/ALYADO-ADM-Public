
$runAtMinute = 10 # Scheduler Time
$startTime = "05:00" # Start tag definition
$stopTime = "23:30" # Stop tag definition

$midTime = (Get-Date)
$midTime = $midTime.AddHours(-$midTime.Hour).AddMinutes(-$midTime.Minute).AddSeconds(-$midTime.Second).AddMilliseconds(-$midTime.Millisecond)

$midTime = $midTime.AddMinutes($runAtMinute)

for ($runtime = $midTime; $runtime -lt $midTime.AddDays(1); $runtime = $runtime.AddHours(1))
{
    $runtime
	if ($startTime)
	{
		if ($runTime -gt $startTime -and -not ($stopTime -and $startTime -lt $stopTime -and $runTime -gt $stopTime))
		{
			Write-Host "- Starting VM if not running" -ForegroundColor Green
		}
	}
	if ($stopTime)
	{
		if ($runTime -gt $stopTime -and -not ($startTime -and $startTime -gt $stopTime -and $runTime -gt $startTime))
		{
			Write-Host "- Stopping VM if running" -ForegroundColor Red
		}
	}
}
