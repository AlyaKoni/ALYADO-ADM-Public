Write-Host "Alya Teams Backgrounds"
Write-Host "======================"
$storageRoot = "https://alyainfpstrg001.blob.core.windows.net/teams/"
$customer = "AlyaConsulting"
$teamsDir = "$env:APPDATA\Microsoft\Teams"
$uploadsDir = "$teamsDir\Backgrounds\Uploads"
if (-Not (Test-Path $teamsDir))
{
    throw "Teams directory $teamsDir not found. Is Teams installed?"
}
if (-Not (Test-Path $uploadsDir))
{
    $null = New-Item -Path $uploadsDir -ItemType Directory -Force
}
$tryFileList = @(
    "fluentSpaces3Own.png",
    "fluentSpaces4Own.png",
    "teamsBackgroundContemporaryOffice02Own.png",
    "teamsBackgroundHomeOwn.png",
    "teamsBackgroundTraditionalOffice01Own.png"
)
foreach($tryFile in $tryFileList)
{
    try
    {
        $outFile = "$uploadsDir\$customer-$tryFile"
        if (Test-Path $outFile)
        {
            $null = Remove-Item -Path $outFile -Force -ErrorAction SilentlyContinue
        }
        $req = Invoke-WebRequest -SkipHttpErrorCheck -UseBasicParsing -Uri ($storageRoot+"$tryFile") -Method Get -OutFile $outFile -ErrorAction SilentlyContinue
    }
    catch {}
}
