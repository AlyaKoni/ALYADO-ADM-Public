
powershell.exe -nologo -ExecutionPolicy bypass -File \\server\ExchangeExport\DiscoverPST.ps1 2>&1 1>\\server\ExchangeExport\Logs\%USERDOMAIN%-%USERNAME%-%CLIENTNAME%.log
