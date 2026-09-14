#Requires -Version 7.0

<#
    Copyright (c) Alya Consulting, 2019-2026

    This file is part of the Alya Base Configuration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
    The Alya Base Configuration is free software: you can redistribute it
    and/or modify it under the terms of the GNU General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    Alya Base Configuration is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of 
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
    Public License for more details: https://www.gnu.org/licenses/gpl-3.0.txt

    Diese Datei ist Teil der Alya Basis Konfiguration.
    https://alyaconsulting.ch/Solutions/AlyaBasisKonfiguration
    Die Alya Basis Konfiguration ist eine Freie Software: Sie können sie unter den
    Bedingungen der GNU General Public License, wie von der Free Software
    Foundation, Version 3 der Lizenz oder (nach Ihrer Wahl) jeder neueren
    veröffentlichten Version, weiter verteilen und/oder modifizieren.
    Die Alya Basis Konfiguration wird in der Hoffnung, dass sie nützlich sein wird,
    aber OHNE JEDE GEWÄHRLEISTUNG, bereitgestellt; sogar ohne die implizite
    Gewährleistung der MARKTFÄHIGKEIT oder EIGNUNG FUER EINEN BESTIMMTEN ZWECK.
    Siehe die GNU General Public License fuer weitere Details:
    https://www.gnu.org/licenses/gpl-3.0.txt


    History:
    Date       Author               Description
    ---------- -------------------- ----------------------------
    08.09.2026 Konrad Brunner       Initial Version
    09.09.2026 Konrad Brunner       Komplette Implementierung: Link-/Button-Scan via Regex, Versionsauswahl,
                                    Download-Kaskade (Invoke-WebRequest, CDP-Netzwerk-Stream, Scrapfly-Downloads-API)
    09.09.2026 Konrad Brunner       Parameter Silent (Default $true): unterdrueckt alle Write-Host- und
                                    Write-Warning-Ausgaben des Skripts
    09.09.2026 Konrad Brunner       Multi-Hop-Navigation (Parameter MaxPageHops), Button-Ranking statt
                                    erstem Treffer, In-Page-Anker ausgeschlossen, Parameter FileRegex
                                    (Filter fuer erwartete Zieldatei)
    09.09.2026 Konrad Brunner       Fix SPA-Renderrace: negativ gerankte Kandidaten (Report/Agreement)
                                    werden nie geklickt; Scan-Retries (3x 8 s) auch wenn nur solche
                                    Junk-Kandidaten gefunden wurden

#>

# ==================================================================
# Scrapfly Cloud Browser - Datei-Downloader
# ==================================================================
#
# Ablauf:
#   1. Verbindung zum Scrapfly Cloud Browser (CDP via rohes WebSocket,
#      wss://browser.scrapfly.io, siehe https://scrapfly.io/docs/cloud-browser-api/getting-started)
#   2. PageUrl oeffnen und warten, bis die Seite geladen ist
#      (CAPTCHAs werden durch solve_captcha=true automatisch geloest)
#   3. DOM mit LinkRegex nach direkten Download-Links durchsuchen.
#      Falls Links gefunden werden: Versionsnummern extrahieren und den
#      Link mit der hoechsten Version waehlen. Ist FileRegex gesetzt,
#      zaehlen nur Links, die dieses Muster erfuellen.
#   4. Falls keine Links gefunden werden: DOM mit ButtonRegex nach
#      Download-Buttons durchsuchen (In-Page-Anker werden ignoriert),
#      die Kandidaten nach Ranking der Reihe nach klicken (exakt
#      "Download" und "Download for <Os>" zuerst, Report-/Agreement-
#      Links zuletzt) und den Download-Event (Browser.downloadWillBegin)
#      abfangen. Die Download-URL wird uebernommen und der Browser-
#      Download sofort abgebrochen (Browser.cancelDownload).
#      Loest ein Klick keinen Download aus, aber eine Navigation
#      (Redirect auf eine Folgeseite, z. B. ein Support-Portal), wird
#      die neue Seite geladen und erneut gescannt (Schritte 3-4),
#      insgesamt bis zu MaxPageHops Seitenwechsel.
#   5. Download-Kaskade (jeder Versuch wird gecatcht, protokolliert und
#      ausgewertet, bevor der naechste Weg probiert wird):
#        a) Direkt mit Invoke-WebRequest (inkl. Cookies aus dem Browser)
#        b) Ueber den Browser via Network.loadNetworkResource + IO.read-Stream
#        c) Ueber die Scrapfly-Downloads-API (Browser-Download ausloesen,
#           warten bis abgeschlossen, via ScrapiumBrowser.getDownloads holen;
#           begrenzt auf 500 MB pro Datei, siehe
#           https://scrapfly.io/docs/cloud-browser-api/file-downloads)
#   6. Die Datei wird mit dem originalen Download-Namen (suggestedFilename
#      bzw. Content-Disposition, sonst URL-Name) in OutDir gespeichert.
#
# Es werden ausschliesslich binaere Installationsdateien (zip, exe, msi und
# aehnliche) akzeptiert - niemals Bilder, SVG, PDF oder andere nicht
# installierbare Dateien. Dateien kleiner als 1 MB werden als Fehler
# gewertet. Abbruchwuerdige Fehler werden nach Protokoll und Auswertung
# weitergeworfen (throw); das Skript gibt dann den Dateinamen NICHT zurueck.
#
# Rueckgabewert bei Erfolg: Name der heruntergeladenen Datei (nur der Name,
# ohne Pfad).
#
# Parameter Silent (Default $true): Wenn gesetzt, werden keine Write-Host-
# oder Write-Warning-Ausgaben des Skripts ausgegeben. Fehler werden weiterhin
# ueber throw gemeldet; das Transcript-Logging bleibt unveraendert aktiv.
# Mit -Silent:$false kann die normale Konsolenausgabe eingeschaltet werden.
#
# Parameter FileRegex (optional): Muster fuer den erwarteten Dateinamen bzw.
# die erwartete Download-URL (z. B. 'CheckPointVPN\.msi'). Wenn gesetzt,
# werden nur Links, Download-Events und Zielnamen akzeptiert, die dem Muster
# entsprechen - falsch benannte Dateien (z. B. zusaetzlich angebotene
# Update-Pakete) koennen so nicht mehr gewonnen werden.
#
# Parameter MaxPageHops (Default 3): maximale Anzahl Redirects/Folgeseiten,
# denen das Skript nach Button-Klicks folgt, bevor es abbricht.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ApiKey = $null,
    [Parameter(Mandatory = $true)]
    [string]$PageUrl = "",
    [Parameter(Mandatory = $true)]
    [string]$OutDir = "",
    [Parameter(Mandatory = $false)]
    [string]$Country = "ch",
    [Parameter(Mandatory = $false)]
    [ValidateSet("windows", "macos", "linux")]
    [string]$Os = "windows",
    [Parameter(Mandatory = $false)]
    [string]$ProxyPool = "public_datacenter_pool",
    [Parameter(Mandatory = $false)]
    [string[]]$LinkRegex = @(),
    [Parameter(Mandatory = $false)]
    [string[]]$ButtonRegex = @(),
    [Parameter(Mandatory = $false)]
    [string]$FileRegex = "",
    [Parameter(Mandatory = $false)]
    [int]$MaxPageHops = 3,
    [Parameter(Mandatory = $false)]
    [string]$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    [Parameter(Mandatory = $false)]
    [bool]$SolveCaptcha = $true,
    [Parameter(Mandatory = $false)]
    [int]$PageLoadWaitSeconds = 120,
    [Parameter(Mandatory = $false)]
    [int]$DownloadEventWaitSeconds = 90,
    [Parameter(Mandatory = $false)]
    [int]$FileTimeoutSeconds = 1800,
    [Parameter(Mandatory = $false)]
    [bool]$Silent = $true
)

# ------------------------------------------------------------------
# Silent-Modus: Write-Host und Write-Warning unterdruecken.
# Die folgenden Funktionen ueberdecken (shadowen) die gleichnamigen
# Cmdlets fuer den gesamten Skript-Scope dieses Skripts (inklusive
# der punktuell geladenen Dateien und aller Funktionen). Alle
# Argumente (auch benannte wie -ForegroundColor) werden ueber
# ValueFromRemainingArguments angenommen und verworfen.
# ------------------------------------------------------------------
if ($Silent)
{
    function Write-Host
    {
        param(
            [Parameter(ValueFromRemainingArguments = $true)]
            $SilencedArguments
        )
    }
    function Write-Warning
    {
        param(
            [Parameter(ValueFromRemainingArguments = $true)]
            $SilencedArguments
        )
    }
}

# Reading configuration
. $PSScriptRoot\..\..\01_ConfigureEnv.ps1

# Starting Transcript
$logDir = Join-Path $AlyaLogs "scripts/misc"
$null = New-Item -Path $logDir -ItemType Directory -Force
Start-Transcript -Path (Join-Path $logDir "Download-FileWithScrapfly-$($AlyaTimeString).log") | Out-Null

# Members
$script:nextId = 10
$script:ActiveFileRegex = ""
$script:fileRegexRejectedUrls = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

# Empfangszustand fuer den CDP-WebSocket-Reader.
# WICHTIG: Ein laufendes ReceiveAsync darf NIEMALS per CancellationToken
# abgebrochen werden - das ABORTED den ClientWebSocket und die Session stirbt.
# Stattdessen bleibt der Receive-Task ueber Aufrufe hinweg pending und es wird
# nur mit Timeout darauf gewartet (Task.Wait).
$script:receiveBuffer = New-Object byte[] 262144
$script:receiveSegment = New-Object System.ArraySegment[byte] -ArgumentList @(, $script:receiveBuffer)
$script:pendingReceiveTask = $null
$script:messageBuilder = New-Object System.Text.StringBuilder

# =============================================================
# Konstanten
# =============================================================

$script:MinFileSizeBytes = 1MB
$script:MaxScrapflyDownloadBytes = 524288000  # 500 MB Limit der Scrapfly-Downloads-API

# Erlaubte Endungen von Installationspaketen (nur Binaerdateien, niemals Bilder/SVG/PDF)
$script:InstallerExtensions = @(
    "7z", "aab", "apk", "appimage", "appx", "appxbundle", "bin", "bz2", "cab", "deb", "dmg",
    "ear", "exe", "gz", "img", "iso", "jar", "msp", "msi", "msix", "msixbundle", "nupkg",
    "pkg", "rpm", "run", "sh", "tar", "tgz", "war", "whl", "xz", "zip", "zst"
)
$script:InstallerExtensionSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$script:InstallerExtensions, [System.StringComparer]::OrdinalIgnoreCase)
$script:InstallerExtensionRegex = "\.(" + ($script:InstallerExtensions -join "|") + ")(\?|#|$)"

# Explizit verbotene Endungen (Dokumente, Bilder, Medien, Text)
$script:ForbiddenExtensions = @(
    "bmp", "csv", "doc", "docx", "gif", "htm", "html", "ico", "jpeg", "jpg", "json", "mp3",
    "mp4", "pdf", "png", "ppt", "pptx", "svg", "tif", "tiff", "txt", "webp", "xhtml", "xls",
    "xlsx", "xml"
)
$script:ForbiddenExtensionRegex = "\.(" + ($script:ForbiddenExtensions -join "|") + ")(\?|#|$)"

# Standard-Regex, falls keine uebergeben wurden
$script:DefaultLinkRegex = $script:InstallerExtensionRegex
$script:DefaultButtonRegex = "^download"

# =============================================================
# Scrapfly key stuff
# =============================================================

if (-Not $ApiKey)
{

    # Checking modules
    Write-Host "Checking modules" -ForegroundColor $CommandInfo
    Install-ModuleIfNotInstalled "Microsoft.PowerShell.SecretManagement"
    Install-ModuleIfNotInstalled "Microsoft.PowerShell.SecretStore"

    # Checking store
    if (-Not (Get-SecretVault -Name "$($AlyaCompanyNameShortM365)Store" -ErrorAction SilentlyContinue))
    {
        & "$($AlyaScripts)/misc/Set-ScrapflyKey.ps1"
    }
    else
    {
        # Checking secret
        $scrapflyKey = Get-Secret -Name "scrapflyKey" -Vault "$($AlyaCompanyNameShortM365)Store" -ErrorAction SilentlyContinue
        if (-Not $scrapflyKey)
        {
            & "$($AlyaScripts)/misc/Set-ScrapflyKey.ps1"
        }
    }
    $scrapflyKey = Get-Secret -Name "scrapflyKey" -Vault "$($AlyaCompanyNameShortM365)Store" -ErrorAction SilentlyContinue
    if (-Not $scrapflyKey)
    {
        throw "Kein Scrapfly API-Key verfuegbar. Bitte Uebergabeparameter -ApiKey verwenden oder das Skript misc/Set-ScrapflyKey.ps1 ausfuehren."
    }
    $ApiKey = ConvertFrom-SecureString -SecureString $scrapflyKey -AsPlainText
}

# Regex-Parameter validieren und Defaults anwenden
foreach ($regex in @($LinkRegex) + @($ButtonRegex) + @($FileRegex))
{
    if ($regex)
    {
        try
        {
            $null = [regex]::new($regex)
        }
        catch
        {
            throw "Ungueltiger Regex '$($regex)': $($_.Exception.Message)"
        }
    }
}
if ($LinkRegex.Count -eq 0)
{
    $LinkRegex = @($script:DefaultLinkRegex)
    Write-Host "Kein LinkRegex uebergeben, Standard wird verwendet: $($script:DefaultLinkRegex)" -ForegroundColor $CommandWarning
}
if ($ButtonRegex.Count -eq 0)
{
    $ButtonRegex = @($script:DefaultButtonRegex)
    Write-Host "Kein ButtonRegex uebergeben, Standard wird verwendet: $($script:DefaultButtonRegex)" -ForegroundColor $CommandWarning
}

$script:ActiveFileRegex = $FileRegex
if ($FileRegex)
{
    Write-Host "FileRegex aktiv: '$FileRegex' - nur passende Dateien werden akzeptiert" -ForegroundColor $CommandInfo
}
if ($MaxPageHops -lt 0)
{
    $MaxPageHops = 0
}

# ------------------------------------------------------------------
# JS-Bausteine
# ------------------------------------------------------------------

$jsStatus = @'
(function(){var t=!!(document.querySelector('iframe[src*="challenges.cloudflare"]')||document.querySelector('iframe[src*="turnstile"]')||document.querySelector('#challenge-stage')||document.querySelector('.cf-challenge')||document.querySelector('#cf-wrapper'));return JSON.stringify({ready:document.readyState,title:document.title,challenge:t});})()
'@

$jsConfirmDownload = @'
(function(){var candidates=Array.from(document.querySelectorAll('a,button,input[type="button"],input[type="submit"]')).filter(function(el){var rect=el.getBoundingClientRect();var style=getComputedStyle(el);return rect.width>0&&rect.height>0&&style.visibility!=='hidden'&&style.display!=='none';});for(var i=0;i<candidates.length;i++){var text=((candidates[i].innerText||candidates[i].value||candidates[i].textContent||'')+'').trim().replace(/\s+/g,' ');var lower=text.toLowerCase();if(lower==='download now'||lower.indexOf('accept and download')>=0||lower.indexOf('agree and download')>=0||lower.indexOf('confirm download')>=0||lower.indexOf('akzeptieren und herunterladen')>=0||lower.indexOf('bestaetigen')>=0||lower==='bestätigen'){candidates[i].click();return JSON.stringify({clicked:true,text:text});}}return JSON.stringify({clicked:false});})()
'@

# Cookie-/Consent-Banner (z. B. OneTrust) akzeptieren und schliessen, damit sie
# keine Klicks auf Download-Buttons blockieren
$jsAcceptCookies = @'
(function(){var selectors=['#onetrust-accept-btn-handler','#onetrust-close-btn-container button','.ot-close-icon','#accept-cookies','.cc-btn.cc-allow','.qc-cmp2-summary-buttons button:first-child','[data-testid="cookie-policy-manage-dialog-accept-button"]'];for(var i=0;i<selectors.length;i++){try{var el=document.querySelector(selectors[i]);if(el){var r=el.getBoundingClientRect();if(r.width>0&&r.height>0){el.click();return JSON.stringify({clicked:true,how:'selector '+selectors[i]});}}}catch(e){}}var els=document.querySelectorAll('button,a[role="button"],input[type="button"],input[type="submit"]');var texts=['accept all','accept all cookies','accept cookies','accept','agree','i agree','allow all','allow cookies','alle akzeptieren','cookies akzeptieren','akzeptieren','zustimmen','einverstanden'];for(var j=0;j<els.length;j++){var el2=els[j];var r2=el2.getBoundingClientRect();if(r2.width<=0||r2.height<=0){continue;}var t=((el2.innerText||el2.value||'')+'').trim().replace(/\s+/g,' ').toLowerCase();if(t.length>40){continue;}for(var k=0;k<texts.length;k++){if(t===texts[k]){el2.click();return JSON.stringify({clicked:true,how:'text '+t});}}}return JSON.stringify({clicked:false});})()
'@

function ConvertTo-JsRegexArray {
    param(
        [string[]]$Regexes
    )
    # Regex-Array als JSON-Array-Literal fuer die Einbettung in JavaScript
    $items = foreach ($singleRegex in $Regexes)
    {
        ConvertTo-Json -InputObject $singleRegex -Compress
    }
    return "[" + ($items -join ",") + "]"
}

function Get-LinkScanJs {
    param(
        [string[]]$Regexes
    )
    $regexArray = ConvertTo-JsRegexArray -Regexes $Regexes
    return @"
(function(){var rx=$regexArray;var out=[];var seen={};var links=document.querySelectorAll('a[href],area[href]');for(var i=0;i<links.length;i++){var h=links[i].href||'';if(!h||h==='#'||h.indexOf('javascript:')===0){continue;}for(var r=0;r<rx.length;r++){try{if(new RegExp(rx[r],'i').test(h)){if(!seen[h]){seen[h]=1;out.push(h);}break;}}catch(e){}}}return JSON.stringify(out);})()
"@
}

function Get-ButtonScanJs {
    param(
        [string[]]$Regexes
    )
    $regexArray = ConvertTo-JsRegexArray -Regexes $Regexes
    return @"
(function(){var rx=$regexArray;var els=document.querySelectorAll('a,button,input[type="button"],input[type="submit"],[role="button"]');var out=[];for(var i=0;i<els.length;i++){var el=els[i];var rect=el.getBoundingClientRect();var style=getComputedStyle(el);if(rect.width<=0||rect.height<=0||style.visibility==='hidden'||style.display==='none'){continue;}var hrefAttr=el.getAttribute('href')||'';if(hrefAttr.charAt(0)==='#'){continue;}var text=((el.innerText||el.value||el.getAttribute('aria-label')||el.getAttribute('title')||el.textContent||'')+'').trim().replace(/\s+/g,' ');if(text.length===0||text.length>120){continue;}var matched=false;for(var r=0;r<rx.length;r++){try{if(new RegExp(rx[r],'i').test(text)){matched=true;break;}}catch(e){}}if(matched){el.setAttribute('data-alya-dl-idx',String(out.length));out.push({index:out.length,tag:el.tagName,text:text.substring(0,120),href:(el.href||'').substring(0,200)});}}return JSON.stringify(out);})()
"@
}

function Get-ButtonScrollJs {
    param(
        [int]$Index
    )
    return @"
(function(){var el=document.querySelector('[data-alya-dl-idx="$Index"]');if(!el){return JSON.stringify({found:false});}el.scrollIntoView({block:'center',inline:'center'});return JSON.stringify({found:true});})()
"@
}

function Get-ButtonRectJs {
    param(
        [int]$Index
    )
    return @"
(function(){var el=document.querySelector('[data-alya-dl-idx="$Index"]');if(!el){return JSON.stringify({found:false});}var r=el.getBoundingClientRect();var s=getComputedStyle(el);return JSON.stringify({found:true,visible:r.width>0&&r.height>0&&s.visibility!=='hidden',x:r.x+r.width/2,y:r.y+r.height/2});})()
"@
}

function Get-ButtonClickJs {
    param(
        [int]$Index
    )
    return @"
(function(){var el=document.querySelector('[data-alya-dl-idx="$Index"]');if(!el){return JSON.stringify({clicked:false});}el.click();return JSON.stringify({clicked:true});})()
"@
}

function Get-RankedButtonOrder {
    param(
        [object[]]$Buttons,
        [string]$TargetOs = "windows"
    )
    # Reiht Button-Kandidaten fuer die Klick-Reihenfolge (beste zuerst) und
    # liefert Objekte mit Index, Tag, Text und Score zurueck:
    # - Text exakt "download" ist der primaere Download-Button (hoechster Rang)
    # - "download for/fuer <os>" passend zum -Os-Parameter kommt danach
    # - generische download-* Texte folgen
    # - Junk (report, agreement, manual, guide, ...) erhaelt einen negativen
    #   Score und darf NICHT geklickt werden (fuehrt auf Marketingseiten o. ae.)
    # Bei gleichem Rang entscheidet die DOM-Reihenfolge (Index aufsteigend).
    $junkPattern = "(?i)report|agreement|vereinbarung|manual|handbuch|guide|anleitung|documentation|dokumentation|license|lizenz|datasheet|datenblatt"
    $scored = foreach ($button in $Buttons) {
        $text = [string]$button.text
        $score = 20
        if ($text -match "(?i)^download$") {
            $score = 100
        }
        elseif ($text -match "(?i)^download\s+(for|fuer)\s+") {
            $score = 60
            if ($TargetOs -eq "windows" -and $text -match "(?i)windows") { $score = 95 }
            elseif ($TargetOs -eq "macos" -and $text -match "(?i)mac") { $score = 95 }
            elseif ($TargetOs -eq "linux" -and $text -match "(?i)linux") { $score = 95 }
        }
        elseif ($text -match "(?i)^(download|herunterladen)") { $score = 40 }
        if ($text -match $junkPattern) { $score -= 50 }
        [pscustomobject]@{
            Index = [int]$button.index
            Tag   = [string]$button.tag
            Text  = $text
            Score = $score
        }
    }
    return @($scored | Sort-Object -Property @{ Expression = { $_.Score }; Descending = $true }, @{ Expression = { $_.Index }; Descending = $false })
}

# ------------------------------------------------------------------
# CDP-Hilfsfunktionen (rohes WebSocket)
# ------------------------------------------------------------------

function Convert-JsonElementToPsObject {
    param(
        [System.Text.Json.JsonElement]$Element
    )

    switch ($Element.ValueKind) {
        ([System.Text.Json.JsonValueKind]::Object) {
            $properties = [ordered]@{}
            $propertyNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($property in $Element.EnumerateObject()) {
                if ($propertyNames.Add($property.Name)) {
                    $properties[$property.Name] = Convert-JsonElementToPsObject -Element $property.Value
                }
            }
            return [pscustomobject]$properties
        }
        ([System.Text.Json.JsonValueKind]::Array) {
            $items = [System.Collections.Generic.List[object]]::new()
            foreach ($item in $Element.EnumerateArray()) {
                $items.Add((Convert-JsonElementToPsObject -Element $item))
            }
            return ,$items.ToArray()
        }
        ([System.Text.Json.JsonValueKind]::String) {
            return $Element.GetString()
        }
        ([System.Text.Json.JsonValueKind]::Number) {
            $integerValue = 0L
            if ($Element.TryGetInt64([ref]$integerValue)) {
                return $integerValue
            }
            return $Element.GetDouble()
        }
        ([System.Text.Json.JsonValueKind]::True) {
            return $true
        }
        ([System.Text.Json.JsonValueKind]::False) {
            return $false
        }
        default {
            return $null
        }
    }
}

function Send-CdpCommand {
    param(
        [System.Net.WebSockets.ClientWebSocket]$WebSocket,
        [int]$Id,
        [string]$Method,
        $Params,
        [string]$SessionId
    )
    $msgObj = [ordered]@{
        id = $Id
        method = $Method
    }
    if ($null -ne $Params) { $msgObj["params"] = $Params }
    if (-not [string]::IsNullOrEmpty($SessionId)) { $msgObj["sessionId"] = $SessionId }
    $json = $msgObj | ConvertTo-Json -Depth 10 -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($json)
    $seg = New-Object System.ArraySegment[byte] -ArgumentList @(, $bytes)
    $null = $WebSocket.SendAsync($seg, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, [System.Threading.CancellationToken]::None).GetAwaiter().GetResult()
}

function Test-CdpReceiveTimeout {
    param(
        [System.Exception]$Exception
    )
    # PowerShell wrappt .NET-Exceptions (z. B. in MethodInvocationException),
    # deshalb die InnerException-Kette nach TimeoutException durchsuchen.
    $currentException = $Exception
    while ($null -ne $currentException) {
        if ($currentException -is [System.TimeoutException]) { return $true }
        $currentException = $currentException.InnerException
    }
    return $false
}

function Receive-CdpMessage {
    param(
        [System.Net.WebSockets.ClientWebSocket]$WebSocket,
        [int]$TimeoutSeconds = 30
    )
    # Wartet mit Timeout auf die naechste vollstaendige CDP-Nachricht, ohne
    # den Receive-Task je abzubrechen (Abbruch wuerde den Socket aborten).
    # Bei Timeout wird eine TimeoutException geworfen und der Receive bleibt
    # fuer den naechsten Aufruf offen.
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        if ($null -eq $script:pendingReceiveTask) {
            $script:pendingReceiveTask = $WebSocket.ReceiveAsync($script:receiveSegment, [System.Threading.CancellationToken]::None)
        }
        $waitMilliseconds = [int][Math]::Max(1, ($deadline - (Get-Date)).TotalMilliseconds)
        $completed = $script:pendingReceiveTask.Wait($waitMilliseconds)
        if (-Not $completed) {
            throw [System.TimeoutException]::new("Keine vollstaendige CDP-Nachricht innerhalb von $TimeoutSeconds s empfangen")
        }
        $receiveResult = $script:pendingReceiveTask.GetAwaiter().GetResult()
        $script:pendingReceiveTask = $null
        if ($receiveResult.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) {
            throw [System.Net.WebSockets.WebSocketException]::new("Der Scrapfly Cloud Browser hat die Verbindung geschlossen (CloseStatus: $([int]$WebSocket.CloseStatus) $($WebSocket.CloseStatus), Grund: $($WebSocket.CloseStatusDescription))")
        }
        [void]$script:messageBuilder.Append([Text.Encoding]::UTF8.GetString($script:receiveBuffer, 0, $receiveResult.Count))
        if (-Not $receiveResult.EndOfMessage) {
            if ((Get-Date) -ge $deadline) {
                throw [System.TimeoutException]::new("CDP-Nachricht nicht vollstaendig innerhalb von $TimeoutSeconds s empfangen")
            }
            continue
        }
        $rawMessage = $script:messageBuilder.ToString()
        [void]$script:messageBuilder.Clear()
        $document = [System.Text.Json.JsonDocument]::Parse($rawMessage)
        try {
            $parsedMessage = Convert-JsonElementToPsObject -Element $document.RootElement
        }
        finally {
            $document.Dispose()
        }
        # Scrapfly-Fehlerframes (top-level "code", z. B. ERR::BROWSER::*) sind
        # keine CDP-Nachrichten und muessen als Fehler behandelt werden
        $frameCode = Get-EventPropertyValue -Object $parsedMessage -Name "code"
        if (($frameCode -is [string]) -and $frameCode.StartsWith("ERR::")) {
            $frameMessage = [string](Get-EventPropertyValue -Object $parsedMessage -Name "message")
            $frameErrorId = [string](Get-EventPropertyValue -Object $parsedMessage -Name "error_id")
            throw "Scrapfly-Fehler $frameCode (error_id: $frameErrorId): $frameMessage"
        }
        return $parsedMessage
    }
}

function Invoke-Cdp {
    param(
        [System.Net.WebSockets.ClientWebSocket]$WebSocket,
        [string]$Method,
        $Params = $null,
        [string]$SessionId = "",
        [int]$TimeoutSeconds = 30,
        $EventSink = $null
    )
    $script:nextId++
    $id = $script:nextId
    Send-CdpCommand -WebSocket $WebSocket -Id $id -Method $Method -Params $Params -SessionId $SessionId
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        $remaining = [int][Math]::Max(3, [Math]::Ceiling(($deadline - (Get-Date)).TotalSeconds))
        if ((Get-Date) -gt $deadline) { throw "CDP-Timeout bei Methode '$Method' (id $id)" }
        $msg = $null
        try {
            $msg = Receive-CdpMessage -WebSocket $WebSocket -TimeoutSeconds $remaining
        }
        catch {
            if (Test-CdpReceiveTimeout -Exception $_.Exception) { continue }
            throw
        }
        if ($null -eq $msg) { continue }
        $hasId = ($null -ne $msg.PSObject.Properties["id"]) -and ($null -ne $msg.id)
        if ($hasId -and ([int]$msg.id -eq $id)) {
            if (($null -ne $msg.PSObject.Properties["error"]) -and ($null -ne $msg.error)) {
                throw "CDP-Fehler bei '$Method': $($msg.error.message)"
            }
            return $msg.result
        }
        if (($null -ne $msg.PSObject.Properties["method"]) -and ($null -ne $EventSink)) {
            $EventSink.Add($msg)
        }
    }
}

function Invoke-ScrapiumCommand {
    param(
        [System.Net.WebSockets.ClientWebSocket]$WebSocket,
        [string]$Method,
        $Params = $null,
        [string]$SessionId = "",
        [int]$TimeoutSeconds = 120,
        $EventSink = $null
    )
    # ScrapiumBrowser-Kommandoen laufen im Browser-Prozess. Zuerst auf der
    # Page-Session versuchen (wie in den Scrapfly-Docs), bei Fehler auf der
    # Browser-Root-Verbindung.
    try {
        return Invoke-Cdp -WebSocket $WebSocket -Method $Method -Params $Params -SessionId $SessionId -TimeoutSeconds $TimeoutSeconds -EventSink $EventSink
    }
    catch {
        Write-Host "Scrapium-Kommando '$Method' auf der Session fehlgeschlagen ($($_.Exception.Message)), Versuch auf Browser-Ebene" -ForegroundColor $CommandWarning
        return Invoke-Cdp -WebSocket $WebSocket -Method $Method -Params $Params -SessionId "" -TimeoutSeconds $TimeoutSeconds -EventSink $EventSink
    }
}

function Watch-CdpEvents {
    param(
        [System.Net.WebSockets.ClientWebSocket]$WebSocket,
        [int]$Seconds,
        $EventSink,
        [scriptblock]$StopCondition = $null,
        [int]$ReceiveTimeoutSeconds = 5
    )
    # Liest CDP-Events bis zur Deadline in den EventSink und bricht frueh ab,
    # wenn die StopCondition erfuellt ist.
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ($true) {
        $remaining = ($deadline - (Get-Date)).TotalSeconds
        if ($remaining -le 0) { break }
        $receiveTimeout = [int][Math]::Max(1, [Math]::Min($ReceiveTimeoutSeconds, [Math]::Ceiling($remaining)))
        $msg = $null
        try {
            $msg = Receive-CdpMessage -WebSocket $WebSocket -TimeoutSeconds $receiveTimeout
        }
        catch {
            if (Test-CdpReceiveTimeout -Exception $_.Exception) {
                $msg = $null
            }
            else {
                if ($WebSocket.State -ne [System.Net.WebSockets.WebSocketState]::Open) {
                    throw "WebSocket-Verbindung zum Scrapfly Cloud Browser wurde getrennt (State: $($WebSocket.State), CloseStatus: $([int]$WebSocket.CloseStatus) $($WebSocket.CloseStatus), Grund: $($WebSocket.CloseStatusDescription)): $($_.Exception.Message)"
                }
                Write-Host "Warnung: Empfangsfehler waehrend Event-Ueberwachung: $($_.Exception.Message)" -ForegroundColor $CommandWarning
                $msg = $null
            }
        }
        if (($null -ne $msg) -and ($null -ne $msg.PSObject.Properties["method"]) -and ($null -ne $msg.method)) {
            $EventSink.Add($msg)
        }
        if ($null -ne $StopCondition -and (& $StopCondition)) { return $true }
    }
    if ($null -ne $StopCondition) { return [bool](& $StopCondition) }
    return $false
}

function Get-JsValue {
    param(
        [System.Net.WebSockets.ClientWebSocket]$WebSocket,
        [string]$Expression,
        [string]$SessionId,
        $EventSink
    )
    $eval = Invoke-Cdp -WebSocket $WebSocket -Method "Runtime.evaluate" -Params @{
        expression = $Expression
        returnByValue = $true
    } -SessionId $SessionId -TimeoutSeconds 30 -EventSink $EventSink
    if (($null -ne $eval.PSObject.Properties["exceptionDetails"]) -and ($null -ne $eval.exceptionDetails)) {
        throw "JS-Fehler: $($eval.exceptionDetails.text)"
    }
    if (($null -eq $eval.PSObject.Properties["result"]) -or ($null -eq $eval.result) -or ($null -eq $eval.result.PSObject.Properties["value"])) {
        throw "JS-Ausdruck lieferte keinen Wert zurueck"
    }
    return $eval.result.value
}

function Get-EventPropertyValue {
    param(
        $Object,
        [string]$Name
    )
    # StrictMode-sicherer Property-Zugriff auf geparste CDP-Events
    if ($null -eq $Object) { return $null }
    if ($null -eq $Object.PSObject.Properties[$Name]) { return $null }
    return $Object.$Name
}

function Get-DownloadCandidateFromEvent {
    param($Msg)
    $method = [string](Get-EventPropertyValue -Object $Msg -Name "method")
    $params = Get-EventPropertyValue -Object $Msg -Name "params"
    if ([string]::IsNullOrEmpty($method) -or $null -eq $params) { return $null }

    if ($method -eq "Browser.downloadWillBegin" -or $method -eq "Page.downloadWillBegin") {
        $url = [string](Get-EventPropertyValue -Object $params -Name "url")
        if (-Not [string]::IsNullOrEmpty($url)) {
            return @{
                Source = $method
                Url = $url
                Priority = 0
                Guid = [string](Get-EventPropertyValue -Object $params -Name "guid")
                SuggestedFilename = [string](Get-EventPropertyValue -Object $params -Name "suggestedFilename")
            }
        }
        return $null
    }
    if ($method -eq "Network.responseReceived") {
        $resp = Get-EventPropertyValue -Object $params -Name "response"
        if ($null -eq $resp) { return $null }
        $url = [string](Get-EventPropertyValue -Object $resp -Name "url")
        if ([string]::IsNullOrEmpty($url) -or $url -match "scrapfly\.io") { return $null }
        $headers = Get-EventPropertyValue -Object $resp -Name "headers"
        if ($null -ne $headers) {
            foreach ($prop in $headers.PSObject.Properties) {
                $headerName = $prop.Name.ToLowerInvariant()
                $headerValue = [string]$prop.Value
                if ($headerName -eq "content-disposition" -and $headerValue -match "attachment|filename") {
                    return @{ Source = $method; Url = $url; Priority = 1; Guid = ""; SuggestedFilename = "" }
                }
            }
        }
        if ($url -match $script:InstallerExtensionRegex) {
            return @{ Source = $method; Url = $url; Priority = 2; Guid = ""; SuggestedFilename = "" }
        }
        return $null
    }
    if ($method -eq "Target.targetCreated" -or $method -eq "Target.targetInfoChanged") {
        $targetInfo = Get-EventPropertyValue -Object $params -Name "targetInfo"
        if ($null -ne $targetInfo) {
            $url = [string](Get-EventPropertyValue -Object $targetInfo -Name "url")
            if ($url -match $script:InstallerExtensionRegex) {
                return @{ Source = $method; Url = $url; Priority = 2; Guid = ""; SuggestedFilename = "" }
            }
        }
        return $null
    }
    if ($method -eq "Network.requestWillBeSent") {
        $request = Get-EventPropertyValue -Object $params -Name "request"
        if ($null -eq $request) { return $null }
        $url = [string](Get-EventPropertyValue -Object $request -Name "url")
        if ($url -match $script:InstallerExtensionRegex -and $url -notmatch "scrapfly\.io") {
            return @{ Source = $method; Url = $url; Priority = 3; Guid = ""; SuggestedFilename = "" }
        }
        return $null
    }
    if ($method -eq "Page.frameNavigated") {
        $frame = Get-EventPropertyValue -Object $params -Name "frame"
        if ($null -eq $frame) { return $null }
        $url = [string](Get-EventPropertyValue -Object $frame -Name "url")
        if ($url -match $script:InstallerExtensionRegex) {
            return @{ Source = $method; Url = $url; Priority = 3; Guid = ""; SuggestedFilename = "" }
        }
        return $null
    }
    return $null
}

function Find-DownloadCandidateInEvents {
    param(
        $Events,
        [int]$StartIndex = 0
    )
    $best = $null
    for ($i = $StartIndex; $i -lt $Events.Count; $i++) {
        $candidate = Get-DownloadCandidateFromEvent -Msg $Events[$i]
        if ($null -eq $candidate) { continue }
        if ($script:ActiveFileRegex) {
            $candidateName = [string]$candidate.SuggestedFilename
            $matchesFileRegex = $false
            if (-Not [string]::IsNullOrWhiteSpace($candidateName) -and $candidateName -match $script:ActiveFileRegex) { $matchesFileRegex = $true }
            if (-Not $matchesFileRegex -and [string]$candidate.Url -match $script:ActiveFileRegex) { $matchesFileRegex = $true }
            if (-Not $matchesFileRegex) {
                if ($script:fileRegexRejectedUrls.Add([string]$candidate.Url)) {
                    Write-Host "Download-Kandidat verworfen (FileRegex '$($script:ActiveFileRegex)'): name='$candidateName' url=$($candidate.Url)" -ForegroundColor $CommandWarning
                }
                continue
            }
        }
        if ($null -eq $best -or $candidate.Priority -lt $best.Priority) { $best = $candidate }
        if ($best.Priority -eq 0) { break }
    }
    return $best
}

function Find-DownloadProgressInEvents {
    param(
        $Events,
        [string]$Guid = "",
        [string[]]$States = @("completed"),
        [int]$StartIndex = 0
    )
    # Liefert den letzten passenden Browser.downloadProgress-Event (neuester gewinnt)
    $found = $null
    for ($i = $StartIndex; $i -lt $Events.Count; $i++) {
        $msg = $Events[$i]
        $method = [string](Get-EventPropertyValue -Object $msg -Name "method")
        if ($method -ne "Browser.downloadProgress" -and $method -ne "Page.downloadProgress") { continue }
        $params = Get-EventPropertyValue -Object $msg -Name "params"
        if ($null -eq $params) { continue }
        if (-Not [string]::IsNullOrEmpty($Guid)) {
            $eventGuid = [string](Get-EventPropertyValue -Object $params -Name "guid")
            if ($eventGuid -ne $Guid) { continue }
        }
        $state = [string](Get-EventPropertyValue -Object $params -Name "state")
        if ($States -contains $state) { $found = $params }
    }
    return $found
}

function Save-CdpStream {
    param(
        [System.Net.WebSockets.ClientWebSocket]$WebSocket,
        [string]$StreamHandle,
        [string]$SessionId,
        [string]$Path,
        $EventSink,
        [bool]$ForceBase64 = $false
    )
    # Liest einen IO-Stream-Handle haeppchenweise (IO.read) in eine lokale Datei.
    # ForceBase64: Scrapfly-Download-Streams (scrapfly-download:*) liefern immer
    # Base64-Text, auch wenn base64Encoded nicht gesetzt ist.
    $fileStream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $endOfFile = $false
        while (-not $endOfFile) {
            $chunk = Invoke-Cdp -WebSocket $WebSocket -Method "IO.read" -Params @{
                handle = $StreamHandle
                size = 8388608
            } -SessionId $SessionId -TimeoutSeconds 120 -EventSink $EventSink
            $chunkData = [string](Get-EventPropertyValue -Object $chunk -Name "data")
            $base64Encoded = [bool](Get-EventPropertyValue -Object $chunk -Name "base64Encoded")
            if (-Not [string]::IsNullOrEmpty($chunkData)) {
                if ($base64Encoded -or $ForceBase64) {
                    $chunkBytes = [Convert]::FromBase64String($chunkData)
                }
                else {
                    $chunkBytes = [Text.Encoding]::UTF8.GetBytes($chunkData)
                }
                if ($chunkBytes.Length -gt 0) {
                    $fileStream.Write($chunkBytes, 0, $chunkBytes.Length)
                }
            }
            $endOfFile = [bool](Get-EventPropertyValue -Object $chunk -Name "eof")
        }
    }
    finally {
        $fileStream.Dispose()
        try {
            $null = Invoke-Cdp -WebSocket $WebSocket -Method "IO.close" -Params @{
                handle = $StreamHandle
            } -SessionId $SessionId -TimeoutSeconds 15 -EventSink $EventSink
        }
        catch {
            Write-Host "Warnung: IO.close fuer Stream '$StreamHandle' fehlgeschlagen: $($_.Exception.Message)" -ForegroundColor $CommandWarning
        }
    }
}

function Save-CdpResource {
    param(
        [System.Net.WebSockets.ClientWebSocket]$WebSocket,
        [string]$Url,
        [string]$FrameId,
        [string]$SessionId,
        [string]$Path,
        $EventSink
    )
    # Laedt eine URL ueber den Netzwerk-Stack des Browsers (mit Credentials)
    # und streamt sie via IO.read in eine lokale Datei.
    $loaded = Invoke-Cdp -WebSocket $WebSocket -Method "Network.loadNetworkResource" -Params @{
        frameId = $FrameId
        url = $Url
        options = @{
            disableCache = $true
            includeCredentials = $true
        }
    } -SessionId $SessionId -TimeoutSeconds 300 -EventSink $EventSink
    $resource = Get-EventPropertyValue -Object $loaded -Name "resource"
    if ($null -eq $resource -or -not $resource.success) {
        $networkError = "unbekannt"
        if ($null -ne $resource) {
            $netError = Get-EventPropertyValue -Object $resource -Name "netError"
            if ($null -ne $netError) { $networkError = [string]$netError }
        }
        throw "CDP-Ressource konnte nicht geladen werden: $networkError"
    }
    $stream = Get-EventPropertyValue -Object $resource -Name "stream"
    if ([string]::IsNullOrEmpty($stream)) {
        throw "CDP-Ressource lieferte keinen lesbaren Stream"
    }
    Save-CdpStream -WebSocket $WebSocket -StreamHandle ([string]$stream) -SessionId $SessionId -Path $Path -EventSink $EventSink
}

# ------------------------------------------------------------------
# Datei-/Versions-Hilfsfunktionen
# ------------------------------------------------------------------

function Get-SanitizedFileName {
    param(
        [string]$Name
    )
    if ([string]::IsNullOrWhiteSpace($Name)) { return $null }
    $name = [System.IO.Path]::GetFileName($Name.Trim())
    foreach ($invalidChar in [System.IO.Path]::GetInvalidFileNameChars()) {
        $name = $name.Replace([string]$invalidChar, "_")
    }
    $name = $name.Trim().Trim('.')
    if ([string]::IsNullOrWhiteSpace($name)) { return $null }
    return $name
}

function Get-FileNameFromUrl {
    param(
        [string]$Url
    )
    if ([string]::IsNullOrWhiteSpace($Url)) { return $null }
    try {
        $uri = [uri]$Url
        $leaf = $uri.Segments[$uri.Segments.Length - 1]
        $name = [uri]::UnescapeDataString($leaf)
        return Get-SanitizedFileName -Name $name
    }
    catch {
        return $null
    }
}

function Get-FileNameFromContentDisposition {
    param(
        [string]$ContentDisposition
    )
    if ([string]::IsNullOrWhiteSpace($ContentDisposition)) { return $null }
    if ($ContentDisposition -match "filename\*\s*=\s*([^']+)'([^']*)'([^;]+)") {
        try {
            return Get-SanitizedFileName -Name ([uri]::UnescapeDataString($Matches[3].Trim().Trim('"')))
        }
        catch { }
    }
    if ($ContentDisposition -match 'filename\s*=\s*"?([^";]+)"?') {
        return Get-SanitizedFileName -Name ($Matches[1].Trim())
    }
    return $null
}

function Test-InstallerExtension {
    param(
        [string]$Name
    )
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    $extension = [System.IO.Path]::GetExtension($Name).TrimStart('.').ToLowerInvariant()
    return $script:InstallerExtensionSet.Contains($extension)
}

function Test-ForbiddenExtension {
    param(
        [string]$Name
    )
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    return $Name -match $script:ForbiddenExtensionRegex
}

function Compare-VersionStrings {
    param(
        [string]$VersionA,
        [string]$VersionB
    )
    # Vergleicht Versionsnummern komponentenweise numerisch
    $partsA = $VersionA.Split('.')
    $partsB = $VersionB.Split('.')
    $count = [Math]::Max($partsA.Count, $partsB.Count)
    for ($i = 0; $i -lt $count; $i++) {
        $valueA = 0L
        $valueB = 0L
        if ($i -lt $partsA.Count) { $null = [long]::TryParse($partsA[$i], [ref]$valueA) }
        if ($i -lt $partsB.Count) { $null = [long]::TryParse($partsB[$i], [ref]$valueB) }
        if ($valueA -gt $valueB) { return 1 }
        if ($valueA -lt $valueB) { return -1 }
    }
    return 0
}

function Select-HighestVersionUrl {
    param(
        [string[]]$Urls
    )
    # Extrahiert Versionsnummern (z. B. 4.51.0.7) aus den URLs und liefert
    # die URL mit der hoechsten Version. URLs ohne Version werden nur als
    # Fallback verwendet.
    $bestUrl = $null
    $bestVersion = $null
    foreach ($currentUrl in $Urls) {
        $currentVersion = $null
        $versionMatches = [regex]::Matches($currentUrl, "\d+(?:\.\d+)+")
        if ($versionMatches.Count -gt 0) {
            $currentVersion = $versionMatches[0].Value
        }
        Write-Host "Kandidat: $currentUrl (Version: $(if ($currentVersion) { $currentVersion } else { "keine" }))"
        if ($null -eq $bestUrl) {
            $bestUrl = $currentUrl
            $bestVersion = $currentVersion
            continue
        }
        if ($null -ne $currentVersion) {
            if ($null -eq $bestVersion -or (Compare-VersionStrings -VersionA $currentVersion -VersionB $bestVersion) -gt 0) {
                $bestUrl = $currentUrl
                $bestVersion = $currentVersion
            }
        }
    }
    if ($null -ne $bestVersion) {
        Write-Host "Hoechste gefundene Version: $bestVersion" -ForegroundColor $CommandInfo
    }
    return $bestUrl
}

function Test-DownloadedFile {
    param(
        [string]$Path,
        [string]$NameHint,
        [string]$Url,
        [string]$ContentType
    )
    # Prueft eine heruntergeladene Datei: nur installierbare Binaerdateien,
    # niemals Bilder/SVG/PDF, Mindestgroesse 1 MB.
    $result = [pscustomobject]@{
        Success = $false
        FileName = $null
        TooSmall = $false
        Reason = ""
    }
    if (-Not (Test-Path -Path $Path)) {
        $result.Reason = "Heruntergeladene Datei nicht gefunden: $Path"
        return $result
    }
    $fileSize = (Get-Item -Path $Path).Length
    if (-Not [string]::IsNullOrWhiteSpace($ContentType) -and $ContentType -match "^\s*(text/|image/|application/pdf|application/json|application/xml)") {
        $result.Reason = "Server lieferte nicht-installierbaren Inhalt (Content-Type: $ContentType)"
        return $result
    }
    $finalName = $null
    foreach ($candidateName in @($NameHint, (Get-FileNameFromUrl -Url $Url))) {
        if (-Not [string]::IsNullOrWhiteSpace($candidateName)) {
            if (Test-InstallerExtension -Name $candidateName) {
                $finalName = Get-SanitizedFileName -Name $candidateName
                break
            }
            if (Test-ForbiddenExtension -Name $candidateName) {
                $result.Reason = "Ziel ist keine installierbare Datei, sondern '$candidateName' (Bilder/SVG/PDF/Dokumente werden nie heruntergeladen)"
                return $result
            }
        }
    }
    if ([string]::IsNullOrWhiteSpace($finalName)) {
        $result.Reason = "Kein Dateiname mit einer Installationspaket-Endung ermittelbar (Hint: '$NameHint', URL: '$Url')"
        return $result
    }
    if ($fileSize -lt $script:MinFileSizeBytes) {
        $result.TooSmall = $true
        $result.Reason = "Datei '$finalName' ist mit $([Math]::Round($fileSize / 1KB, 1)) KB kleiner als 1 MB"
        return $result
    }
    $result.Success = $true
    $result.FileName = $finalName
    return $result
}

# ------------------------------------------------------------------
# Browser-Interaktions-Funktionen
# ------------------------------------------------------------------

function Invoke-ButtonClick {
    param(
        [System.Net.WebSockets.ClientWebSocket]$WebSocket,
        [string]$SessionId,
        [int]$Index,
        $EventSink
    )
    # Klickt ein per Button-Scan markiertes Element (data-alya-dl-idx).
    # Bevorzugt wird ein echter Maus-Click via Input.dispatchMouseEvent
    # (trusted Event), als Fallback ein JS-click().
    try {
        $scrollResult = Get-JsValue -WebSocket $WebSocket -Expression (Get-ButtonScrollJs -Index $Index) -SessionId $SessionId -EventSink $EventSink | ConvertFrom-Json
        if (-Not $scrollResult.found) {
            Write-Host "Button mit Index $Index wurde nicht mehr gefunden" -ForegroundColor $CommandWarning
            return $false
        }
        Start-Sleep -Milliseconds 800
        $rectResult = Get-JsValue -WebSocket $WebSocket -Expression (Get-ButtonRectJs -Index $Index) -SessionId $SessionId -EventSink $EventSink | ConvertFrom-Json
        if ($rectResult.found -and $rectResult.visible -and $rectResult.x -gt 0 -and $rectResult.y -gt 0) {
            $mouseBase = @{
                x = [double]$rectResult.x
                y = [double]$rectResult.y
                button = "left"
                clickCount = 1
                buttons = 1
            }
            $null = Invoke-Cdp -WebSocket $WebSocket -Method "Input.dispatchMouseEvent" -Params ($mouseBase + @{ type = "mouseMoved" }) -SessionId $SessionId -TimeoutSeconds 30 -EventSink $EventSink
            $null = Invoke-Cdp -WebSocket $WebSocket -Method "Input.dispatchMouseEvent" -Params ($mouseBase + @{ type = "mousePressed" }) -SessionId $SessionId -TimeoutSeconds 30 -EventSink $EventSink
            $null = Invoke-Cdp -WebSocket $WebSocket -Method "Input.dispatchMouseEvent" -Params ($mouseBase + @{ type = "mouseReleased" }) -SessionId $SessionId -TimeoutSeconds 30 -EventSink $EventSink
            Write-Host "Maus-Klick auf Button Index $Index bei ($($rectResult.x)/$($rectResult.y)) ausgefuehrt"
        }
        else {
            $clickResult = Get-JsValue -WebSocket $WebSocket -Expression (Get-ButtonClickJs -Index $Index) -SessionId $SessionId -EventSink $EventSink | ConvertFrom-Json
            if (-Not $clickResult.clicked) {
                Write-Host "JS-Klick auf Button Index $Index fehlgeschlagen" -ForegroundColor $CommandWarning
                return $false
            }
            Write-Host "JS-Klick auf Button Index $Index ausgefuehrt"
        }
        return $true
    }
    catch {
        Write-Host "Fehler beim Klick auf Button Index $($Index): $($_.Exception.Message)" -ForegroundColor $CommandError
        return $false
    }
}

function Get-BrowserWebSession {
    param(
        [System.Net.WebSockets.ClientWebSocket]$WebSocket,
        $EventSink
    )
    # Holt alle Cookies aus dem Cloud-Browser und baut eine WebRequestSession
    # fuer direkte Downloads mit Invoke-WebRequest.
    $webSession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
    try {
        $result = Invoke-Cdp -WebSocket $WebSocket -Method "Storage.getCookies" -Params $null -SessionId "" -TimeoutSeconds 30 -EventSink $EventSink
        $cookies = Get-EventPropertyValue -Object $result -Name "cookies"
        $cookieCount = 0
        if ($null -ne $cookies) {
            foreach ($currentCookie in $cookies) {
                try {
                    $cookie = [System.Net.Cookie]::new([string]$currentCookie.name, [string]$currentCookie.value)
                    $cookieDomain = [string](Get-EventPropertyValue -Object $currentCookie -Name "domain")
                    if (-Not [string]::IsNullOrWhiteSpace($cookieDomain)) { $cookie.Domain = $cookieDomain }
                    $cookiePath = [string](Get-EventPropertyValue -Object $currentCookie -Name "path")
                    if (-Not [string]::IsNullOrWhiteSpace($cookiePath)) { $cookie.Path = $cookiePath }
                    $cookieSecure = Get-EventPropertyValue -Object $currentCookie -Name "secure"
                    if ($null -ne $cookieSecure) { $cookie.Secure = [bool]$cookieSecure }
                    $webSession.Cookies.Add($cookie)
                    $cookieCount++
                }
                catch {
                    # Einzelne Cookies koennen wegen Domain-/Path-Mismatch nicht
                    # uebernommen werden - unkritisch.
                }
            }
        }
        Write-Host "$cookieCount Cookies aus dem Cloud-Browser uebernommen"
    }
    catch {
        Write-Host "Warnung: Cookies konnten nicht gelesen werden: $($_.Exception.Message)" -ForegroundColor $CommandWarning
    }
    return $webSession
}

function Invoke-DirectDownload {
    param(
        [System.Net.WebSockets.ClientWebSocket]$WebSocket,
        [string]$Url,
        [string]$NameHint,
        [string]$TmpPath,
        [string]$Referer,
        [int]$TimeoutSeconds,
        $EventSink
    )
    # Versuch a: Direkter Download mit Invoke-WebRequest (inkl. Browser-Cookies)
    $attemptResult = [pscustomobject]@{
        Success = $false
        FileName = $null
        TmpPath = $TmpPath
        TooSmall = $false
        Error = ""
    }
    Write-Host "Versuch 1/3: Direkter Download mit Invoke-WebRequest: $Url" -ForegroundColor $CommandInfo
    try {
        $webSession = Get-BrowserWebSession -WebSocket $WebSocket -EventSink $EventSink
        $requestHeaders = @{
            "Referer" = $Referer
            "Accept" = "*/*"
        }
        $response = Invoke-WebRequest -Uri $Url -OutFile $TmpPath -PassThru -WebSession $webSession -Headers $requestHeaders -UserAgent $UserAgent -TimeoutSec $TimeoutSeconds -MaximumRedirection 10 -ErrorAction Stop
        $contentType = $null
        $dispositionName = $null
        if ($null -ne $response.Headers) {
            if ($response.Headers.ContainsKey("Content-Type")) {
                $contentType = ($response.Headers["Content-Type"] -join ";")
            }
            if ($response.Headers.ContainsKey("Content-Disposition")) {
                $dispositionName = Get-FileNameFromContentDisposition -ContentDisposition ($response.Headers["Content-Disposition"] -join ";")
            }
        }
        $effectiveHint = $NameHint
        if (-Not [string]::IsNullOrWhiteSpace($dispositionName)) {
            $effectiveHint = $dispositionName
            Write-Host "Dateiname aus Content-Disposition: $dispositionName"
        }
        $testResult = Test-DownloadedFile -Path $TmpPath -NameHint $effectiveHint -Url $Url -ContentType $contentType
        $attemptResult.Success = $testResult.Success
        $attemptResult.FileName = $testResult.FileName
        $attemptResult.TooSmall = $testResult.TooSmall
        $attemptResult.Error = $testResult.Reason
        if ($testResult.Success) {
            Write-Host "Direkter Download erfolgreich: $($testResult.FileName) ($([Math]::Round((Get-Item -Path $TmpPath).Length / 1MB, 1)) MB)"
        }
    }
    catch {
        $attemptResult.Error = $_.Exception.Message
        Write-Host "Direkter Download fehlgeschlagen: $($_.Exception.Message)" -ForegroundColor $CommandWarning
        if (Test-Path -Path $TmpPath) {
            try { Remove-Item -Path $TmpPath -Force } catch { }
        }
    }
    return $attemptResult
}

function Invoke-CdpResourceDownload {
    param(
        [System.Net.WebSockets.ClientWebSocket]$WebSocket,
        [string]$SessionId,
        [string]$Url,
        [string]$NameHint,
        [string]$TmpPath,
        $EventSink
    )
    # Versuch b: Download ueber den Netzwerk-Stack des Cloud-Browsers
    # (Network.loadNetworkResource + IO.read-Stream)
    $attemptResult = [pscustomobject]@{
        Success = $false
        FileName = $null
        TmpPath = $TmpPath
        TooSmall = $false
        Error = ""
    }
    Write-Host "Versuch 2/3: Download ueber CDP (Network.loadNetworkResource + IO-Stream): $Url" -ForegroundColor $CommandInfo
    try {
        $frameTree = Invoke-Cdp -WebSocket $WebSocket -Method "Page.getFrameTree" -Params $null -SessionId $SessionId -TimeoutSeconds 30 -EventSink $EventSink
        $frameId = [string]$frameTree.frameTree.frame.id
        Save-CdpResource -WebSocket $WebSocket -Url $Url -FrameId $frameId -SessionId $SessionId -Path $TmpPath -EventSink $EventSink
        $testResult = Test-DownloadedFile -Path $TmpPath -NameHint $NameHint -Url $Url -ContentType $null
        $attemptResult.Success = $testResult.Success
        $attemptResult.FileName = $testResult.FileName
        $attemptResult.TooSmall = $testResult.TooSmall
        $attemptResult.Error = $testResult.Reason
        if ($testResult.Success) {
            Write-Host "CDP-Stream-Download erfolgreich: $($testResult.FileName) ($([Math]::Round((Get-Item -Path $TmpPath).Length / 1MB, 1)) MB)"
        }
    }
    catch {
        $attemptResult.Error = $_.Exception.Message
        Write-Host "CDP-Stream-Download fehlgeschlagen: $($_.Exception.Message)" -ForegroundColor $CommandWarning
        if (Test-Path -Path $TmpPath) {
            try { Remove-Item -Path $TmpPath -Force } catch { }
        }
    }
    return $attemptResult
}

function Invoke-BrowserFileDownload {
    param(
        [System.Net.WebSockets.ClientWebSocket]$WebSocket,
        [string]$SessionId,
        [string]$Url,
        [string]$NameHint,
        [string]$TmpPath,
        $EventSink,
        [string]$KnownGuid = "",
        [int]$ButtonIndex = -1,
        [int]$EventWaitSeconds = 90,
        [int]$TimeoutSeconds = 1800
    )
    # Versuch c: Echten Browser-Download ausloesen, auf Abschluss warten und
    # die Datei ueber die Scrapfly-Downloads-API holen (ScrapiumBrowser.getDownloads,
    # max. 500 MB pro Datei).
    $attemptResult = [pscustomobject]@{
        Success = $false
        FileName = $null
        TmpPath = $TmpPath
        TooSmall = $false
        Error = ""
    }
    Write-Host "Versuch 3/3: Browser-Download ueber die Scrapfly-Downloads-API" -ForegroundColor $CommandInfo
    $downloadGuid = $KnownGuid
    $suggestedName = $NameHint
    $extraTargetId = $null
    try {
        $completedProgress = $null
        $failedProgress = $null

        # 1) Laeuft evtl. noch ein Download (Abbruch fehlgeschlagen)? Dann auf Abschluss warten.
        if (-Not [string]::IsNullOrEmpty($downloadGuid)) {
            Write-Host "Warte auf Abschluss des bereits laufenden Browser-Downloads (Guid: $downloadGuid)"
            $null = Watch-CdpEvents -WebSocket $WebSocket -Seconds $TimeoutSeconds -EventSink $EventSink -StopCondition {
                $null -ne (Find-DownloadProgressInEvents -Events $EventSink -Guid $downloadGuid -States @("completed", "canceled", "failed"))
            }
            $completedProgress = Find-DownloadProgressInEvents -Events $EventSink -Guid $downloadGuid -States @("completed")
            $failedProgress = Find-DownloadProgressInEvents -Events $EventSink -Guid $downloadGuid -States @("canceled", "failed")
            if ($null -ne $failedProgress) {
                Write-Host "Bereits laufender Download wurde abgebrochen/ist fehlgeschlagen (State: $($failedProgress.state)), loese Download neu aus" -ForegroundColor $CommandWarning
                $downloadGuid = ""
                $failedProgress = $null
            }
        }

        # 2) Download neu ausloesen, falls keiner laeuft/abgeschlossen ist
        if ($null -eq $completedProgress -and [string]::IsNullOrEmpty($downloadGuid)) {
            if (-Not [string]::IsNullOrWhiteSpace($Url)) {
                Write-Host "Loese Browser-Download durch Navigation auf die Download-URL aus: $Url"
                $newTarget = Invoke-Cdp -WebSocket $WebSocket -Method "Target.createTarget" -Params @{ url = $Url } -SessionId "" -TimeoutSeconds 60 -EventSink $EventSink
                $extraTargetId = [string](Get-EventPropertyValue -Object $newTarget -Name "targetId")
                $triggerIndex = $EventSink.Count
                $null = Watch-CdpEvents -WebSocket $WebSocket -Seconds $EventWaitSeconds -EventSink $EventSink -StopCondition {
                    $candidate = Find-DownloadCandidateInEvents -Events $EventSink -StartIndex $triggerIndex
                    ($null -ne $candidate -and -Not [string]::IsNullOrEmpty($candidate.Guid))
                }
                $newCandidate = Find-DownloadCandidateInEvents -Events $EventSink -StartIndex $triggerIndex
                if ($null -ne $newCandidate -and -Not [string]::IsNullOrEmpty($newCandidate.Guid)) {
                    $downloadGuid = $newCandidate.Guid
                    if (-Not [string]::IsNullOrWhiteSpace($newCandidate.SuggestedFilename)) {
                        $suggestedName = $newCandidate.SuggestedFilename
                    }
                }
            }
            if ([string]::IsNullOrEmpty($downloadGuid) -and $ButtonIndex -ge 0) {
                if ($null -ne $extraTargetId) {
                    try { $null = Invoke-Cdp -WebSocket $WebSocket -Method "Target.closeTarget" -Params @{ targetId = $extraTargetId } -SessionId "" -TimeoutSeconds 15 -EventSink $EventSink } catch { }
                    $extraTargetId = $null
                }
                Write-Host "Navigation loeste keinen Download aus, klicke den Download-Button (Index $ButtonIndex) erneut"
                $clicked = Invoke-ButtonClick -WebSocket $WebSocket -SessionId $SessionId -Index $ButtonIndex -EventSink $EventSink
                if ($clicked) {
                    $triggerIndex = $EventSink.Count
                    $null = Watch-CdpEvents -WebSocket $WebSocket -Seconds $EventWaitSeconds -EventSink $EventSink -StopCondition {
                        $candidate = Find-DownloadCandidateInEvents -Events $EventSink -StartIndex $triggerIndex
                        ($null -ne $candidate -and -Not [string]::IsNullOrEmpty($candidate.Guid))
                    }
                    $newCandidate = Find-DownloadCandidateInEvents -Events $EventSink -StartIndex $triggerIndex
                    if ($null -ne $newCandidate -and -Not [string]::IsNullOrEmpty($newCandidate.Guid)) {
                        $downloadGuid = $newCandidate.Guid
                        if (-Not [string]::IsNullOrWhiteSpace($newCandidate.SuggestedFilename)) {
                            $suggestedName = $newCandidate.SuggestedFilename
                        }
                    }
                }
            }
            if ([string]::IsNullOrEmpty($downloadGuid)) {
                $attemptResult.Error = "Browser-Download konnte nicht ausgeloest werden (kein Browser.downloadWillBegin-Event)"
                Write-Host $attemptResult.Error -ForegroundColor $CommandWarning
                return $attemptResult
            }
            Write-Host "Browser-Download ausgeloest (Guid: $downloadGuid, Dateiname: $suggestedName)"
        }

        # 3) Auf Abschluss warten (mit Fortschrittsprotokoll)
        if ($null -eq $completedProgress) {
            $progressDeadline = (Get-Date).AddSeconds($TimeoutSeconds)
            $lastProgressLog = Get-Date
            while ($true) {
                $null = Watch-CdpEvents -WebSocket $WebSocket -Seconds 15 -EventSink $EventSink -StopCondition {
                    $null -ne (Find-DownloadProgressInEvents -Events $EventSink -Guid $downloadGuid -States @("completed", "canceled", "failed"))
                }
                $completedProgress = Find-DownloadProgressInEvents -Events $EventSink -Guid $downloadGuid -States @("completed")
                $failedProgress = Find-DownloadProgressInEvents -Events $EventSink -Guid $downloadGuid -States @("canceled", "failed")
                if ($null -ne $completedProgress) { break }
                if ($null -ne $failedProgress) {
                    $attemptResult.Error = "Browser-Download fehlgeschlagen (State: $($failedProgress.state))"
                    Write-Host $attemptResult.Error -ForegroundColor $CommandWarning
                    return $attemptResult
                }
                if ((Get-Date) -gt $progressDeadline) {
                    $attemptResult.Error = "Timeout ($TimeoutSeconds s) beim Warten auf den Abschluss des Browser-Downloads"
                    Write-Host $attemptResult.Error -ForegroundColor $CommandWarning
                    return $attemptResult
                }
                if (((Get-Date) - $lastProgressLog).TotalSeconds -ge 30) {
                    $lastProgressLog = Get-Date
                    $inProgress = Find-DownloadProgressInEvents -Events $EventSink -Guid $downloadGuid -States @("inProgress")
                    if ($null -ne $inProgress) {
                        $receivedMb = [Math]::Round([long]$inProgress.receivedBytes / 1MB, 1)
                        $totalMb = [Math]::Round([long]$inProgress.totalBytes / 1MB, 1)
                        Write-Host "Download-Fortschritt: $receivedMb MB von $totalMb MB"
                    }
                    else {
                        Write-Host "Download laeuft, noch keine Fortschrittsdaten..."
                    }
                }
            }
            Write-Host "Browser-Download abgeschlossen ($([Math]::Round([long]$completedProgress.receivedBytes / 1MB, 1)) MB empfangen)"
        }

        # 4) Groessen-Limit pruefen (500 MB pro Datei bei der Scrapfly-Downloads-API)
        if (-Not [string]::IsNullOrWhiteSpace($suggestedName)) {
            try {
                $metadataResult = Invoke-ScrapiumCommand -WebSocket $WebSocket -Method "ScrapiumBrowser.getDownloadsMetadatas" -SessionId $SessionId -TimeoutSeconds 60 -EventSink $EventSink
                $metadata = Get-EventPropertyValue -Object $metadataResult -Name "metadata"
                if ($null -ne $metadata) {
                    foreach ($metaProperty in $metadata.PSObject.Properties) {
                        Write-Host "Download im Browser: $($metaProperty.Name) ($([Math]::Round([long]$metaProperty.Value / 1MB, 1)) MB)"
                        if ($metaProperty.Name -eq $suggestedName -and [long]$metaProperty.Value -gt $script:MaxScrapflyDownloadBytes) {
                            throw "Datei '$suggestedName' ($([long]$metaProperty.Value) Bytes) ueberschreitet das 500-MB-Limit der Scrapfly-Downloads-API"
                        }
                    }
                }
            }
            catch {
                if ($_.Exception.Message -match "ueberschreitet") { throw }
                Write-Host "Warnung: Download-Metadaten konnten nicht geprueft werden: $($_.Exception.Message)" -ForegroundColor $CommandWarning
            }
        }

        # 5) Datei ueber die Scrapfly-Downloads-API holen
        $downloads = Invoke-ScrapiumCommand -WebSocket $WebSocket -Method "ScrapiumBrowser.getDownloads" -SessionId $SessionId -TimeoutSeconds 900 -EventSink $EventSink
        $guidNames = Get-EventPropertyValue -Object $downloads -Name "guid_names"
        $streams = Get-EventPropertyValue -Object $downloads -Name "streams"
        $filesByGuid = Get-EventPropertyValue -Object $downloads -Name "files_by_guid"
        $files = Get-EventPropertyValue -Object $downloads -Name "files"

        $resolvedName = $suggestedName
        if (-Not [string]::IsNullOrEmpty($downloadGuid) -and $null -ne $guidNames) {
            $guidName = Get-EventPropertyValue -Object $guidNames -Name $downloadGuid
            if (-Not [string]::IsNullOrWhiteSpace($guidName)) { $resolvedName = [string]$guidName }
        }

        $saved = $false
        # 5a) Grosse Dateien kommen als IO-Stream (downloads_stream=1)
        if (-Not $saved -and $null -ne $streams -and -Not [string]::IsNullOrEmpty($downloadGuid)) {
            $streamEntry = Get-EventPropertyValue -Object $streams -Name $downloadGuid
            if ($null -ne $streamEntry) {
                $streamHandle = [string](Get-EventPropertyValue -Object $streamEntry -Name "stream")
                $streamName = Get-EventPropertyValue -Object $streamEntry -Name "name"
                if (-Not [string]::IsNullOrWhiteSpace($streamName)) { $resolvedName = [string]$streamName }
                Write-Host "Datei wird als Stream uebertragen (Handle: $streamHandle)"
                Save-CdpStream -WebSocket $WebSocket -StreamHandle $streamHandle -SessionId $SessionId -Path $TmpPath -EventSink $EventSink -ForceBase64 $true
                $saved = $true
            }
        }
        # 5b) Kleine Dateien kommen inline als Base64
        if (-Not $saved) {
            $inlineBase64 = $null
            if ($null -ne $filesByGuid -and -Not [string]::IsNullOrEmpty($downloadGuid)) {
                $inlineBase64 = Get-EventPropertyValue -Object $filesByGuid -Name $downloadGuid
            }
            if ($null -eq $inlineBase64 -and $null -ne $files -and -Not [string]::IsNullOrWhiteSpace($resolvedName)) {
                $inlineBase64 = Get-EventPropertyValue -Object $files -Name $resolvedName
            }
            if ($null -eq $inlineBase64 -and $null -ne $filesByGuid) {
                $guidProperties = @($filesByGuid.PSObject.Properties)
                if ($guidProperties.Count -eq 1) { $inlineBase64 = $guidProperties[0].Value }
            }
            if ($null -eq $inlineBase64 -and $null -ne $files) {
                $fileProperties = @($files.PSObject.Properties)
                if ($fileProperties.Count -eq 1) {
                    $inlineBase64 = $fileProperties[0].Value
                    if ([string]::IsNullOrWhiteSpace($resolvedName)) { $resolvedName = $fileProperties[0].Name }
                }
            }
            if ($null -ne $inlineBase64) {
                Write-Host "Datei wird inline (Base64) uebertragen"
                $fileBytes = [Convert]::FromBase64String([string]$inlineBase64)
                [System.IO.File]::WriteAllBytes($TmpPath, $fileBytes)
                $saved = $true
            }
        }
        # 5c) Fallback: Einzeldatei per ScrapiumBrowser.getDownload
        if (-Not $saved -and -Not [string]::IsNullOrWhiteSpace($resolvedName)) {
            Write-Host "Datei nicht in getDownloads gefunden, versuche ScrapiumBrowser.getDownload fuer '$resolvedName'" -ForegroundColor $CommandWarning
            $singleDownload = Invoke-ScrapiumCommand -WebSocket $WebSocket -Method "ScrapiumBrowser.getDownload" -Params @{ filename = $resolvedName } -SessionId $SessionId -TimeoutSeconds 900 -EventSink $EventSink
            $singleData = Get-EventPropertyValue -Object $singleDownload -Name "data"
            if ($null -eq $singleData) {
                $singleFiles = Get-EventPropertyValue -Object $singleDownload -Name "files"
                if ($null -ne $singleFiles) { $singleData = Get-EventPropertyValue -Object $singleFiles -Name $resolvedName }
            }
            if ($null -ne $singleData) {
                $fileBytes = [Convert]::FromBase64String([string]$singleData)
                [System.IO.File]::WriteAllBytes($TmpPath, $fileBytes)
                $saved = $true
            }
        }
        if (-Not $saved) {
            $attemptResult.Error = "Datei konnte nicht aus dem Cloud-Browser abgerufen werden (weder Stream noch Inhalt gefunden)"
            Write-Host $attemptResult.Error -ForegroundColor $CommandWarning
            return $attemptResult
        }

        $testResult = Test-DownloadedFile -Path $TmpPath -NameHint $resolvedName -Url $Url -ContentType $null
        $attemptResult.Success = $testResult.Success
        $attemptResult.FileName = $testResult.FileName
        $attemptResult.TooSmall = $testResult.TooSmall
        $attemptResult.Error = $testResult.Reason
        if ($testResult.Success) {
            Write-Host "Scrapfly-API-Download erfolgreich: $($testResult.FileName) ($([Math]::Round((Get-Item -Path $TmpPath).Length / 1MB, 1)) MB)"
        }
        return $attemptResult
    }
    catch {
        $attemptResult.Error = $_.Exception.Message
        Write-Host "Scrapfly-API-Download fehlgeschlagen: $($_.Exception.Message)" -ForegroundColor $CommandWarning
        if (Test-Path -Path $TmpPath) {
            try { Remove-Item -Path $TmpPath -Force } catch { }
        }
        return $attemptResult
    }
    finally {
        if (-Not [string]::IsNullOrEmpty($extraTargetId)) {
            try { $null = Invoke-Cdp -WebSocket $WebSocket -Method "Target.closeTarget" -Params @{ targetId = $extraTargetId } -SessionId "" -TimeoutSeconds 15 -EventSink $EventSink } catch { }
        }
    }
}

# ------------------------------------------------------------------
# Hauptablauf
# ------------------------------------------------------------------

$filename = $null
$webSocket = $null
$tmpRoot = Join-Path $AlyaTemp "Scrapfly-$($AlyaTimeString)"
$sawTooSmallFile = $false
$downloadButtonIndex = -1

try {
    Write-Host "=== Scrapfly Cloud Browser - Datei-Download ===" -ForegroundColor $CommandInfo
    Write-Host "Seite: $PageUrl (os=$Os, country=$Country, proxy=$ProxyPool)"
    Write-Host "Zielverzeichnis: $OutDir"
    $null = New-Item -Path $OutDir -ItemType Directory -Force
    $null = New-Item -Path $tmpRoot -ItemType Directory -Force

    # --- Schritt 1: WebSocket zum Scrapfly Cloud Browser verbinden ---
    Write-Host "Verbinde mit dem Scrapfly Cloud Browser..." -ForegroundColor $CommandInfo
    $queryItems = @(
        "api_key=$([uri]::EscapeDataString($ApiKey))"
        "proxy_pool=$([uri]::EscapeDataString($ProxyPool))"
        "os=$([uri]::EscapeDataString($Os))"
        "country=$([uri]::EscapeDataString($Country))"
        "target_url=$([uri]::EscapeDataString($PageUrl))"
        "solve_captcha=$($(if ($SolveCaptcha) { "true" } else { "false" }))"
        "auto_close=true"
        "timeout=1800"
        "downloads_stream=1"
        "block_images=true"
        "block_media=true"
        "blacklist=true"
    )
    $browserWsUrl = "wss://browser.scrapfly.io?" + ($queryItems -join "&")
    $webSocket = [System.Net.WebSockets.ClientWebSocket]::new()
    $webSocket.Options.KeepAliveInterval = [TimeSpan]::FromSeconds(20)
    try {
        $connectCts = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(90))
        $null = $webSocket.ConnectAsync([uri]$browserWsUrl, $connectCts.Token).GetAwaiter().GetResult()
        $connectCts.Dispose()
    }
    catch {
        throw "CDP-Verbindung zum Scrapfly Cloud Browser fehlgeschlagen: $($_.Exception.Message)"
    }
    Write-Host "Verbunden (State: $($webSocket.State))"

    $eventSink = [System.Collections.Generic.List[object]]::new()

    # --- Schritt 2: Page-Target ermitteln und attachen ---
    $targetsResult = Invoke-Cdp -WebSocket $webSocket -Method "Target.getTargets" -Params $null -SessionId "" -TimeoutSeconds 30 -EventSink $eventSink
    $pageTargetId = $null
    foreach ($targetInfo in $targetsResult.targetInfos) {
        if ($targetInfo.type -eq "page") {
            $pageTargetId = [string]$targetInfo.targetId
            break
        }
    }
    if ([string]::IsNullOrEmpty($pageTargetId)) {
        Write-Host "Kein Page-Target gefunden, erstelle eines" -ForegroundColor $CommandWarning
        $newTarget = Invoke-Cdp -WebSocket $webSocket -Method "Target.createTarget" -Params @{ url = "about:blank" } -SessionId "" -TimeoutSeconds 60 -EventSink $eventSink
        $pageTargetId = [string](Get-EventPropertyValue -Object $newTarget -Name "targetId")
    }
    $attachResult = Invoke-Cdp -WebSocket $webSocket -Method "Target.attachToTarget" -Params @{ targetId = $pageTargetId; flatten = $true } -SessionId "" -TimeoutSeconds 30 -EventSink $eventSink
    $sessionId = [string](Get-EventPropertyValue -Object $attachResult -Name "sessionId")
    if ([string]::IsNullOrEmpty($sessionId)) {
        throw "Target.attachToTarget lieferte keine SessionId (Target: $pageTargetId)"
    }
    Write-Host "Session attacht: $sessionId"

    # --- Schritt 3: Domaenen aktivieren ---
    $null = Invoke-Cdp -WebSocket $webSocket -Method "Page.enable" -Params $null -SessionId $sessionId -TimeoutSeconds 30 -EventSink $eventSink
    $null = Invoke-Cdp -WebSocket $webSocket -Method "Runtime.enable" -Params $null -SessionId $sessionId -TimeoutSeconds 30 -EventSink $eventSink
    $null = Invoke-Cdp -WebSocket $webSocket -Method "Network.enable" -Params $null -SessionId $sessionId -TimeoutSeconds 30 -EventSink $eventSink
    Write-Host "CDP-Domaenen aktiviert (Page, Runtime, Network)"

    # --- Schritt 4: Seite oeffnen und warten, bis sie geladen ist ---
    Write-Host "Oeffne Seite: $PageUrl" -ForegroundColor $CommandInfo
    $navigateResult = Invoke-Cdp -WebSocket $webSocket -Method "Page.navigate" -Params @{ url = $PageUrl } -SessionId $sessionId -TimeoutSeconds 60 -EventSink $eventSink
    $navigateError = Get-EventPropertyValue -Object $navigateResult -Name "errorText"
    if (-Not [string]::IsNullOrWhiteSpace($navigateError)) {
        throw "Page.navigate auf '$PageUrl' fehlgeschlagen: $navigateError"
    }
    $pageReady = $false
    $pageTitle = ""
    $loadDeadline = (Get-Date).AddSeconds($PageLoadWaitSeconds)
    while ((Get-Date) -lt $loadDeadline) {
        try {
            $statusRaw = Get-JsValue -WebSocket $webSocket -Expression $jsStatus -SessionId $sessionId -EventSink $eventSink
            $status = $statusRaw | ConvertFrom-Json
            $pageTitle = [string]$status.title
            if ($status.challenge) {
                Write-Host "Bot-Schutz/CAPTCHA erkannt (Titel: $pageTitle), warte auf automatische Loesung (solve_captcha)..."
            }
            if ($status.ready -eq "complete" -and -not $status.challenge) {
                $pageReady = $true
                break
            }
        }
        catch {
            Write-Host "Warnung: Statusabfrage der Seite fehlgeschlagen: $($_.Exception.Message)" -ForegroundColor $CommandWarning
        }
        Start-Sleep -Seconds 3
    }
    if ($pageReady) {
        Write-Host "Seite geladen (Titel: $pageTitle)"
    }
    else {
        Write-Host "Warnung: Seite innerhalb von $PageLoadWaitSeconds s nicht vollstaendig geladen, fahre dennoch fort" -ForegroundColor $CommandWarning
    }
    # Kurz warten, damit dynamisch nachgeladene Komponenten (Buttons/Links) erscheinen
    Start-Sleep -Seconds 3

    # Cookie-/Consent-Banner akzeptieren, damit sie Klicks nicht blockieren
    try {
        $cookieResult = Get-JsValue -WebSocket $webSocket -Expression $jsAcceptCookies -SessionId $sessionId -EventSink $eventSink | ConvertFrom-Json
        if ($cookieResult.clicked) {
            Write-Host "Cookie-/Consent-Banner akzeptiert ($($cookieResult.how))"
            Start-Sleep -Seconds 2
        }
    }
    catch {
        Write-Host "Warnung: Pruefung auf Cookie-Banner fehlgeschlagen: $($_.Exception.Message)" -ForegroundColor $CommandWarning
    }

    # --- Schritt 5: Multi-Hop-Suche nach dem Download (Links vor Buttons) ---
    # Pro Seite (Hop): zuerst LinkScan; ohne Treffer ButtonScan mit Ranking.
    # Die Regex-Parameter (LinkRegex, ButtonRegex, FileRegex) gelten auf
    # JEDEM Hop gleich. Ein Klick, der weder Download noch Navigation
    # ausloest, fuehrt zum naechsten Button-Kandidaten derselben Seite;
    # eine Navigation fuehrt zum naechsten Hop (neue Seite laden, erneut
    # scannen), bis MaxPageHops erreicht ist.
    $downloadUrl = $null
    $suggestedName = $null
    $knownGuid = ""
    $candidate = $null
    $linkScanJs = Get-LinkScanJs -Regexes $LinkRegex
    $buttonScanJs = Get-ButtonScanJs -Regexes $ButtonRegex
    $jsLocationNoFragment = "(function(){return location.href.split('#')[0];})()"
    $currentLocation = $PageUrl
    $hop = 0
    while ($true) {
        $hopLabel = $(if ($hop -eq 0) { "Startseite" } else { "Hop $hop" })
        Write-Host "--- Suche auf $hopLabel ($currentLocation) ---" -ForegroundColor $CommandInfo

        # 5a) DOM mit LinkRegex nach direkten Download-Links durchsuchen,
        # bei Folgeseiten mit Nachlade-Versuchen (SPA/Challenge-Seiten
        # rendern Inhalte teils verzoegert)
        $links = @()
        $buttons = @()
        $clickableButtons = @()
        # Auch die Startseite kann Inhalte verzoegert rendern (SPA): bis zu
        # 3 Versuche. Ein Versuch gilt erst als erfolgreich, wenn Links ODER
        # mindestens ein klickbarer (nicht negativ gerankter) Button gefunden
        # wurde - "nur Junk-Kandidaten" (Report-/Agreement-Links) zaehlen als
        # unvollstaendig gerenderte Seite und werden erneut gescannt.
        $scanAttempts = 3
        for ($scanAttempt = 1; $scanAttempt -le $scanAttempts; $scanAttempt++) {
            $links = @(Get-JsValue -WebSocket $webSocket -Expression $linkScanJs -SessionId $sessionId -EventSink $eventSink | ConvertFrom-Json)
            if ($FileRegex -and $links.Count -gt 0) {
                $unfilteredCount = $links.Count
                $links = @($links | Where-Object { $_ -match $FileRegex })
                if ($unfilteredCount -ne $links.Count) {
                    Write-Host "FileRegex filtert Link-Kandidaten: $unfilteredCount -> $($links.Count)" -ForegroundColor $CommandInfo
                }
            }
            if ($links.Count -gt 0) { break }
            $buttons = @(Get-JsValue -WebSocket $webSocket -Expression $buttonScanJs -SessionId $sessionId -EventSink $eventSink | ConvertFrom-Json)
            if ($buttons.Count -gt 0) {
                $clickableButtons = @(Get-RankedButtonOrder -Buttons $buttons -TargetOs $Os | Where-Object { $_.Score -ge 0 })
                if ($clickableButtons.Count -gt 0) { break }
            }
            if ($scanAttempt -lt $scanAttempts) {
                Write-Host "Keine Download-Links und keine klickbaren Download-Buttons gefunden (Versuch $scanAttempt von $scanAttempts), warte 8 s auf nachgeladene Inhalte..." -ForegroundColor $CommandWarning
                Start-Sleep -Seconds 8
            }
        }
        Write-Host "$($links.Count) Link(s) passend zum LinkRegex gefunden"
        if ($links.Count -gt 0) {
            foreach ($link in $links) {
                Write-Host "Link-Kandidat: $link"
            }
            $downloadUrl = Select-HighestVersionUrl -Urls $links
            $suggestedName = Get-FileNameFromUrl -Url $downloadUrl
            break
        }

        # 5b) Mit ButtonRegex nach Download-Buttons suchen (Ranking statt DOM-Reihenfolge)
        Write-Host "Keine direkten Download-Links gefunden, suche Download-Buttons..." -ForegroundColor $CommandInfo
        if ($buttons.Count -eq 0) {
            if ($hop -eq 0) {
                throw "Weder Download-Link (LinkRegex) noch Download-Button (ButtonRegex) auf der Seite '$PageUrl' gefunden."
            }
            throw "Auf der Seite '$currentLocation' (Hop $hop) weder Download-Link (LinkRegex) noch Download-Button (ButtonRegex) gefunden."
        }
        foreach ($rankedButton in (Get-RankedButtonOrder -Buttons $buttons -TargetOs $Os)) {
            $hrefInfo = ""
            foreach ($button in $buttons) {
                if ([int]$button.index -eq [int]$rankedButton.Index) {
                    $buttonHref = [string](Get-EventPropertyValue -Object $button -Name "href")
                    if ($buttonHref) { $hrefInfo = " href=$buttonHref" }
                    break
                }
            }
            $junkInfo = $(if ($rankedButton.Score -lt 0) { " [JUNK - wird nicht geklickt]" } else { "" })
            Write-Host "Button-Kandidat: [$($rankedButton.Index)] <$($rankedButton.Tag)> '$($rankedButton.Text)' (Score $($rankedButton.Score))$hrefInfo$junkInfo"
        }
        if ($clickableButtons.Count -eq 0) {
            throw "Auf der Seite '$currentLocation' wurden nur unbrauchbare Button-Kandidaten gefunden (Report-/Agreement-Links o. ae., alle mit negativem Ranking). Die Seite ist moeglicherweise nicht vollstaendig gerendert, oder der gewuenschte Button passt nicht auf ButtonRegex ('$($ButtonRegex -join ', ')')."
        }
        $rankedIndexes = @($clickableButtons | ForEach-Object { [int]$_.Index })
        Write-Host "Klick-Reihenfolge nach Ranking: $($rankedIndexes -join ', ')" -ForegroundColor $CommandInfo

        $navigated = $false
        $candidate = $null
        $perButtonWaitSeconds = [Math]::Min(30, $DownloadEventWaitSeconds)
        foreach ($buttonIndex in $rankedIndexes) {
            $buttonText = ""
            foreach ($button in $buttons) {
                if ([int]$button.index -eq [int]$buttonIndex) { $buttonText = [string]$button.text; break }
            }
            Write-Host "Klicke Download-Button Index $buttonIndex ('$buttonText')..." -ForegroundColor $CommandInfo
            $locationBefore = [string](Get-JsValue -WebSocket $webSocket -Expression $jsLocationNoFragment -SessionId $sessionId -EventSink $eventSink)
            $beforeClick = $eventSink.Count
            $clicked = Invoke-ButtonClick -WebSocket $webSocket -SessionId $sessionId -Index $buttonIndex -EventSink $eventSink
            if (-Not $clicked) {
                Write-Host "Warnung: Button Index $buttonIndex konnte nicht geklickt werden, probiere naechsten Kandidaten" -ForegroundColor $CommandWarning
                continue
            }
            # Auf Download-Events warten; bevorzugt wird Browser.downloadWillBegin
            # (mit Guid + suggestedFilename), damit der Browser-Download sofort
            # abgebrochen werden kann. Zwischendurch moegliche Bestaetigungsdialoge pruefen.
            $firstSegmentSeconds = [Math]::Min(15, $perButtonWaitSeconds)
            $null = Watch-CdpEvents -WebSocket $webSocket -Seconds $firstSegmentSeconds -EventSink $eventSink -StopCondition {
                $watchCandidate = Find-DownloadCandidateInEvents -Events $eventSink -StartIndex $beforeClick
                ($null -ne $watchCandidate -and -Not [string]::IsNullOrEmpty($watchCandidate.Guid))
            }
            $candidate = Find-DownloadCandidateInEvents -Events $eventSink -StartIndex $beforeClick
            if (-Not ($candidate -and -Not [string]::IsNullOrEmpty($candidate.Guid)) -and $perButtonWaitSeconds -gt $firstSegmentSeconds) {
                # Eventuell ist ein Bestaetigungs-/Akzeptieren-Dialog erschienen
                try {
                    $confirm = Get-JsValue -WebSocket $webSocket -Expression $jsConfirmDownload -SessionId $sessionId -EventSink $eventSink | ConvertFrom-Json
                    if ($confirm.clicked) {
                        Write-Host "Bestaetigungsdialog geklickt: '$($confirm.text)'"
                    }
                }
                catch {
                    Write-Host "Warnung: Pruefung auf Bestaetigungsdialog fehlgeschlagen: $($_.Exception.Message)" -ForegroundColor $CommandWarning
                }
                # Fallback: JS-Klick direkt auf das Element (umgeht ueberlagernde
                # Banner/Overlays, die den physischen Mausklick abfangen)
                try {
                    $jsClick = Get-JsValue -WebSocket $webSocket -Expression (Get-ButtonClickJs -Index $buttonIndex) -SessionId $sessionId -EventSink $eventSink | ConvertFrom-Json
                    if ($jsClick.clicked) {
                        Write-Host "Zusaetzlicher JS-Klick auf den Download-Button ausgefuehrt"
                    }
                }
                catch {
                    Write-Host "Warnung: JS-Klick-Fallback fehlgeschlagen: $($_.Exception.Message)" -ForegroundColor $CommandWarning
                }
                $null = Watch-CdpEvents -WebSocket $webSocket -Seconds ($perButtonWaitSeconds - $firstSegmentSeconds) -EventSink $eventSink -StopCondition {
                    $watchCandidate = Find-DownloadCandidateInEvents -Events $eventSink -StartIndex $beforeClick
                    ($null -ne $watchCandidate -and -Not [string]::IsNullOrEmpty($watchCandidate.Guid))
                }
                $candidate = Find-DownloadCandidateInEvents -Events $eventSink -StartIndex $beforeClick
            }
            if ($candidate) {
                $downloadButtonIndex = [int]$buttonIndex
                break
            }
            # Kein Download-Event: Hat der Klick eine Navigation ausgeloest?
            # (Fragment-Wechsel zaehlen nicht - reine In-Page-Anker sind
            # bereits im ButtonScan ausgeschlossen)
            Start-Sleep -Seconds 2
            $locationAfter = [string](Get-JsValue -WebSocket $webSocket -Expression $jsLocationNoFragment -SessionId $sessionId -EventSink $eventSink)
            if ($locationAfter -and $locationAfter -ne $locationBefore) {
                Write-Host "Klick hat Navigation ausgeloest: $locationAfter" -ForegroundColor $CommandInfo
                $currentLocation = $locationAfter
                $navigated = $true
                break
            }
            Write-Host "Klick auf '$buttonText' loeste weder Download noch Navigation aus, probiere naechsten Kandidaten..." -ForegroundColor $CommandWarning
        }

        if ($candidate) {
            Write-Host "Download-Event abgegriffen (Quelle: $($candidate.Source)): $($candidate.Url)"
            $downloadUrl = $candidate.Url
            if (-Not [string]::IsNullOrWhiteSpace($candidate.SuggestedFilename)) {
                $suggestedName = [string]$candidate.SuggestedFilename
            }
            if (-Not [string]::IsNullOrEmpty($candidate.Guid)) {
                # Download-Event im Browser sofort abbrechen - die Datei wird
                # spaeter gezielt geholt (Kaskade unten)
                try {
                    $null = Invoke-Cdp -WebSocket $webSocket -Method "Browser.cancelDownload" -Params @{ guid = $candidate.Guid } -SessionId "" -TimeoutSeconds 30 -EventSink $eventSink
                    Write-Host "Browser-Download abgebrochen (Guid: $($candidate.Guid))"
                }
                catch {
                    Write-Host "Warnung: Browser-Download konnte nicht abgebrochen werden: $($_.Exception.Message)" -ForegroundColor $CommandWarning
                    $knownGuid = [string]$candidate.Guid
                }
            }
            break
        }

        if (-Not $navigated) {
            throw "Kein Button-Kandidat auf der Seite '$currentLocation' hat einen Download oder eine Navigation ausgeloest."
        }
        if ($hop -ge $MaxPageHops) {
            throw "Maximale Anzahl Seitenwechsel erreicht (MaxPageHops=$MaxPageHops), ohne einen Download auszuloesen. Letzte Seite: '$currentLocation'."
        }
        $hop++

        # --- Naechster Hop: neue Seite laden, Cookies akzeptieren, erneut scannen ---
        Write-Host "=== Hop $($hop): warte auf die neue Seite ===" -ForegroundColor $CommandInfo
        $hopPageReady = $false
        $hopDeadline = (Get-Date).AddSeconds($PageLoadWaitSeconds)
        while ((Get-Date) -lt $hopDeadline) {
            try {
                $statusRaw = Get-JsValue -WebSocket $webSocket -Expression $jsStatus -SessionId $sessionId -EventSink $eventSink
                $status = $statusRaw | ConvertFrom-Json
                if ($status.challenge) {
                    Write-Host "Bot-Schutz/CAPTCHA erkannt (Titel: $([string]$status.title)), warte auf automatische Loesung (solve_captcha)..."
                }
                if ($status.ready -eq "complete" -and -not $status.challenge) {
                    $hopPageReady = $true
                    break
                }
            }
            catch {
                Write-Host "Warnung: Statusabfrage der neuen Seite fehlgeschlagen: $($_.Exception.Message)" -ForegroundColor $CommandWarning
            }
            Start-Sleep -Seconds 3
        }
        if ($hopPageReady) {
            Write-Host "Neue Seite geladen ($currentLocation)"
        }
        else {
            Write-Host "Warnung: neue Seite innerhalb von $PageLoadWaitSeconds s nicht vollstaendig geladen, fahre dennoch fort" -ForegroundColor $CommandWarning
        }
        # Kurz warten, damit dynamisch nachgeladene Komponenten (Buttons/Links) erscheinen
        Start-Sleep -Seconds 5
        # Cookie-/Consent-Banner der neuen Seite akzeptieren
        try {
            $hopCookieResult = Get-JsValue -WebSocket $webSocket -Expression $jsAcceptCookies -SessionId $sessionId -EventSink $eventSink | ConvertFrom-Json
            if ($hopCookieResult.clicked) {
                Write-Host "Cookie-/Consent-Banner akzeptiert ($($hopCookieResult.how))"
                Start-Sleep -Seconds 2
            }
        }
        catch {
            Write-Host "Warnung: Pruefung auf Cookie-Banner fehlgeschlagen: $($_.Exception.Message)" -ForegroundColor $CommandWarning
        }
    }

    if (-Not $downloadUrl) {
        throw "Es konnte keine Download-URL ermittelt werden."
    }

    Write-Host "Download-URL: $downloadUrl" -ForegroundColor $CommandInfo
    if (-Not [string]::IsNullOrWhiteSpace($suggestedName)) {
        Write-Host "Originaler Download-Name: $suggestedName"
    }

    # --- Schritt 7: Ziel frueh pruefen (nie Bilder/SVG/PDF/Dokumente) ---
    $earlyName = $suggestedName
    if ([string]::IsNullOrWhiteSpace($earlyName)) {
        $earlyName = Get-FileNameFromUrl -Url $downloadUrl
    }
    if (-Not [string]::IsNullOrWhiteSpace($earlyName)) {
        if (Test-ForbiddenExtension -Name $earlyName) {
            throw "Ziel '$earlyName' ist keine installierbare Datei (Bilder/SVG/PDF/Dokumente werden nie heruntergeladen)."
        }
        if (-Not (Test-InstallerExtension -Name $earlyName)) {
            Write-Host "Warnung: Endung von '$earlyName' ist keine bekannte Installationspaket-Endung, Versuch wird trotzdem gestartet (Pruefung erfolgt nach dem Download)" -ForegroundColor $CommandWarning
        }
        if ($FileRegex -and $earlyName -notmatch $FileRegex) {
            throw "Ermitteltes Ziel '$earlyName' entspricht nicht dem erwarteten Muster (FileRegex: '$FileRegex')."
        }
    }

    # --- Schritt 8: Download-Kaskade ---
    $attemptResults = @()
    $tmpPath = Join-Path $tmpRoot "download.part"

    $directResult = Invoke-DirectDownload -WebSocket $webSocket -Url $downloadUrl -NameHint $suggestedName -TmpPath $tmpPath -Referer $PageUrl -TimeoutSeconds $FileTimeoutSeconds -EventSink $eventSink
    $attemptResults += $directResult
    if (-Not $directResult.Success) {
        if ($directResult.TooSmall) { $sawTooSmallFile = $true }
        $cdpResult = Invoke-CdpResourceDownload -WebSocket $webSocket -SessionId $sessionId -Url $downloadUrl -NameHint $suggestedName -TmpPath $tmpPath -EventSink $eventSink
        $attemptResults += $cdpResult
        if (-Not $cdpResult.Success) {
            if ($cdpResult.TooSmall) { $sawTooSmallFile = $true }
            $browserResult = Invoke-BrowserFileDownload -WebSocket $webSocket -SessionId $sessionId -Url $downloadUrl -NameHint $suggestedName -TmpPath $tmpPath -EventSink $eventSink -KnownGuid $knownGuid -ButtonIndex $downloadButtonIndex -EventWaitSeconds $DownloadEventWaitSeconds -TimeoutSeconds $FileTimeoutSeconds
            $attemptResults += $browserResult
            if (-Not $browserResult.Success) {
                if ($browserResult.TooSmall) { $sawTooSmallFile = $true }
            }
        }
    }

    $successResult = $attemptResults | Where-Object { $_.Success } | Select-Object -First 1
    if (-Not $successResult) {
        $attemptErrors = ($attemptResults | ForEach-Object { $_.Error } | Where-Object { $_ }) -join " | "
        if ($sawTooSmallFile) {
            throw "Die heruntergeladene Datei war kleiner als 1 MB und wurde verworfen. Alle Download-Versuche: $attemptErrors"
        }
        throw "Datei konnte nicht heruntergeladen werden. Alle Download-Versuche: $attemptErrors"
    }

    # --- Schritt 9: Datei mit dem originalen Namen nach OutDir verschieben ---
    $targetPath = Join-Path $OutDir $successResult.FileName
    Move-Item -Path $successResult.TmpPath -Destination $targetPath -Force
    $filename = $successResult.FileName
    $finalSize = (Get-Item -Path $targetPath).Length
    Write-Host "Datei gespeichert: $targetPath ($([Math]::Round($finalSize / 1MB, 1)) MB)" -ForegroundColor $CommandInfo
}
catch {
    Write-Host "FEHLER: $($_.Exception.Message)" -ForegroundColor $CommandError
    if ($_.ScriptStackTrace) {
        Write-Host $_.ScriptStackTrace -ForegroundColor $CommandError
    }
    throw
}
finally {
    if ($null -ne $webSocket) {
        try {
            # CloseOutputAsync statt CloseAsync: ein evtl. noch offener Receive-Task
            # wuerde den Close-Handshake blockieren. Abort beendet ihn danach.
            if ($webSocket.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
                $closeCts = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(5))
                $null = $webSocket.CloseOutputAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "done", $closeCts.Token).GetAwaiter().GetResult()
                $closeCts.Dispose()
            }
        }
        catch {
            # CloseOutput-Fehler sind beim Aufraeumen unkritisch
        }
        try { $webSocket.Abort() } catch { }
        try { $webSocket.Dispose() } catch { }
        Write-Host "Cloud-Browser-Session geschlossen"
    }
    if (Test-Path -Path $tmpRoot) {
        try { Remove-Item -Path $tmpRoot -Recurse -Force } catch { }
    }
    $null = Stop-Transcript
}

return $filename

# SIG # Begin signature block
# MII2OwYJKoZIhvcNAQcCoII2LDCCNigCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBcriIh89lWjQBH
# qlmSMEEmZjs4c+z5JA2j5vGVoXOD96CCFIswggWiMIIEiqADAgECAhB4AxhCRXCK
# Qc9vAbjutKlUMA0GCSqGSIb3DQEBDAUAMEwxIDAeBgNVBAsTF0dsb2JhbFNpZ24g
# Um9vdCBDQSAtIFIzMRMwEQYDVQQKEwpHbG9iYWxTaWduMRMwEQYDVQQDEwpHbG9i
# YWxTaWduMB4XDTIwMDcyODAwMDAwMFoXDTI5MDMxODAwMDAwMFowUzELMAkGA1UE
# BhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExKTAnBgNVBAMTIEdsb2Jh
# bFNpZ24gQ29kZSBTaWduaW5nIFJvb3QgUjQ1MIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAti3FMN166KuQPQNysDpLmRZhsuX/pWcdNxzlfuyTg6qE9aND
# m5hFirhjV12bAIgEJen4aJJLgthLyUoD86h/ao+KYSe9oUTQ/fU/IsKjT5GNswWy
# KIKRXftZiAULlwbCmPgspzMk7lA6QczwoLB7HU3SqFg4lunf+RuRu4sQLNLHQx2i
# CXShgK975jMKDFlrjrz0q1qXe3+uVfuE8ID+hEzX4rq9xHWhb71hEHREspgH4nSr
# /2jcbCY+6R/l4ASHrTDTDI0DfFW4FnBcJHggJetnZ4iruk40mGtwEd44ytS+ocCc
# 4d8eAgHYO+FnQ4S2z/x0ty+Eo7+6CTc9Z2yxRVwZYatBg/WsHet3DUZHc86/vZWV
# 7Z0riBD++ljop1fhs8+oWukHJZsSxJ6Acj2T3IyU3ztE5iaA/NLDA/CMDNJF1i7n
# j5ie5gTuQm5nfkIWcWLnBPlgxmShtpyBIU4rxm1olIbGmXRzZzF6kfLUjHlufKa7
# fkZvTcWFEivPmiJECKiFN84HYVcGFxIkwMQxc6GYNVdHfhA6RdktpFGQmKmgBzfE
# ZRqqHGsWd/enl+w/GTCZbzH76kCy59LE+snQ8FB2dFn6jW0XMr746X4D9OeHdZrU
# SpEshQMTAitCgPKJajbPyEygzp74y42tFqfT3tWbGKfGkjrxgmPxLg4kZN8CAwEA
# AaOCAXcwggFzMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzAP
# BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQfAL9GgAr8eDm3pbRD2VZQu86WOzAf
# BgNVHSMEGDAWgBSP8Et/qC5FJK5NUPpjmove4t0bvDB6BggrBgEFBQcBAQRuMGww
# LQYIKwYBBQUHMAGGIWh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL3Jvb3RyMzA7
# BggrBgEFBQcwAoYvaHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# cm9vdC1yMy5jcnQwNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxz
# aWduLmNvbS9yb290LXIzLmNybDBHBgNVHSAEQDA+MDwGBFUdIAAwNDAyBggrBgEF
# BQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wDQYJ
# KoZIhvcNAQEMBQADggEBAKz3zBWLMHmoHQsoiBkJ1xx//oa9e1ozbg1nDnti2eEY
# XLC9E10dI645UHY3qkT9XwEjWYZWTMytvGQTFDCkIKjgP+icctx+89gMI7qoLao8
# 9uyfhzEHZfU5p1GCdeHyL5f20eFlloNk/qEdUfu1JJv10ndpvIUsXPpYd9Gup7EL
# 4tZ3u6m0NEqpbz308w2VXeb5ekWwJRcxLtv3D2jmgx+p9+XUnZiM02FLL8Mofnre
# kw60faAKbZLEtGY/fadY7qz37MMIAas4/AocqcWXsojICQIZ9lyaGvFNbDDUswar
# AGBIDXirzxetkpNiIHd1bL3IMrTcTevZ38GQlim9wX8wggboMIIE0KADAgECAhB3
# vQ4Ft1kLth1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkw
# FwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENv
# ZGUgU2lnbmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAw
# MDBaMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIw
# MAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAy
# MDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj
# /SBerjgSi8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlM
# g7BKRFAEeIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRV
# X5YLEeWatSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV
# 0xHK5s2zBZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEz
# IHXMsdXtHQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMk
# oog28vmfvpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq
# 7rfYrWGlr3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult
# 5a/dm2tjIF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNu
# twFsDeCXpxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYy
# AjIwfLWTyCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofn
# GrhO7izB36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
# FgQUJZ3Q/FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0
# Q9lWULvOljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8v
# b2NzcC5nbG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUH
# MAKGOmh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWdu
# aW5ncm9vdHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJ
# KwYBBAGgMgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24u
# Y29tL3JlcG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJ
# yTm6t6E5iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbV
# YQLFY4/UovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQt
# pFg6bBNJ+KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSX
# hndGKj0jfShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6
# bs+XYXvfcXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nO
# ZNm9/Lws80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOH
# X5OKSBoRHeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dq
# cYC/lt5yA9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0i
# xxnJpsoOqHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7
# qWPLd0jV+mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72
# f1LiSY25EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB/UwggXdoAMCAQICDB/ud0g6
# 04YfM/tV5TANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjAwHhcNMjUwMjA0MDgyNzE5WhcNMjgwMjA1MDgy
# NzE5WjCCATYxHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRgwFgYDVQQF
# Ew9DSEUtMjQ1LjIyNi43NDgxEzARBgsrBgEEAYI3PAIBAxMCQ0gxFzAVBgsrBgEE
# AYI3PAIBAhMGQWFyZ2F1MQswCQYDVQQGEwJDSDEPMA0GA1UECBMGQWFyZ2F1MRYw
# FAYDVQQHEw1PYmVyZW50ZmVsZGVuMRQwEgYDVQQJEwtQZnJ1bmR3ZWcgMzEsMCoG
# A1UEChMjQWx5YSBDb25zdWx0aW5nIEluaC4gS29ucmFkIEJydW5uZXIxLDAqBgNV
# BAMTI0FseWEgQ29uc3VsdGluZyBJbmguIEtvbnJhZCBCcnVubmVyMSUwIwYJKoZI
# hvcNAQkBFhZpbmZvQGFseWFjb25zdWx0aW5nLmNoMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAzMcA2ZZU2lQmzOPQ63/+1NGNBCnCX7Q3jdxNEMKmotOD
# 4ED6gVYDU/RLDs2SLghFwdWV23B72R67rBHteUnuYHI9vq5OO2BWiwqVG9kmfq4S
# /gJXhZrh0dOXQEBe1xHsdCcxgvYOxq9MDczDtVBp7HwYrECxrJMvF6fhV0hqb3wp
# 8nKmrVa46Av4sUXwB6xXfiTkZn7XjHWSEPpCC1c2aiyp65Kp0W4SuVlnPUPEZJqt
# f2phU7+yR2/P84ICKjK1nz0dAA23Gmwc+7IBwOM8tt6HQG4L+lbuTHO8VpHo6GYJ
# QWTEE/bP0ZC7SzviIKQE1SrqRTFM1Rawh8miCuhYeOpOOoEXXOU5Ya/sX9ZlYxKX
# vYkPbEdx+QF4vPzSv/Gmx/RrDDmgMIEc6kDXrHYKD36HVuibHKYffPsRUWkTjUc4
# yMYgcMKb9otXAQ0DbaargIjYL0kR1ROeFuuQbd72/2ImuEWuZo4XwT3S8zf4rmmY
# F8T4xO2k6IKJnTLl4HFomvvL5Kv6xiUCD1kJ/uv8tY/3AwPBfxfkUbCN9KYVu5X2
# mMIVpqWCZ1OuuQBnaH+m6OIMZxP7rVN1RbsHvZnOvCGlukAozmplxKCyrfwNFaO7
# spNY6rQb3TcP6XzB8A6FLVcgV8RQZykJInUhVkqx4B1484oLNOTTwWj3BjiLAoMC
# AwEAAaOCAdkwggHVMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8w
# TAYIKwYBBQUHMAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0
# L2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6
# Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBV
# BgNVHSAETjBMMEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3
# dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAA
# MEcGA1UdHwRAMD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nn
# Y2NyNDVldmNvZGVzaWduY2EyMDIwLmNybDAhBgNVHREEGjAYgRZpbmZvQGFseWFj
# b25zdWx0aW5nLmNoMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB8GA1UdIwQYMBaAFCWd
# 0PxZCYZjxezzsRM7VxwDkjYRMB0GA1UdDgQWBBTpsiC/962CRzcMNg4tiYGr9Ubd
# 2jANBgkqhkiG9w0BAQsFAAOCAgEAHUdaTxX5PlIXXqquyClCSobZaP1rH4a2OzVy
# /fAHsVv1RtHmQnGE6qFcGomAF33g3B+JvitW9sPoXuIPrjnWSnXKzEmpc3mXbQmW
# 2H3Bh6zNXULENnniCb16RD0WockSw3eSH9VGcxAazRQqX6FbG3mt4CaaRZiPnWT0
# MP6pBPKOL6LE/vDOtvfPmcaVdofzmJYUhLtlfi1wiRlfHipIpQ3MFeiD1rWXwQq/
# pFL9zlcctWFE7U49lbHK4dQWASTRpcM6ZeIkzYVEeV8ot/4A0XSx1RasewnuTcex
# U0bcV0hLQ4FZ8cow0neGTGYbW4Y96XB9UFW++dfubzOI0DtpMjm5o1dUVHkq+Ehf
# 6AMOGaM56A6fbTjOjOSBJJUeQJKl/9JZA0hOwhhUFAZXyd8qIXhOMBAqZui+dzEC
# p9LnR+34c+KVJzsWt8x3Kf5zFmv2EnoidpoinpvGw4mtAMCobgui8UGx3P4aBo9m
# UF5qE6YwQqPOQK7B4xmXxYRt8okBZp6o2yLfDZW2hUcSsUPjgferbqnNpWy6q+Ku
# aJRsz+cnZXLZGPfEaVRns0sXSy81GXujo8ycWyJtNiymOJHZTWYTZgrIAa9fy/Jl
# N6m6GM1jEhX4/8dvx6CrT5jD+oUac/cmS7gHyNWFpcnUAgqZDP+OsuxxOzxmutof
# dgNBzMUxgiEGMIIhAgIBATBsMFwxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
# YWxTaWduIG52LXNhMTIwMAYDVQQDEylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29k
# ZVNpZ25pbmcgQ0EgMjAyMAIMH+53SDrThh8z+1XlMA0GCWCGSAFlAwQCAQUAoHww
# EAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIP0inwcS
# 3QGgaJeNBxcYTWg1I6Vt6+Un6ifxxvuWprs9MA0GCSqGSIb3DQEBAQUABIICAKiY
# 948ZLOSWfW9TQTrpc/TkpxzzlbHyNPUdeO6YfTiDShv8T5Pc15cwG3gWpnGQQcWU
# R99DquxhzWxZjE+bIz2hxVZQFfa7lwKRZKPKPDsw8wGy8/koErj3EByyfktGySo6
# GnmhrMipce+WTymzhqrJ7/nndcrfunu7vPlrh1D+ttwyRnQrft0g52qjJRlBsPPT
# f+h0xFGqwdqMd6FFrI8HoKUiY8BlamXcvQtLeaBSKHWE7tsWOiTLLEd/QRQsewUG
# ToA9zc/k4rtpRVbjQ8D9+hXYGuiv2NQ25QNBBpHKxv20EYfaJquzu/9V0KTpz7fa
# I2f9oYxf0IM0T4cQExKFlWXWRjzz/MnqcIvScr1+5nDjK/Mtq/uEFhPkMeM2HSVQ
# QUvsCEoUHrqvqpp92tymUgfxEhT+ildk+p5ihFUHa4vymoS2lDRoydqrCdXiF7un
# 0o46LjDOuqXbocfjoufKXsVLzjQ5CFMrhRj9desNRJgeQg5stBSDxlfwhKhZZLYJ
# RQ0pJEO1Ag0XdU+dBLppD+NXjatT3aTh8eKkaL+QXf1lH7tqQqE8lMZfH7ZOw151
# zRMCl65BownoRUFJDUhWkImNAF5EPWguHWFQ9xLIfX2EWrCT6aEfh6ERZx7horwk
# teKV/ijmqh4pe8dDD13/ejrBvpFP9767/aCe2YasoYId7TCCHekGCisGAQQBgjcD
# AwExgh3ZMIId1QYJKoZIhvcNAQcCoIIdxjCCHcICAQMxDTALBglghkgBZQMEAgIw
# geQGCyqGSIb3DQEJEAEEoIHUBIHRMIHOAgEBBgsrBgEEAaAyAgMCAjAxMA0GCWCG
# SAFlAwQCAQUABCAkxdZVCKeOCMsXxM/TkGL0KNpXDHx5wt64xunfLyEwZAIUCSpC
# /SyljMnogcxKq5QaJXNq1swYDzIwMjYwOTA5MTgwNjAyWjADAgEBoF2kWzBZMQsw
# CQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMm
# R2xvYmFsc2lnbiBSNDUgVFNBIGZvciBDb2RlU2lnbiAyMDI1MTCgghlgMIIGijCC
# BHKgAwIBAgIRAIRyP8GVzBbx2yui9mDfK+QwDQYJKoZIhvcNAQEMBQAwXjELMAkG
# A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0ds
# b2JhbFNpZ24gT2ZmbGluZSBSNDUgVGltZXN0YW1waW5nIENBIDIwMjUwHhcNMjUx
# MDE1MDcyNTA0WhcNMzcwMTEwMDAwMDAwWjBZMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTEvMC0GA1UEAxMmR2xvYmFsc2lnbiBSNDUgVFNB
# IGZvciBDb2RlU2lnbiAyMDI1MTAwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGK
# AoIBgQDRSo2hjYZASCijCQSc2RMQPPKojE/xf4Uija2JnsJ7Snl2gDoxKjQ9HcU6
# rVD8pgy1sBKdVxtLLFhY3gzY/PA2iwIs6ZzCnxshtjShsN1RyzRrzc4Fq+0xQx6q
# ADUMn96mqHE/0ok53DPbmpBkkUDytGM79nQfw9WVymYgA+TkbA0/QOmPNNJIZ6Cj
# X0t3wJfhL0caiXthBBMEWKxT5v2U7ZRbCq/DVDXA9oX1iFVBVaBpx57MLL00nyHu
# x0InYS7Rr54M3tNhm7+0maxpyTFa51uY1PHtTJMup/l3RGooQ5YweCH2hDoUNwKO
# C7QkFbklhPdq27EXkueg8qLOnRDmVO1r+B1yMAbl6QuV0L+OPB1SKBAPpmIFklmJ
# 0SoibbUqxsTzejjdI+ywQLUcXilogwKWsJ46h6wjlU5AVqT7FEBYzWCTt6hf7SLQ
# bPGs02Ba8oaaNfo0SL+aApN94luEB/wuE1lgptrckLzbQlCp56OgkAJYpqYuui+T
# fueCIU0CAwEAAaOCAcYwggHCMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAK
# BggrBgEFBQcDCDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQy+tPhB2gnkGsI0j8d
# PIxlNigGGTAfBgNVHSMEGDAWgBR3AjsBMQ8edHfDSMjDB2NViKU7ojCBpQYIKwYB
# BQUHAQEEgZgwgZUwQgYIKwYBBQUHMAGGNmh0dHA6Ly9vY3NwLmdsb2JhbHNpZ24u
# Y29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNTBPBggrBgEFBQcwAoZDaHR0
# cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3NvZmZsaW5lcjQ1dGlt
# ZXN0YW1wY2EyMDI1LmNydDBKBgNVHR8EQzBBMD+gPaA7hjlodHRwOi8vY3JsLmds
# b2JhbHNpZ24uY29tL2dzb2ZmbGluZXI0NXRpbWVzdGFtcGNhMjAyNS5jcmwwVgYD
# VR0gBE8wTTAIBgZngQwBBAIwQQYJKwYBBAGgMgEeMDQwMgYIKwYBBQUHAgEWJmh0
# dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMA0GCSqGSIb3DQEB
# DAUAA4ICAQCOrnCmj0eGkYpuniz6/WFm91s6KjnhkMKYlbcftgpMBtlhysVniEOf
# BvhcvoFQw4AOHG9NRVvZpkBnag5Dt1HM3Jg21gRVCBwFyP1ET8IDxoflYx5OD4SC
# NLHs6vCg6rFkNT81v9Zy8u0xXy3WboN5iK/SbTmLGqCrAGJihLLrfIhvddwVrdBy
# iHteLxgjugT6JQogCSoBF2JqmH0ZBCl515btbTuWZLrQUs5vvl2o98Mdju9yyJRW
# LzPVcUkRk9d8xBBi638FBOAuo3fcyThGcne7wUOa+TghhwIHbZ3pxTYpgo5cCxEZ
# sH8EXwiTUTwHf0qesssg/2XdcGH7s0AR4TyOJ2QnAayYOAM/XOBxNzURQg4mhMdP
# L/F8VCMKj3koJaVcx2akh0B82le/aBU8q2Oa++OwOwiHF5e+f9m+yhyYbwGSogWI
# V3hgRl+VyKrch8gv35FHr/cVz8n0/CPGRXGiYJZ7P1wOOgYdkMD2iDKVYQby5Ix/
# xCB0/lSKLnqEoFezfmnCJbGgACVswMsxhJEUjtxEcQc9afalne+IOts0v/yCRikJ
# snmVbS0x50Dk2OH+VCiU9s/XyzgfC7WzrtQ5diIdc2Ksi3JMTJm4a0LiEIZWitD5
# +6PokOkQ8+35TsHOwUhs87I/yyJjlIZpAV4Of1/JN8bWVB3Edm4WzjCCBqAwggSI
# oAMCAQICEQCD2oY3t58MhAyUe4QKUngfMA0GCSqGSIb3DQEBDAUAMFMxCzAJBgNV
# BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9i
# YWxTaWduIFRpbWVzdGFtcGluZyBSb290IFI0NTAeFw0yNTA3MTYwMzA1MDRaFw00
# MTA3MTYwMDAwMDBaMF4xCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWdu
# IG52LXNhMTQwMgYDVQQDEytHbG9iYWxTaWduIE9mZmxpbmUgUjQ1IFRpbWVzdGFt
# cGluZyBDQSAyMDI1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApHcW
# +O19i+LdAoZFYzS+5X+WYvnWoFqXAfir1hynhUTdH4RW1Db+yOmrQ275jlsQ6bzo
# Z3nN0CMncZX4E0Qhpp6Qvx27+flpfzeMQacD7VciWUiF3TLiu7wT2bBCSENUn3hf
# GMG4PJvYFvO5o4DA1iNvHhG4oSzctodoJfb4c8EjVahCw/NLizB3ra+NWe2gZBSa
# ZKraMxFt676yqx7RcQnjbF4R0OLGovsZt23vU69A5BdoPxdA9zu9rM+qTBsPDVUJ
# exYwEVU0GY7BJ5mUWWniyAPHW0Wv4Azk5t7I0XUIjA3+2OGkr0dVBXVBDyEeGBVr
# YXEdhfVLwuh6HBGJFdIrEY5KoGlpoT+4BBQe4XCH5sv15Uo+M72VKWjPA5Ex3nfF
# JC4P5FW1SR6olCSaIrtnZzc+zgmpSyiD+GcE2udQRQHbDi74enXgazk0+ktpHZ1Z
# 8oTvSaSIREovXSLbH3KC8uFIkXucl7XPH7ZGIrmF9eF4zuoo5FIUnsvV60kLqFDz
# Pk+UbLmgZDUCPlFFBBehaaNvixEymx9ON2KXev+MfK6OZChqGbrOC2wvvAFHyKlT
# ZbVHdqNiu0u5a2T1C9dSTRny1/hxLwcxL9BWPzQLwhsiyXqUzM7uD0lD9+PYMaxU
# YgoVSxqb4xvPCiVqLNabI+WtjEzYfQ0P+6tBTFsCAwEAAaOCAWIwggFeMA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDASBgNVHRMBAf8ECDAGAQH/
# AgEAMB0GA1UdDgQWBBR3AjsBMQ8edHfDSMjDB2NViKU7ojAfBgNVHSMEGDAWgBRG
# shx34XsV8KU5oXDe0cQu6m2y3jCBjgYIKwYBBQUHAQEEgYEwfzA3BggrBgEFBQcw
# AYYraHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vdGltZXN0YW1wcm9vdHI0NTBE
# BggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQv
# dGltZXN0YW1wcm9vdHI0NS5jcnQwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2Ny
# bC5nbG9iYWxzaWduLmNvbS90aW1lc3RhbXByb290cjQ1LmNybDARBgNVHSAECjAI
# MAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggIBADKj7n7RbuRmMZZYXqlMPRJoR6X1
# n//quXGLVfOpFoR9Ya05L94w0ywBjelyGGf+nAB+CZFQ7gUOd2a2bpfpW8Xw5ArM
# +YjPEf8AtC4E6Yr105U1YNjlTSERoWJKc1hkSN5m4dpsYteFykzFQVwX50hYKH3y
# Z6Vcu6Ha0EA5ofzLpi2jK2jbRDCXbFNLi5mO1xKRdB2AzAF0f5C00b4H3d5sCOB8
# njTvAwaTMGEMeTkLWM4Z9Y+3UOtOpo1QuxXbDpXVkLXraG25iL1VtvjxEAy4534n
# UINB9whORicJJSTLba6fOK2f/1QGWEdewWLHAzE+N5oH0QoNRALpJ5JjIfeInvO+
# sQdBidnPuLKJ95HTj7XyMvJhFZjtbHJGlEWx4UgKcuNKLDLXWALfwQDN2Dey3kTf
# d4yw4nQdk1PctLLK3F4L2nnLv94BMkpY+Rfl53oOEN4yTvtwCYP+VDuZrktc7Nac
# oTVxZnKGkv8a1akckdOwQZC+i8Ay1VyzMAX/Tb4+r3c65B7cpAtq3OoUijXUJgvZ
# xci6TX78smL2TYy2tWn+8G4krnXvy2ELR2XYnKEOS4MVmrSCsjM5nxSrghE10VDX
# QbEfa93lhikfFoIuINKzWDLqvu8ZucmxEufxpHjNnnRVXX/Zv5KQq8pu/MQoOz6D
# C74n5+O5bSwvT5sgMIIGozCCBIugAwIBAgIQeEqqgXNmnJAJVOQhyUfrwDANBgkq
# hkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSNjET
# MBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0yMDEy
# MDkwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIFRpbWVzdGFt
# cGluZyBSb290IFI0NTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALp0
# M+wn3BI4IRvF02Eo1lq8T9+LzJGEQyRXvGQhvDscHz1PjK0Ht/PF1wLpERSCmqq0
# lHI7cQ0a72hrhXmOr2bqWJgNusF8edL/zbNvMUXQBXQEAHJqJ364Nz86iO2Xg/Wr
# NU0Pn1k79S/fWcV8pTJ2YJbI7e74BH4ZUXKov0RBerx7HjsAm7y64Ja/kP6Nm8Ny
# iwAS+CA6YDj3wcyFivuHeS6hKyDmy6CFkSO2xCgHVCje7BAxT4ryzRQfHt1VHOoo
# MUz5IWqozfOWZ/oBQZvNDwtof7ve8UPqF+Ww3HAis2k2WXRrxuWJKnzlC4Fdqz+P
# uNF2cvN8oqnil0G/zIxF/mHJ9mwHCwAE6BUjT4IqLfbvw/oRNkih0f16OTo0XaMs
# Dpt3UCA0QN2xAzGtX+lih3OWA2H3lLDZXGxP5xTF4fF7DSOczXCMHWreSi2LKrvb
# QhQFB6r7FNwx0/YfbMu+aGZEcE1tF/lx6wVzjpGSdetoXB72RGEYKWLdF2aI7Ci6
# SW/bPnf+uTEfdRwYoqZHvdjuSIU7/bPiDz8qmMaa+oJvsaWlhh1aOvqkbHQPd1Jh
# an+HKd45m4vus0VgMCSXFRIqhTCTJqyWpi3ocG0LqTKtLJsoCnZC8lVhUZiU3u32
# xRdvPBUQsA6tsN7FFvRl0cwvWlYIz5nE8FWRwix5AgMBAAGjggF4MIIBdDAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDwYDVR0TAQH/BAUwAwEB
# /zAdBgNVHQ4EFgQURrIcd+F7FfClOaFw3tHELuptst4wHwYDVR0jBBgwFoAUrmwF
# o5MT4qLn4tcc1sfwf8hnU6AwewYIKwYBBQUHAQEEbzBtMC4GCCsGAQUFBzABhiJo
# dHRwOi8vb2NzcDIuZ2xvYmFsc2lnbi5jb20vcm9vdHI2MDsGCCsGAQUFBzAChi9o
# dHRwOi8vc2VjdXJlLmdsb2JhbHNpZ24uY29tL2NhY2VydC9yb290LXI2LmNydDA2
# BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL3Jvb3Qt
# cjYuY3JsMEcGA1UdIARAMD4wPAYEVR0gADA0MDIGCCsGAQUFBwIBFiZodHRwczov
# L3d3dy5nbG9iYWxzaWduLmNvbS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQwFAAOC
# AgEAi0i6Nlc8csXadfnvMvWGvdwSKOOILk82XyaZ7A8BIRCWkjjGcGtt867UDr0l
# 74Z/4omNlaV+KUQDTaqYqPG33OopYyHc7c2ICssQaWF5KUIMI7zpxe9SHi8zN9VP
# ZnpmqUdUM7HdFvLYZHGjMZTlb/ZNS+KEbNDJJWdPyEvQzksF1j37fUH6irHAIeB+
# CLDZZCv56vLHCvTPLgw0YO5su5LwP/F7UhJod1mB9RwupDqMOQMN7eXMr2ZIeWPV
# Sbj/S9IlT0hOkzuTd7CaSGy2oB2zdJ5fvSIEO3w3DYW1w5q73ZxaA420DZ9MdjTV
# ha1Fe7Wfuy6Ju6zIv5JjSMY/yheqDbwAEV+L6ONDhIpDNM39O8Cie9sfuGfIjBXe
# P6Z/xyjvoW9vskHPAiLrAfhLyNJ2byXfXtpoaD17RATCQW5JO6eYVgTt0SYrBJTb
# 5O1mjj2AnaSkVXlQXuP4Gh/AFm+QFTyKpkihDHu6KuCxqYcFRpvtJVU9N2mY7UaZ
# mIVHCh5i2/2c5cFDQo69z2/2jJH9guSf7K3jlVUF80kvbTT3/2fumUC705qAQkDa
# I4lgH4NxkrXp5soK+d3HbLJYQZxmjZsqbx9vVwRDXINdO2mc3jn6hE0183sbbYvx
# bwPBKVLilL97VIvfQHoLcAJ3Py+IBwIAddKvxtYiMhmjO+gwggWDMIIDa6ADAgEC
# Ag5F5rsDgzPDhWVI5v9FUTANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9i
# YWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
# AxMKR2xvYmFsU2lnbjAeFw0xNDEyMTAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMEwx
# IDAeBgNVBAsTF0dsb2JhbFNpZ24gUm9vdCBDQSAtIFI2MRMwEQYDVQQKEwpHbG9i
# YWxTaWduMRMwEQYDVQQDEwpHbG9iYWxTaWduMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAlQfoc8pm+ewUyns89w0I8bRFCyyCtEjG61s8roO4QZIzFKRv
# f+kqzMawiGvFtonRxrL/FM5RFCHsSt0bWsbWh+5NOhUG7WRmC5KAykTec5RO86eJ
# f094YwjIElBtQmYvTbl5KE1SGooagLcZgQ5+xIq8ZEwhHENo1z08isWyZtWQmrcx
# BsW+4m0yBqYe+bnrqqO4v76CY1DQ8BiJ3+QPefXqoh8q0nAue+e8k7ttU+JIfIwQ
# Bzj/ZrJ3YX7g6ow8qrSk9vOVShIHbf2MsonP0KBhd8hYdLDUIzr3XTrKotudCd5d
# RC2Q8YHNV5L6frxQBGM032uTGL5rNrI55KwkNrfw77YcE1eTtt6y+OKFt3OiuDWq
# RfLgnTahb1SK8XJWbi6IxVFCRBWU7qPFOJabTk5aC0fzBjZJdzC8cTflpuwhCHX8
# 5mEWP3fV2ZGXhAps1AJNdMAU7f05+4PyXhShBLAL6f7uj+FuC7IIs2FmCWqxBjpl
# llnA8DX9ydoojRoRh3CBCqiadR2eOoYFAJ7bgNYl+dwFnidZTHY5W+r5paHYgw/R
# /98wEfmFzzNI9cptZBQselhP00sIScWVZBpjDnk99bOMylitnEJFeW4OhxlcVLFl
# tr+Mm9wT6Q1vuC7cZ27JixG1hBSKABlwg3mRl5HUGie/Nx4yB9gUYzwoTK8CAwEA
# AaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYE
# FK5sBaOTE+Ki5+LXHNbH8H/IZ1OgMB8GA1UdIwQYMBaAFK5sBaOTE+Ki5+LXHNbH
# 8H/IZ1OgMA0GCSqGSIb3DQEBDAUAA4ICAQCDJe3o0f2VUs2ewASgkWnmXNCE3tyt
# ok/oR3jWZZipW6g8h3wCitFutxZz5l/AVJjVdL7BzeIRka0jGD3d4XJElrSVXsB7
# jpl4FkMTVlezorM7tXfcQHKso+ubNT6xCCGh58RDN3kyvrXnnCxMvEMpmY4w06wh
# 4OMd+tgHM3ZUACIquU0gLnBo2uVT/INc053y/0QMRGby0uO9RgAabQK6JV2NoTFR
# 3VRGHE3bmZbvGhwEXKYV73jgef5d2z6qTFX9mhWpb+Gm+99wMOnD7kJG7cKTBYn6
# fWN7P9BxgXwA6JiuDng0wyX7rwqfIGvdOxOPEoziQRpIenOgd2nHtlx/gsge/lgb
# KCuobK1ebcAF0nu364D+JTf+AptorEJdw+71zNzwUHXSNmmc5nsE324GabbeCglI
# WYfrexRgemSqaUPvkcdM7BjdbO9TLYyZ4V7ycj7PVMi9Z+ykD0xF/9O5MCMHTI8Q
# v4aW2ZlatJlXHKTMuxWJU7osBQ/kxJ4ZsRg01Uyduu33H68klQR4qAO77oHl2l98
# i0qhkHQlp7M+S8gsVr3HyO844lyS8Hn3nIS6dC1hASB+ftHyTwdZX4stQ1LrRgyU
# 4fVmR3l31VRbH60kN8tFWk6gREjI2LCZxRWECfbWSUnAZbjmGnFuoKjxguhFPmzW
# AtcKZ4MFWsmkEDGCA2EwggNdAgEBMHMwXjELMAkGA1UEBhMCQkUxGTAXBgNVBAoT
# EEdsb2JhbFNpZ24gbnYtc2ExNDAyBgNVBAMTK0dsb2JhbFNpZ24gT2ZmbGluZSBS
# NDUgVGltZXN0YW1waW5nIENBIDIwMjUCEQCEcj/BlcwW8dsrovZg3yvkMAsGCWCG
# SAFlAwQCAqCCAUEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMCsGCSqGSIb3
# DQEJNDEeMBwwCwYJYIZIAWUDBAICoQ0GCSqGSIb3DQEBDAUAMD8GCSqGSIb3DQEJ
# BDEyBDD8bt6s/Mb5tARyPcLXC2hMORyZiN47nOfSYk4+2tLEE1xgGXyCeNLZPNPl
# +ltlLN0wgbQGCyqGSIb3DQEJEAIvMYGkMIGhMIGeMIGbBCCDKtcuUj/erIP6RpS8
# 58bMJhdkiChmVmWIyK3KOoOFUTB3MGKkYDBeMQswCQYDVQQGEwJCRTEZMBcGA1UE
# ChMQR2xvYmFsU2lnbiBudi1zYTE0MDIGA1UEAxMrR2xvYmFsU2lnbiBPZmZsaW5l
# IFI0NSBUaW1lc3RhbXBpbmcgQ0EgMjAyNQIRAIRyP8GVzBbx2yui9mDfK+QwDQYJ
# KoZIhvcNAQEMBQAEggGAvesMT7Gpn6fRPvI3wMnss2m0wbiKj0YMIchC0tCWAOgo
# /yBFMuF7q/iipUHpmbjbn87AK2k38xlqM9KolJawxdKzcepRLk0tDCBv/Amx+H7x
# 3mHvN2lvEbn5ec9CVj9rSY6oV358kKl1dvs9Hs6WFZ1ybUsIzuvjA2rfc6suha1H
# Z1jZUZm7xvvq2z8ooOEVLLkBZpfmU1G7U/VEQxbNmubfsPwZ69Kr0pszs1jbavR1
# DXfseruvf7R4erRZ8eCVuM+af4aKa/CFC67TsknHdZLjB0tihfmWMDFCYko3gI/C
# WHsKkCpMC5c+H18/f9eOV/UNhrCk0V1/eqcN78dBNXp677ULDwtanihn0++4a8uW
# +9m5V7we96LqnQgZxRy343Thi7xQL/AvcLFOn+bT38FhK/YI/tnGcQZ+I79fTeKv
# v5VXH/ddHDeU98tqkgHjOmCOwmzC6aiU4wUNXzhWaift3hBiKfKFObP37yy+aGvB
# 2V8JmwSxfJoW0bqcWC9X
# SIG # End signature block
