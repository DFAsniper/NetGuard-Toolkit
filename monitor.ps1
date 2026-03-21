## =========================================
## CONFIGURATION
## =========================================

# Detect default gateway automatically
$gateway = (Get-NetRoute -AddressFamily IPv4 |
    Where-Object {
        $_.DestinationPrefix -eq '0.0.0.0/0' -and
        $_.NextHop -ne '0.0.0.0'
    } |
    Sort-Object RouteMetric |
    Select-Object -First 1).NextHop

# Safety check
if (-not $gateway) {
    Write-Host "❌ Could not detect gateway automatically." -ForegroundColor Red
    exit
}

Write-Host "🌐 Detected Gateway: $gateway" -ForegroundColor Cyan

$internet = "8.8.8.8"

$logFolder = "$env:USERPROFILE\Desktop\NetworkMonitorLogs"

## Rolling window size for live packet loss
$windowSize = 30

## =========================================
## VALIDATE LOG FOLDER
## =========================================

if (-not (Test-Path $logFolder)) {
    Write-Host "ERROR: Log folder does not exist. Please create it here first:" -ForegroundColor Red
    Write-Host $logFolder -ForegroundColor Red
    exit
}

## =========================================
## LOG FILE SETUP (ONE FILE PER DAY)
## =========================================

$dateStamp = Get-Date -Format "yyyy-MM-dd"
$logFile = Join-Path $logFolder "network_log_$dateStamp.txt"

## =========================================
## SESSION COUNTERS
## =========================================

$gwSent = 0
$gwLost = 0
$netSent = 0
$netLost = 0

## =========================================
## ROLLING WINDOW STORAGE
## 1 = success, 0 = lost
## =========================================

$gwRecentResults = @()
$netRecentResults = @()

## =========================================
## STATE TRACKING (FOR EVENTS)
## =========================================

$internetWasDown = $false
$highPingActive = $false
$liveLossActive = $false

## =========================================
## FUNCTION: TEST TARGET (PING PARSER)
## =========================================

function Test-Target {
    param([string]$Target)

    $output = ping.exe -n 1 $Target

    $success = $false
    $pingMs = $null

    foreach ($line in $output) {
        if ($line -match "time[=<]\s*(\d+)\s*ms") {
            $success = $true
            $pingMs = [int]$matches[1]
            break
        }
        elseif ($line -match "Average = (\d+)ms") {
            $success = $true
            $pingMs = [int]$matches[1]
        }
    }

    if (-not $success) {
        return @{
            Status = "LOST"
            Ping   = "---"
            PingMs = -1
            Success = 0
        }
    }

    return @{
        Status = "OK"
        Ping   = ("{0,3} ms" -f $pingMs)
        PingMs = $pingMs
        Success = 1
    }
}

## =========================================
## FUNCTION: COLOR LOGIC
## =========================================

function Get-StatusColor {
    param([string]$Status, [int]$PingMs = -1)

    if ($Status -eq "LOST") { return "Red" }
    elseif ($PingMs -ge 100) { return "Yellow" }
    else { return "Green" }
}

## =========================================
## FUNCTION: EVENT LOGGER
## =========================================

function Write-EventLine {
    param([string]$Message)

    $eventTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $eventLine = "***** $eventTime | $Message *****"

    Add-Content -Path $logFile -Value $eventLine
    Write-Host $eventLine -ForegroundColor Yellow
}

## =========================================
## FUNCTION: UPDATE ROLLING WINDOW
## =========================================

function Update-RollingWindow {
    param(
        [array]$History,
        [int]$Value,
        [int]$MaxSize
    )

    $History += $Value

    if ($History.Count -gt $MaxSize) {
        $History = $History[-$MaxSize..-1]
    }

    return $History
}

## =========================================
## FUNCTION: CALCULATE LOSS %
## =========================================

function Get-LossPercent {
    param([array]$History)

    if (-not $History -or $History.Count -eq 0) {
        return 0
    }

    $sent = $History.Count
    $received = ($History | Measure-Object -Sum).Sum
    $lost = $sent - $received

    return [math]::Round(($lost / $sent) * 100, 2)
}

## =========================================
## FUNCTION: RUN TRACEROUTE
## =========================================

function Run-TraceRouteSnapshot {
    param(
        [string]$Target,
        [string]$LogFile,
        [int]$MaxHopsToTest = 5,
        [int]$HopPingCount = 3
    )

    $traceOutput = tracert.exe -d $Target

    Add-Content -Path $LogFile -Value ""
    Add-Content -Path $LogFile -Value "===== TRACEROUTE START ====="
    foreach ($line in $traceOutput) {
        Add-Content -Path $LogFile -Value $line
    }
    Add-Content -Path $LogFile -Value "===== TRACEROUTE END ====="
    Add-Content -Path $LogFile -Value ""

    ## -----------------------------------------
    ## Build hop objects from traceroute output
    ## -----------------------------------------

    $hopEntries = @()

    foreach ($line in $traceOutput) {
        if ($line -match '^\s*(\d+)\s+') {
            $hopNumber = [int]$matches[1]

            ## Case 1: hop timed out / no IP found
            if ($line -match 'Request timed out') {
                $hopEntries += [PSCustomObject]@{
                    Hop    = $hopNumber
                    IP     = "UNKNOWN"
                    Type   = "TIMEOUT"
                }
                continue
            }

            ## Case 2: hop has an IP address
            if ($line -match '(\d{1,3}(?:\.\d{1,3}){3})\s*$') {
                $ip = $matches[1]
                $hopEntries += [PSCustomObject]@{
                    Hop    = $hopNumber
                    IP     = $ip
                    Type   = "IP"
                }
            }
        }
    }

    ## Remove duplicate IP hops, but keep UNKNOWN timeout hops
    $seenIPs = @{}
    $filteredHops = @()

    foreach ($entry in $hopEntries) {
        if ($entry.Type -eq "TIMEOUT") {
            $filteredHops += $entry
        }
        elseif (-not $seenIPs.ContainsKey($entry.IP)) {
            $seenIPs[$entry.IP] = $true
            $filteredHops += $entry
        }
    }

    $filteredHops = $filteredHops | Select-Object -First $MaxHopsToTest

    Add-Content -Path $LogFile -Value "===== HOP LOSS SNAPSHOT START ====="

    if (-not $filteredHops -or $filteredHops.Count -eq 0) {
        Add-Content -Path $LogFile -Value "No hop data could be parsed from traceroute."
        Add-Content -Path $LogFile -Value "===== HOP LOSS SNAPSHOT END ====="
        Add-Content -Path $LogFile -Value ""
        return
    }

    foreach ($hop in $filteredHops) {

        ## If traceroute only gave us a timeout and no IP, log it as UNKNOWN
        if ($hop.Type -eq "TIMEOUT") {
            $lineOut = "Hop {0,-2} | {1,-15} | LOSS | Avg --- | Loss 100%" -f $hop.Hop, "UNKNOWN"
            Add-Content -Path $LogFile -Value $lineOut
            continue
        }

        ## Otherwise ping the hop IP a few times for a quick loss snapshot
        $pingOutput = ping.exe -n $HopPingCount $hop.IP

        $times = @()
        $lostCount = 0

        foreach ($line in $pingOutput) {
            if ($line -match "time[=<]\s*(\d+)\s*ms") {
                $times += [int]$matches[1]
            }
            elseif ($line -match "Request timed out") {
                $lostCount++
            }
        }

        $lossPct = [math]::Round(($lostCount / $HopPingCount) * 100, 2)

        if ($times.Count -gt 0) {
            $avg = [math]::Round((($times | Measure-Object -Average).Average), 2)

            if ($lossPct -ge 100) {
                $status = "LOSS"
            }
            elseif ($lossPct -gt 0) {
                $status = "PART"
            }
            else {
                $status = "OK"
            }

            $lineOut = "Hop {0,-2} | {1,-15} | {2,-4} | Avg {3} ms | Loss {4}%" -f $hop.Hop, $hop.IP, $status, $avg, $lossPct
        }
        else {
            $lineOut = "Hop {0,-2} | {1,-15} | LOSS | Avg --- | Loss 100%" -f $hop.Hop, $hop.IP
        }

        Add-Content -Path $LogFile -Value $lineOut
    }

    Add-Content -Path $LogFile -Value "===== HOP LOSS SNAPSHOT END ====="
    Add-Content -Path $LogFile -Value ""
}

## =========================================
## CREATE HEADER (ONLY IF FILE IS NEW)
## =========================================

if (-not (Test-Path $logFile)) {

    "{0,-19} | {1,-8} | {2,-13} | {3,-6} | {4,-6} | {5,4} | {6,4} | {7,8} | {8,8}" -f `
    "Timestamp","Target","IP Address","Status","Ping","Sent","Lost","Sess Loss %","Live Loss %" |
    Out-File -FilePath $logFile -Encoding utf8

    "----------------------------------------------------------------------------------------------------------------" |
    Out-File -FilePath $logFile -Append -Encoding utf8
}

## =========================================
## SESSION START MARKER
## =========================================

Add-Content -Path $logFile -Value ""
Add-Content -Path $logFile -Value "===== NEW SESSION START: $(Get-Date -Format 'HH:mm:ss') ====="
Add-Content -Path $logFile -Value "----------------------------------------------------------------------------------------------------------------"

Write-Host "Saving logs to: $logFile" -ForegroundColor Cyan

## =========================================
## MAIN LOOP
## =========================================

try {
    while ($true) {

        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Cyan

        $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        ## -------- LOCAL TEST --------

        $gwSent++
        $gwTest = Test-Target -Target $gateway
        $gwStatus = $gwTest.Status
        $gwPingText = $gwTest.Ping
        $gwPingMs = $gwTest.PingMs
        $gwRecentResults = Update-RollingWindow -History $gwRecentResults -Value $gwTest.Success -MaxSize $windowSize

        if ($gwStatus -eq "LOST") { $gwLost++ }

        ## -------- INTERNET TEST --------

        $netSent++
        $netTest = Test-Target -Target $internet
        $netStatus = $netTest.Status
        $netPingText = $netTest.Ping
        $netPingMs = $netTest.PingMs
        $netRecentResults = Update-RollingWindow -History $netRecentResults -Value $netTest.Success -MaxSize $windowSize

        if ($netStatus -eq "LOST") { $netLost++ }

        ## -------- CALCULATIONS --------

        $gwLossPct = [math]::Round(($gwLost / $gwSent) * 100, 2)
        $netLossPct = [math]::Round(($netLost / $netSent) * 100, 2)

        $gwLiveLossPct = Get-LossPercent -History $gwRecentResults
        $netLiveLossPct = Get-LossPercent -History $netRecentResults

        ## -------- COLORS --------

        $gwColor = Get-StatusColor -Status $gwStatus -PingMs $gwPingMs
        $netColor = Get-StatusColor -Status $netStatus -PingMs $netPingMs

        ## -------- DISPLAY --------

        Write-Host "Time: $time"
        Write-Host ""

        Write-Host "LOCAL NETWORK (Gateway)"
        Write-Host "-----------------------"
        Write-Host "IP Address      : $gateway"
        Write-Host "Status          : $gwStatus" -ForegroundColor $gwColor
        Write-Host "Ping            : $gwPingText" -ForegroundColor $gwColor
        Write-Host "Sent            : $gwSent"
        Write-Host "Lost            : $gwLost"
        Write-Host "Session Loss %  : $gwLossPct"
        Write-Host "Live Loss %     : $gwLiveLossPct  (last $windowSize checks)"
        Write-Host ""

        Write-Host "INTERNET"
        Write-Host "--------"
        Write-Host "IP Address      : $internet"
        Write-Host "Status          : $netStatus" -ForegroundColor $netColor
        Write-Host "Ping            : $netPingText" -ForegroundColor $netColor
        Write-Host "Sent            : $netSent"
        Write-Host "Lost            : $netLost"
        Write-Host "Session Loss %  : $netLossPct"
        Write-Host "Live Loss %     : $netLiveLossPct  (last $windowSize checks)"
        Write-Host ""

        ## -------- DIAGNOSIS --------

        if ($gwStatus -eq "OK" -and $netStatus -eq "LOST") {
            Write-Host "Diagnosis: Internet issue (ISP side)" -ForegroundColor Yellow
        }
        elseif ($gwStatus -eq "LOST" -and $netStatus -eq "LOST") {
            Write-Host "Diagnosis: Local network or router issue" -ForegroundColor Red
        }
        elseif ($gwStatus -eq "OK" -and $netStatus -eq "OK") {
            Write-Host "Diagnosis: Everything normal" -ForegroundColor Green
        }
        else {
            Write-Host "Diagnosis: Mixed behavior" -ForegroundColor Yellow
        }

        ## -------- LOG WRITING --------

        $gwLogLine = "{0,-19} | {1,-8} | {2,-13} | {3,-6} | {4,-6} | {5,4} | {6,4} | {7,8} | {8,8}" -f `
            $time, "LOCAL", $gateway, $gwStatus, $gwPingText, $gwSent, $gwLost, "$gwLossPct%", "$gwLiveLossPct%"

        $netLogLine = "{0,-19} | {1,-8} | {2,-13} | {3,-6} | {4,-6} | {5,4} | {6,4} | {7,8} | {8,8}" -f `
            $time, "INTERNET", $internet, $netStatus, $netPingText, $netSent, $netLost, "$netLossPct%", "$netLiveLossPct%"

        Add-Content -Path $logFile -Value $gwLogLine
        Add-Content -Path $logFile -Value $netLogLine
        Add-Content -Path $logFile -Value "----------------------------------------------------------------------------------------------------------------"

        ## -------- EVENT DETECTION --------

        if ($netStatus -eq "LOST" -and -not $internetWasDown) {
            Write-EventLine "INTERNET LOSS DETECTED"
            [console]::beep(1000, 400)
            Run-TraceRouteSnapshot -Target $internet -LogFile $logFile -MaxHopsToTest $maxTraceHopsToTest -HopPingCount $hopPingCount

            $internetWasDown = $true
        }
        elseif ($netStatus -eq "OK" -and $internetWasDown) {
            Write-EventLine "INTERNET RESTORED"
            $internetWasDown = $false
        }

        if ($netStatus -eq "OK" -and $netPingMs -ge 100 -and -not $highPingActive) {
            Write-EventLine "HIGH INTERNET PING DETECTED ($netPingMs ms)"
            $highPingActive = $true
        }
        elseif (($netStatus -eq "LOST" -or $netPingMs -lt 100) -and $highPingActive) {
            Write-EventLine "HIGH INTERNET PING CLEARED"
            $highPingActive = $false
        }

        if ($netLiveLossPct -gt 0 -and -not $liveLossActive) {
            Write-EventLine "LIVE PACKET LOSS DETECTED ($netLiveLossPct% over last $windowSize checks)"
            $liveLossActive = $true
        }
        elseif ($netLiveLossPct -eq 0 -and $liveLossActive) {
            Write-EventLine "LIVE PACKET LOSS CLEARED"
            $liveLossActive = $false
        }

        Start-Sleep -Seconds 1
    }
}

## =========================================
## SESSION SUMMARY (ON EXIT)
## =========================================

finally {

    $endTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $gwLossPctFinal = if ($gwSent -gt 0) { [math]::Round(($gwLost / $gwSent) * 100, 2) } else { 0 }
    $netLossPctFinal = if ($netSent -gt 0) { [math]::Round(($netLost / $netSent) * 100, 2) } else { 0 }

    Add-Content -Path $logFile -Value ""
    Add-Content -Path $logFile -Value "===== SESSION END: $endTime ====="
    Add-Content -Path $logFile -Value "Session Summary:"
    Add-Content -Path $logFile -Value ("Local    - Sent: {0}, Lost: {1}, Session Loss: {2}%" -f $gwSent, $gwLost, $gwLossPctFinal)
    Add-Content -Path $logFile -Value ("Internet - Sent: {0}, Lost: {1}, Session Loss: {2}%" -f $netSent, $netLost, $netLossPctFinal)
    Add-Content -Path $logFile -Value ("Final Live Window Size: {0} checks" -f $windowSize)
    Add-Content -Path $logFile -Value "================================================================================================================"

    Write-Host ""
    Write-Host "Session ended: $endTime" -ForegroundColor Cyan
    Write-Host "Session Summary:" -ForegroundColor Cyan
    Write-Host "Local    - Sent: $gwSent, Lost: $gwLost, Session Loss: $gwLossPctFinal%"
    Write-Host "Internet - Sent: $netSent, Lost: $netLost, Session Loss: $netLossPctFinal%"
    Write-Host "Log saved to: $logFile" -ForegroundColor Cyan
}