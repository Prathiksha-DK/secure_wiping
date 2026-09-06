# PowerShell Service Health Checker for Secure Wipe
$ProgressPreference = 'SilentlyContinue'

function Check-Port {
    param (
        [string]$Name,
        [int]$Port,
        [string]$Path = "",
        [bool]$Required = $true
    )

    $connection = New-Object System.Net.Sockets.TcpClient
    try {
        $connection.Connect("127.0.0.1", $Port)
        $connection.Close()
        
        # Port is open, try HTTP GET check if path specified
        if ($Path -ne "") {
            try {
                $response = Invoke-RestMethod -Uri "http://localhost:$Port$Path" -Method Get -TimeoutSec 2
                return "OK"
            } catch {
                return "OK (Unresponsive HTTP)"
            }
        }
        return "OK"
    } catch {
        if ($Required) {
            return "NOT RUNNING"
        } else {
            return "NOT RUNNING"
        }
    }
}

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "      SECURE WIPE HEALTH CHECK REPORT         " -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

$frontend = Check-Port "Frontend" 3000
$backend = Check-Port "Main Backend" 9758 "/api/devices"
$socket = Check-Port "Socket" 8586
$connApi = Check-Port "Connection API" 5403 "/getConnectedUsers"
$auth = Check-Port "Auth Platform" 9758 "/api/auth/me"
$faris = Check-Port "FARIS API" 9758 "/api/devices"
$reports = Check-Port "Reports" 9758 "/api/history"
$boom = Check-Port "Boom Wipe" 5695 "/health"
$pendrive = Check-Port "Pendrive" 8743 "/health"

function Format-StatusColor($status, $isOptional = $false) {
    if ($status -eq "OK") { return "Green" }
    if ($isOptional) { return "Yellow" }
    return "Red"
}

Write-Host ("Frontend         :3000   " + $frontend) -ForegroundColor (Format-StatusColor $frontend)
Write-Host ("Main Backend     :9758   " + $backend) -ForegroundColor (Format-StatusColor $backend)
Write-Host ("Auth Platform    :9758   " + $auth) -ForegroundColor (Format-StatusColor $auth)
Write-Host ("FARIS Engine     :9758   " + $faris) -ForegroundColor (Format-StatusColor $faris)
Write-Host ("Reports          :9758   " + $reports) -ForegroundColor (Format-StatusColor $reports)
Write-Host ("Socket           :8586   " + $socket) -ForegroundColor (Format-StatusColor $socket)
Write-Host ("Connection API   :5403   " + $connApi) -ForegroundColor (Format-StatusColor $connApi)
Write-Host ("Boom Wipe        :5695   " + $boom) -ForegroundColor (Format-StatusColor $boom $true)
Write-Host ("Pendrive         :8743   " + $pendrive) -ForegroundColor (Format-StatusColor $pendrive $true)
Write-Host "Facial Security  :5000   SKIPPED" -ForegroundColor Gray
Write-Host "DoD Wipe         :--     NOT EXECUTED" -ForegroundColor Gray

Write-Host "==============================================" -ForegroundColor Cyan
