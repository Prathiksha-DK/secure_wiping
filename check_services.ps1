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
$faris = Check-Port "FARIS API" 9758 "/api/devices"
$reports = Check-Port "Reports" 9758 "/api/history"
$boom = Check-Port "Boom Wipe" 5695 "/health"
$pendrive = Check-Port "Pendrive" 8743 "/health"

Write-Host ("Frontend         :3000   " + $frontend) -ForegroundColor ($frontend -eq "OK" ? "Green" : "Red")
Write-Host ("Main Backend     :9758   " + $backend) -ForegroundColor ($backend -eq "OK" ? "Green" : "Red")
Write-Host ("Socket           :8586   " + $socket) -ForegroundColor ($socket -eq "OK" ? "Green" : "Red")
Write-Host ("Connection API   :5403   " + $connApi) -ForegroundColor ($connApi -eq "OK" ? "Green" : "Red")
Write-Host ("FARIS Engine     :9758   " + $faris) -ForegroundColor ($faris -eq "OK" ? "Green" : "Red")
Write-Host ("Reports          :9758   " + $reports) -ForegroundColor ($reports -eq "OK" ? "Green" : "Red")
Write-Host ("Boom Wipe        :5695   " + $boom) -ForegroundColor ($boom -eq "OK" ? "Green" : "Yellow")
Write-Host ("Pendrive         :8743   " + $pendrive) -ForegroundColor ($pendrive -eq "OK" ? "Green" : "Yellow")
Write-Host "Facial Security  :5000   SKIPPED" -ForegroundColor Gray
Write-Host "DoD Wipe         :--     NOT EXECUTED" -ForegroundColor Gray

Write-Host "==============================================" -ForegroundColor Cyan
