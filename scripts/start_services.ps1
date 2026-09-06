# SecureWipe Enterprise Service Orchestrator
# Starts all safe core development services in separate background processes
param (
    [switch]$Interactive = $false
)

$RootDir = Split-Path -Parent $PSScriptRoot
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "       STARTING SECUREWIPE ENTERPRISE SERVICES              " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Workspace Root: $RootDir" -ForegroundColor Gray

function Is-PortListening([int]$port) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $client.Connect("127.0.0.1", $port)
        $client.Close()
        return $true
    } catch {
        return $false
    }
}

# 1. Main Backend API (Port 9758)
if (Is-PortListening 9758) {
    Write-Host "[OK] Core Backend API already running on port 9758" -ForegroundColor Green
} else {
    Write-Host "[*] Launching Core Backend API (Port 9758)..." -ForegroundColor Yellow
    $backendDir = Join-Path $RootDir "backend"
    Start-Process -FilePath "python" -ArgumentList "app.py" -WorkingDirectory $backendDir -WindowStyle Minimized
}

# 2. FARIS Forensic Recovery Service (Port 8760)
if (Is-PortListening 8760) {
    Write-Host "[OK] FARIS Forensic Engine already running on port 8760" -ForegroundColor Green
} else {
    Write-Host "[*] Launching FARIS Forensic Engine (Port 8760)..." -ForegroundColor Yellow
    $farisDir = Join-Path $RootDir "FARIS\application"
    Start-Process -FilePath "python" -ArgumentList "faris_service.py" -WorkingDirectory $farisDir -WindowStyle Minimized
}

# 3. Connection Server and API (Ports 8586 and 5403)
if ((Is-PortListening 8586) -or (Is-PortListening 5403)) {
    Write-Host "[OK] Connection Servers already running on ports 8586 / 5403" -ForegroundColor Green
} else {
    Write-Host "[*] Launching Connection Servers (Ports 8586 and 5403)..." -ForegroundColor Yellow
    $connDir = Join-Path $RootDir "connection-server"
    Start-Process -FilePath "python" -ArgumentList "start_servers.py" -WorkingDirectory $connDir -WindowStyle Minimized
}

# 4. Next.js Frontend UI (Port 3000)
if (Is-PortListening 3000) {
    Write-Host "[OK] Frontend UI already running on port 3000" -ForegroundColor Green
} else {
    Write-Host "[*] Launching Next.js Frontend (Port 3000)..." -ForegroundColor Yellow
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "npm", "run", "dev" -WorkingDirectory $RootDir -WindowStyle Minimized
}

Write-Host "`nWaiting 5 seconds for initialization..." -ForegroundColor Gray
Start-Sleep -Seconds 5

if (Test-Path (Join-Path $RootDir "check_services.ps1")) {
    & (Join-Path $RootDir "check_services.ps1")
} elseif (Test-Path (Join-Path $PSScriptRoot "check_services.ps1")) {
    & (Join-Path $PSScriptRoot "check_services.ps1")
}

Write-Host "`nApplication Access:" -ForegroundColor Cyan
Write-Host "  Web Dashboard:  http://localhost:3000" -ForegroundColor White
Write-Host "  Login Portal:   http://localhost:3000/login" -ForegroundColor White
Write-Host "  Core REST API:  http://127.0.0.1:9758/api/devices" -ForegroundColor White
Write-Host "  FARIS Engine:   http://127.0.0.1:8760/api/faris/health" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
