# SecureWipe Enterprise Service Shutdown Script
# Terminates all running services by port binding

$ports = @(3000, 9758, 8760, 8586, 5403, 5695, 8743)

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "       STOPPING SECUREWIPE ENTERPRISE SERVICES              " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$stoppedCount = 0

foreach ($port in $ports) {
    $connections = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if ($connections) {
        $pids = $connections | Select-Object -ExpandProperty OwningProcess -Unique
        foreach ($pidToKill in $pids) {
            try {
                $proc = Get-Process -Id $pidToKill -ErrorAction SilentlyContinue
                if ($proc) {
                    $procName = $proc.ProcessName
                    Stop-Process -Id $pidToKill -Force -ErrorAction SilentlyContinue
                    Write-Host "[OK] Stopped $procName (PID $pidToKill) listening on port $port" -ForegroundColor Green
                    $stoppedCount++
                }
            } catch {
                Write-Host "[!] Could not terminate PID $pidToKill on port ${port}: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
}

if ($stoppedCount -eq 0) {
    Write-Host "[i] No active SecureWipe services were found running." -ForegroundColor Gray
} else {
    Write-Host "`n[OK] Successfully terminated $stoppedCount service process(es)." -ForegroundColor Green
}

Write-Host "============================================================" -ForegroundColor Cyan
