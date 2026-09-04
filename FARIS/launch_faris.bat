@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title FARIS - Forensic Adaptive Recovery and Integrity System (Offline Portable)

echo =====================================================================
echo  FARIS — Forensic Adaptive Recovery and Integrity System
echo  Mode: Offline / Air-Gapped / Portable Distribution
echo =====================================================================
echo.

if exist "runtime\python\python.exe" (
    echo [*] Launching via bundled FARIS portable Python runtime...
    "runtime\python\python.exe" launch_faris.py
) else (
    where python >nul 2>nul
    if %ERRORLEVEL% equ 0 (
        echo [*] Launching via system Python...
        python launch_faris.py
    ) else (
        echo [ERROR] No Python runtime found in runtime\python\ or system PATH.
        pause
    )
)

endlocal
