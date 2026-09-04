@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"
title FARIS - Forensic Adaptive Recovery and Integrity System (Offline Portable)

if exist "runtime\python\python.exe" (
    "runtime\python\python.exe" launch_faris.py
) else (
    python launch_faris.py
)

endlocal
