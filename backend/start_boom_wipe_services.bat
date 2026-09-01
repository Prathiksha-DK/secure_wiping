@echo off
echo Starting Boom Wipe Services...

echo.
echo Starting Main Boom Wipe Service (Port 5695)...
start "Boom Wipe Service" python boom_wipe_app.py

echo.
echo Starting Pendrive Boom Wipe Service (Port 8743)...
start "Pendrive Wipe Service" python pendrive_wipe_app.py

echo.
echo Both services are starting...
echo Main Boom Wipe Service: http://localhost:5695
echo Pendrive Wipe Service: http://localhost:8743
echo.
echo Press any key to continue...
pause >nul
