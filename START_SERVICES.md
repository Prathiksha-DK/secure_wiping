# Secure Wipe Startup Guide

Follow this guide to start the necessary services for local development and validation testing.

> [!CAUTION]
> **Safety Notice**: Do not invoke any real wipe operations or call destructive endpoints during development. 

## Prerequisites
- Windows 10/11 with PowerShell
- Python 3.10+ installed and on system PATH
- Node.js 18+ installed

---

## Service Startup Configuration

### TERMINAL 1: Next.js Frontend
- **Service Name**: Frontend UI
- **Directory**: `D:\wiping`
- **Command**: `npm run dev`
- **Port**: `3000`
- **Health / Test URL**: `http://localhost:3000/login`
- **Safety**: Safe (Read-Only UI)

### TERMINAL 2: Main Backend API
- **Service Name**: Flask Main Backend
- **Directory**: `D:\wiping\backend`
- **Command**: `python app.py`
- **Port**: `9758`
- **Health / Test URL**: `http://localhost:9758/api/devices`
- **Safety**: Safe (Device enumerator & reports viewer). Avoid triggers to physical disk wipe endpoints in real-world contexts.

### TERMINAL 3: Connection Server & API
- **Service Name**: Socket.IO Connection Tracker
- **Directory**: `D:\wiping\connection-server`
- **Command**: `python start_servers.py`
- **Port**: `8586` (Socket) & `5403` (REST API)
- **Health / Test URL**: `http://localhost:5403/getConnectedUsers`
- **Safety**: Safe

### TERMINAL 4: Main Boom Wipe Service
- **Service Name**: Boom Wipe Endpoint
- **Directory**: `D:\wiping\backend`
- **Command**: `python boom_wipe_app.py`
- **Port**: `5695`
- **Health / Test URL**: `http://localhost:5695/health`
- **Safety**: **DESTRUCTIVE** if a POST request is sent to `/boom-wipe`. Leave OFF unless testing the `/health` status endpoint.

### TERMINAL 5: Pendrive Boom Wipe Service
- **Service Name**: USB Pendrive Boom Wipe
- **Directory**: `D:\wiping\backend`
- **Command**: `python pendrive_wipe_app.py`
- **Port**: `8743`
- **Health / Test URL**: `http://localhost:8743/health`
- **Safety**: **DESTRUCTIVE** if a POST request is sent to `/wipe-pendrive`. Leave OFF unless testing the `/health` status endpoint.

---

## Services to Leave OFF During Development

1. **Facial Recognition / Security Monitor (`facial recognition/app/crypto_eyev2.py`)**:
   - **Reason**: Although the real Windows shutdown commands have been disabled for development safety, there is no need to start it unless actively testing camera feeds.
2. **DoD Wiping Core (`DoD -Wiping/dod.exe`)**:
   - **Reason**: Performs real, raw block-level formatting. Do NOT run this executable.
