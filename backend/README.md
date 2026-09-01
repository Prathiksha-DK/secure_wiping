# SecureWiping Backend (Flask)

A minimal Flask backend exposing a GET /api/devices endpoint on port 9758 that lists connected storage devices on Windows.

## Quick start (Windows PowerShell)

```powershell
# Create and activate a virtual environment
py -3 -m venv .venv
. .\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run the server
python app.py
```

The server will listen on http://localhost:9758 and expose:
- GET /api/devices

### Response format

```json
[
  {
    "name": "string",
    "type": "string",
    "size": "string",
    "health": 100,
    "healthStatus": "Healthy"
  }
]
```

Notes:
- Device discovery uses PowerShell's `Get-PhysicalDisk`. The `type` field prefers `USB` when the BusType is USB; otherwise it uses the disk's `MediaType` (e.g., SSD/HDD/Unspecified).
- The numeric `health` is derived from `HealthStatus` (Healthy=100, Warning=50, Unhealthy=10, Unknown=0).
- If you get a Windows Firewall prompt on first run, allow access for local development.

## Troubleshooting
- Ensure PowerShell is available on PATH (it is by default on Windows).
- If the response is empty, verify that `Get-PhysicalDisk` returns results by running it directly in PowerShell.
- If your frontend is hosted on a different origin, CORS is enabled for /api/* by default during development.

