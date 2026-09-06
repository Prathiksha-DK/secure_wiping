# Continuous Biometric Security & Operator Verification Engine

## Overview
This service provides continuous visual operator authentication during secure wiping sessions using facial recognition models and gaze tracking.

## Directory Structure
- `app/`
  - `crypto_eyev2.py`: Real-time OpenCV / facial embedding verification loop with SQLite audit trail.
  - `security_alerts.db`: Local incident registry for unauthorized operator presence.
- `embeddings/`
  - `admin_encodings.joblib`: Pre-trained face encoding vectors for authorized administrators.
- `utils/`
  - `save_admin_encoding.py`: Utility script to capture and register new operator biometric encodings.

## Execution
```powershell
python app/crypto_eyev2.py
```
> [!NOTE]
> Camera feed and shutdown interlocks are non-destructive in development mode.
