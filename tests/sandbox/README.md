# Safe Development & Test Sandbox

## Overview
This directory holds mock binary targets and sample evidence blobs used for non-destructive local testing.

## Files
- `safe_dummy_wipe_target.bin`: A 1 MB synthetic binary image used to validate block overwrites, file carving, and forensic signatures without risk to physical storage drives.
- `safe_forensic_evidence_sample.bin`: A small synthetic disk image containing known file signatures (JPEG, PNG, SQLite) for verification of carving algorithms.

> [!NOTE]
> All automated unit tests in `FARIS/tests/` and `backend/` use synthetic or temporary mock images created on-the-fly.
