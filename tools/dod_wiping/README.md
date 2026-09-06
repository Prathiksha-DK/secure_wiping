# DoD 5220.22-M Low-Level Data Sanitization Utility

## Overview
This module contains the low-level C-based hardware storage enumerator and raw sector-level sanitization binary adhering to **DoD 5220.22-M (3-Pass)** standards.

## Components
deviceList.C----Source----Windows physical disk enumerator using SetupAPI and IOCTL_STORAGE_GET_DEVICE_NUMBER.

dod.exe----Binary---Block-level overwrite engine using three passes: Pass 1 — 0x00, Pass 2 — 0xFF, Pass 3 — pseudo-random pattern.

list.exe---Binary----Compiled disk enumeration executable.

## Build Instructions (GCC / MinGW)
```powershell
gcc -O2 -o bin/list.exe src/deviceList.c -lsetupapi
```

> [!CAUTION]
> **Safety Warning**: `dod.exe` performs raw physical drive block overwrites. Do NOT execute against active system volumes (`C:\`).
