# FARIS — Third-Party Engine & Dependency Inventory

This document maintains the verified provenance, exact build, official source, license, and distribution status of all forensic components in FARIS.

---

## 1. libewf / EWF Tools
* **Name**: libewf (ewfacquire, ewfverify, ewfinfo, ewfexport)
* **Exact Version**: `20230405`
* **Official Upstream**: Joachim Metz / libyal (`https://github.com/libyal/libewf`)
* **License**: GNU Lesser General Public License v3.0 (LGPL-3.0) / LGPL v3+
* **Bundled Location**: `FARIS/engines/libewf/`
* **Bundled Files**: `ewfacquire.exe`, `ewfacquirestream.exe`, `ewfexport.exe`, `ewfinfo.exe`, `ewfverify.exe`, `libewf.dll`, `zlib.dll`
* **Purpose**: Bit-stream Expert Witness Compression Format (E01) acquisition, verification, and metadata extraction.
* **Redistribution Status**: Permitted under LGPL-3.0 with license notice and dynamic linking.
* **Verification Status**: **VERIFIED & BUNDLED**

---

## 2. The Sleuth Kit (TSK)
* **Name**: The Sleuth Kit (Win64)
* **Exact Version**: `4.15.0`
* **Official Upstream**: Brian Carrier (`https://www.sleuthkit.org`, `https://github.com/sleuthkit/sleuthkit`)
* **License**: Common Public License v1.0 (CPL-1.0) / IBM Public License / GPL v2
* **Bundled Location**: `FARIS/engines/sleuthkit/bin/`
* **Bundled Files**: `mmls.exe`, `fsstat.exe`, `fls.exe`, `istat.exe`, `icat.exe`, `ifind.exe`, `ils.exe`, `tsk_recover.exe`, `blkls.exe`, `blkcat.exe`, `img_cat.exe`, `img_stat.exe`, `tsk_imageinfo.exe`, and MSVC runtime DLLs.
* **Purpose**: Partition table analysis, filesystem geometry, inode inspection, metadata recovery, and unallocated block streaming.
* **Redistribution Status**: Permitted under CPL-1.0 and GPL v2 with license notices preserved in `engines/sleuthkit/`.
* **Verification Status**: **VERIFIED & BUNDLED**

---

## 3. SQLite Runtime
* **Name**: SQLite Database Engine
* **Exact Version**: `3.45+` (Embedded in Python C-Runtime)
* **Official Upstream**: SQLite Development Team (`https://www.sqlite.org`)
* **License**: Public Domain
* **Purpose**: In-memory database validation, PRAGMA quick_check, record deserialization, and reconstructed database creation.
* **Verification Status**: **VERIFIED & BUNDLED**

---

## 4. CGSecurity PhotoRec & TestDisk
* **Name**: TestDisk & PhotoRec
* **Evaluated Version**: `7.2 (Stable Win64)`
* **Official Upstream**: Christophe GRENIER / CGSecurity (`https://www.cgsecurity.org/`)
* **License**: GNU General Public License v2 or later (GPL-2.0-or-later)
* **Status**: **EVALUATED / NOT BUNDLED** (FARIS uses its internal zero-dependency signature carver `recovery/file_carving.py` for standard carving).

---

## 5. Volatility 3
* **Name**: Volatility 3 Framework
* **Evaluated Version**: `2.5.0+`
* **Official Upstream**: Volatility Foundation (`https://www.volatilityfoundation.org/`)
* **License**: Volatility Software License (VSL v1.0)
* **Status**: **EVALUATED / NOT BUNDLED** (For disk-only storage images such as `pendrive_image.E01`, FARIS reports `N/A — evidence type not applicable`).
