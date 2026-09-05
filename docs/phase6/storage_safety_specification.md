# SecureWipe — Storage Safety & Anti-Destruction Specification

## 1. Safety Model Philosophy: Fail Closed

SecureWipe operates under a strict **fail-closed security model**:
* Any ambiguity in target identification, partition hierarchy, filesystem mounting status, or authorization results in immediate refusal to sanitize (`SAFETY_REJECTED`).
* Sanitization permissions are never granted based on assumptions or fuzzy matching.

---

## 2. Multi-Layer Storage Safety Validation Pipeline

Before any destructive I/O operation begins, the target passes through 6 sequential validation gates:

```
[Target Submitted]
       |
       v
[Gate 1: Format & Path Resolution] --------> FAIL -> [Abort: Invalid Target Format]
       |
       v
[Gate 2: Host Operating System Check] -----> FAIL -> [Abort: System / Boot Disk Protection]
       |
       v
[Gate 3: Application Workspace Check] -----> FAIL -> [Abort: SecureWipe Application Runtime]
       |
       v
[Gate 4: Mount Point Hierarchy Check] -----> FAIL -> [Abort: Critical Mount Active]
       |
       v
[Gate 5: Anti-Misdirection Fingerprint] ---> FAIL -> [Abort: Hardware Fingerprint Mismatch]
       |
       v
[Gate 6: Exclusive Device Lock Mutex] -----> FAIL -> [Abort: Target Locked by Active Job]
       |
       v
[Permit Destructive Operation]
```

---

## 3. Platform-Specific System Disk Protections

### 3.1 POSIX / Linux Environment
* **Root Volume Check**: Checks device nodes against `/`, `/boot`, `/boot/efi`, `/etc`, `/usr`, `/var`, `/home`, `/root`, `/opt`.
* **Block Device Tree Inspection**: Executes `lsblk -J -b -o NAME,MOUNTPOINT,PKNAME,TYPE` to inspect all parent disks and child partitions. If any child partition contains a critical mount, the parent physical device is locked and protected from whole-disk erasure.
* **psutil Cross-Verification**: Inspects active mounted filesystems via `psutil.disk_partitions(all=True)` to catch dynamically mounted system filesystems.

### 3.2 Windows Environment
* **Drive Letter Check**: Explicitly blocks `C:` or `SystemDrive`.
* **PowerShell Partition Query**: Inspects `Get-Partition | Where-Object { $_.IsBoot -or $_.IsSystem -or $_.DriveLetter -eq 'C' }` to identify the physical `DiskNumber` hosting Windows.
* **PhysicalDrive Locking**: Automatically blocks `\\.\PhysicalDriveX` if it corresponds to the Windows boot disk number.

---

## 4. Hardware Identity Fingerprinting & Anti-Misdirection

To protect against physical device swapping or dynamic kernel device re-enumeration (e.g., `/dev/sdb` re-assigned after unplugging):
* SecureWipe computes:
  $$\text{Fingerprint} = \text{SHA256}(\text{Serial} \,||\, \text{Model} \,||\, \text{SizeBytes} \,||\, \text{BusType} \,||\, \text{TargetType})$$
* This fingerprint is cryptographically signed into the Stage 1 Confirmation Token and re-validated immediately before the first destructive sector write in Stage 2.

---

## 5. Device Concurrency Lock Manager

* **Canonical Identifier**: Every device is mapped to a canonical key (`DISK:<SERIAL>` or `FILE:<ABS_PATH>`).
* **Exclusive Mutex**: An in-memory thread lock prevents concurrent wipe jobs from targeting the same physical medium simultaneously.
* **Automatic Release**: Lock is guaranteed to be released in a `finally` block upon job completion, failure, or cancellation.
