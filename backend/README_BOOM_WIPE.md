# Boom Wipe - High-Intensity Data Destruction System

## 🚀 Overview

The Boom Wipe system provides **high-intensity, military-grade data destruction** using a revolutionary "bomb placement" methodology. This system is designed for scenarios requiring immediate and forceful data destruction with maximum security.

## 💣 How Boom Wipe Works

### The Bomb Method
1. **Memory Bomb Placement**: The system strategically places "bombs" across the storage device
2. **Optimized Coverage**: Each bomb covers a specific memory sector to ensure complete coverage
3. **Parallel Detonation**: Multiple bombs detonate simultaneously using multi-threading
4. **Triple Overwrite**: Each bomb performs 3 overwrite passes:
   - **Pass 1**: All zeros (`0x00`)
   - **Pass 2**: All ones (`0xFF`)
   - **Pass 3**: Random data patterns

### Technical Specifications
- **Main Storage Bombs**: 1MB per bomb (optimized for HDDs/SSDs)
- **Pendrive Bombs**: 512KB per bomb (optimized for flash storage)
- **Concurrent Threads**: Up to 16 for main storage, 8 for pendrives
- **Direct I/O**: No buffering, immediate hardware writes
- **Real-time Progress**: Live bomb detonation tracking

## 🎯 Services

### 1. Main Boom Wipe Service (Port 5695)
**Purpose**: Execute boom wipe on primary storage devices (HDDs, SSDs)
- **URL**: `http://localhost:5695`
- **Target**: All storage devices
- **Bomb Size**: 1MB (high-intensity coverage)

### 2. Pendrive Boom Wipe Service (Port 8743)
**Purpose**: Execute boom wipe on removable devices (pendrives, USB drives)
- **URL**: `http://localhost:8743`
- **Target**: Removable devices only
- **Bomb Size**: 512KB (flash-optimized coverage)

## 🔌 API Endpoints

### Main Boom Wipe Service (5695)

#### Execute Boom Wipe
```http
POST /boom-wipe
Content-Type: application/json

{
  "device": "Primary SSD (512GB)"
}
```

**Response (Success)**:
```json
{
  "status": "success",
  "message": "Boom Wipe initiated successfully on Primary SSD (512GB).",
  "wipe_id": "wipe_1695735600_1234"
}
```

#### List Storage Devices
```http
GET /devices
```

#### Check Wipe Status
```http
GET /wipe-status/wipe_1695735600_1234
```

#### Health Check
```http
GET /health
```

### Pendrive Boom Wipe Service (8743)

#### Execute Pendrive Boom Wipe
```http
POST /wipe-pendrive
Content-Type: application/json

{
  "device": "E (16GB) - FAT32"
}
```

#### Quick Wipe (Single Pass)
```http
POST /quick-wipe
Content-Type: application/json

{
  "device": "E (16GB) - FAT32"
}
```

#### List Pendrives
```http
GET /pendrives
```

## ⚡ Installation & Setup

### Prerequisites
- **Python 3.8+**
- **Administrator Privileges** (required for direct device access)
- **Windows OS** (uses Win32 APIs)

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Start Services

#### Option 1: Batch Script (Recommended)
```bash
start_boom_wipe_services.bat
```

#### Option 2: Manual Start
```bash
# Terminal 1 - Main Boom Wipe Service
python boom_wipe_app.py

# Terminal 2 - Pendrive Boom Wipe Service  
python pendrive_wipe_app.py
```

### Test the APIs
```bash
python test_boom_wipe.py
```

## 🛡️ Security Features

### Direct Device Access
- Bypasses filesystem layer
- Direct hardware I/O operations
- No buffering or caching

### Multi-Pass Overwriting
- **3 distinct patterns** per bomb
- **Random data generation** for final pass
- **Immediate flush** to hardware

### Parallel Processing
- **ThreadPoolExecutor** for concurrent bombs
- **Configurable thread limits**
- **Progress tracking** per bomb

### Real-time Monitoring
- Live progress updates
- Bomb detonation status
- Error handling and recovery

## ⚠️ Critical Safety Warnings

> **🚨 DANGER: DATA DESTRUCTION IS PERMANENT AND IRREVERSIBLE**

### Before Using:
1. **Verify device names** carefully - wrong device = data loss
2. **Backup critical data** - operations cannot be undone
3. **Run as Administrator** - required for device access
4. **Test on non-critical devices** first
5. **Close all applications** using target device

### Legal & Ethical Use:
- Only use on devices you own
- Comply with local data destruction laws
- Consider environmental disposal regulations
- Document destruction for compliance audits

## 📊 Monitoring & Progress

### Real-time Status
Monitor bomb detonation progress:
```bash
GET /wipe-status/your_wipe_id
```

### Sample Progress Response
```json
{
  "status": "success",
  "wipe_status": {
    "status": "placing_bombs",
    "device": "Primary SSD (512GB)",
    "progress": 65.4,
    "total_bombs": 524288,
    "completed_bombs": 342814,
    "device_size_mb": 512000
  }
}
```

## 🔧 Configuration

### Bomb Size Adjustment
```python
# In boom_wipe_app.py
self.bomb_size = 1024 * 1024  # 1MB bombs

# In pendrive_wipe_app.py  
self.bomb_size = 512 * 1024   # 512KB bombs
```

### Thread Limits
```python
max_threads = min(16, total_bombs)  # Main storage
max_threads = min(8, total_bombs)   # Pendrives
```

### Overwrite Passes
```python
self.overwrite_passes = 3  # Standard: 3 passes
```

## 🎯 Use Cases

### High-Security Scenarios
- Government data destruction
- Financial institution purging
- Healthcare record elimination
- Corporate data sanitization

### Emergency Data Destruction
- Security breach response
- Stolen device recovery
- Compliance violation cleanup
- Forensic counter-measures

### Routine Maintenance
- Device decommissioning
- Storage repurposing
- Compliance auditing
- Security testing

## 🔍 Troubleshooting

### Common Issues

**"Device not found"**
- Run as Administrator
- Check device is connected
- Verify exact device name

**"Access denied"**
- Close all programs using the device
- Run PowerShell/CMD as Administrator
- Check antivirus interference

**"Service won't start"**
- Install missing dependencies
- Check port availability (5695, 8743)
- Verify Python installation

### Debug Mode
Enable detailed logging:
```python
logging.basicConfig(level=logging.DEBUG)
```

## 📈 Performance

### Expected Throughput
- **SSD**: 100-500 MB/s per thread
- **HDD**: 50-150 MB/s per thread  
- **USB 3.0**: 20-100 MB/s per thread
- **USB 2.0**: 5-25 MB/s per thread

### Time Estimates
- **16GB Pendrive**: 3-10 minutes
- **256GB SSD**: 15-45 minutes
- **1TB HDD**: 1-3 hours
- **4TB HDD**: 4-12 hours

## 📜 License & Disclaimer

This software is provided for legitimate data destruction purposes only. The developers are not responsible for any data loss, hardware damage, or legal consequences resulting from misuse. Always ensure you have proper authorization before using this software.

---

**🎯 Ready to detonate? Start your Boom Wipe services and unleash the power of parallel data destruction!**
