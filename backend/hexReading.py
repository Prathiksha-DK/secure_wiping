import os

def read_sectors(drive_path, sector_size=512, num_sectors=100):
    """
    Reads the first `num_sectors` sectors from the drive
    """
    with open(drive_path, "rb") as f:
        data = f.read(sector_size * num_sectors)
    return data

def verify_wipe(data, allowed_bytes=(0x00, 0xFF)):
    """
    Checks if all bytes are only in allowed_bytes
    """
    for b in data:
        if b not in allowed_bytes:
            return False
    return True

def main():
    # Physical drive path (must run Python as Administrator)
    # Replace '1' with your target drive number
    drive_path = r"\\.\PhysicalDrive0"
    
    # Read first 100 sectors (adjust for more coverage)
    data = read_sectors(drive_path, sector_size=512, num_sectors=100)
    
    # Verify wipe
    if verify_wipe(data):
        print("✅ Wipe verification PASSED (sectors are clean)")
    else:
        print("❌ Wipe verification FAILED (old data detected)")

if __name__ == "__main__":
    main()
