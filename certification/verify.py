import hashlib
import os
import uuid
import json
import socket
import platform
import subprocess
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# -----------------------------
# Hashing Utility
# -----------------------------
def file_hash(path, chunk_size=1024*1024):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            sha256.update(chunk)
    return sha256.hexdigest()

# -----------------------------
# Load hashes from JSON file
# -----------------------------
def load_hashes_from_file(hash_file_path):
    """Load SHA256 hashes from a JSON file containing an array of hashes"""
    try:
        with open(hash_file_path, 'r') as f:
            hashes = json.load(f)
        
        # Validate that it's a list
        if not isinstance(hashes, list):
            print(f"❌ Error: File does not contain a JSON array")
            return []
        
        # Validate each hash
        valid_hashes = []
        for h in hashes:
            if isinstance(h, str) and len(h) == 64:  # SHA256 is 64 chars
                valid_hashes.append(h.lower())  # Normalize to lowercase
            else:
                print(f"⚠️ Invalid hash format: {h}")
        
        print(f"✅ Loaded {len(valid_hashes)} valid hashes from {hash_file_path}")
        return valid_hashes
        
    except FileNotFoundError:
        print(f"❌ Hash file '{hash_file_path}' not found!")
        return []
    except json.JSONDecodeError:
        print(f"❌ Error: '{hash_file_path}' is not a valid JSON file")
        return []
    except Exception as e:
        print(f"❌ Error reading hash file: {e}")
        return []

# -----------------------------
# Verify Multiple Wipes in Folder
# -----------------------------
def verify_multiple_wipes_in_folder(hash_list, folder_path):
    """Verify that multiple hashes are NOT found in the folder"""
    print(f"\nScanning folder: {folder_path}")
    print(f"Checking {len(hash_list)} hashes...")
    
    found_hashes = []
    not_found_hashes = []
    
    try:
        # Create a set of all file hashes in the folder for efficient lookup
        folder_hashes = set()
        file_count = 0
        
        for root, dirs, files in os.walk(folder_path):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    h = file_hash(fpath).lower()  # Normalize to lowercase
                    folder_hashes.add(h)
                    file_count += 1
                    if file_count % 100 == 0:
                        print(f"  Processed {file_count} files...")
                except Exception as e:
                    print(f"  ⚠️ Skipped {fpath} (error: {e})")
        
        print(f"\n✅ Scanned {file_count} files in total")
        
        # Check each hash against the folder
        for i, original_hash in enumerate(hash_list, 1):
            print(f"\nChecking hash {i}/{len(hash_list)}: {original_hash[:16]}...")
            
            if original_hash.lower() in folder_hashes:
                print(f"  ❌ FOUND in folder!")
                found_hashes.append(original_hash)
            else:
                print(f"  ✅ NOT found in folder")
                not_found_hashes.append(original_hash)
        
        # Summary
        print(f"\n{'='*60}")
        print(f"VERIFICATION SUMMARY:")
        print(f"  Total hashes checked: {len(hash_list)}")
        print(f"  ✅ Successfully wiped (not found): {len(not_found_hashes)}")
        print(f"  ❌ Failed wipes (still found): {len(found_hashes)}")
        print(f"{'='*60}")
        
        # Only return True if ALL hashes were not found
        if len(found_hashes) == 0:
            print("\n✅ ALL hashes verified as wiped! Certificate can be generated.")
            return True, not_found_hashes, found_hashes
        else:
            print(f"\n❌ {len(found_hashes)} hash(es) still found. Wipe verification FAILED!")
            return False, not_found_hashes, found_hashes
            
    except FileNotFoundError:
        print("❌ Folder not found. Check the path.")
        return False, [], hash_list
    except Exception as e:
        print(f"❌ Error during verification: {e}")
        return False, [], hash_list

# -----------------------------
# System Info Auto-detection
# -----------------------------
def get_system_info():
    deviceName = socket.gethostname()
    deviceSerial = "Unknown"
    deviceType = "Unknown"

    try:
        if os.name == "nt":
            serial_cmd = subprocess.check_output("wmic bios get serialnumber", shell=True).decode().split("\n")[1].strip()
            if serial_cmd:
                deviceSerial = serial_cmd
            disk_cmd = subprocess.check_output("wmic diskdrive get MediaType", shell=True).decode().split("\n")[1].strip()
            if disk_cmd:
                deviceType = disk_cmd
        else:
            serial_cmd = subprocess.check_output("sudo dmidecode -s system-serial-number", shell=True).decode().strip()
            if serial_cmd:
                deviceSerial = serial_cmd
            deviceType = platform.system()
    except Exception as e:
        print(f"⚠️ Could not fetch system details: {e}")

    return deviceName, deviceSerial, deviceType

# -----------------------------
# Generate Corporate Minimalist Certificate (Image) - Modified for multiple hashes
# -----------------------------
def generate_certificate_image(certificate_data, signature, fname_base):
    # Corporate Minimalist Design
    img_width, img_height = 1200, 900  # Increased height for multiple hashes
    img = Image.new("RGB", (img_width, img_height), "#FFFFFF")
    draw = ImageDraw.Draw(img)

    # Font setup
    try:
        title_font = ImageFont.truetype("arialbd.ttf", 36)
        header_font = ImageFont.truetype("arialbd.ttf", 18)
        field_font = ImageFont.truetype("arial.ttf", 16)
        small_font = ImageFont.truetype("arial.ttf", 12)
    except:
        title_font = header_font = field_font = small_font = ImageFont.load_default()

    # Top accent line
    draw.rectangle([0, 0, img_width, 8], fill="#000000")

    # Logo area (placeholder circle)
    draw.ellipse([50, 40, 110, 100], fill="#000000")
    draw.text((70, 55), "DE", font=header_font, fill="#FFFFFF")

    # Title
    draw.text((150, 55), "DATA ERASURE CERTIFICATE", font=title_font, fill="#000000")

    # Horizontal line
    draw.line([(50, 120), (img_width-50, 120)], fill="#CCCCCC", width=1)

    # Report ID in top right
    draw.text((img_width-300, 40), "CERTIFICATE NO.", font=small_font, fill="#666666")
    draw.text((img_width-300, 60), certificate_data['reportId'].split('-')[0].upper(), 
              font=header_font, fill="#000000")

    # Main content in grid layout
    y = 160
    left_col = 100
    mid_col = 400
    right_col = 700

    # Row 1
    draw.text((left_col, y), "DEVICE DETAILS", font=header_font, fill="#000000")
    draw.text((mid_col, y), "WIPE INFORMATION", font=header_font, fill="#000000")
    draw.text((right_col, y), "VERIFICATION", font=header_font, fill="#000000")

    y += 40
    # Device column
    draw.text((left_col, y), "Device Name", font=small_font, fill="#666666")
    draw.text((left_col, y+20), certificate_data['deviceName'], font=field_font, fill="#000000")

    draw.text((left_col, y+60), "Serial Number", font=small_font, fill="#666666")
    draw.text((left_col, y+80), certificate_data['deviceSerial'], font=field_font, fill="#000000")

    draw.text((left_col, y+120), "Device Type", font=small_font, fill="#666666")
    draw.text((left_col, y+140), certificate_data['deviceType'], font=field_font, fill="#000000")

    # Wipe column
    draw.text((mid_col, y), "Method", font=small_font, fill="#666666")
    draw.text((mid_col, y+20), certificate_data['wipeMethod'], font=field_font, fill="#000000")

    draw.text((mid_col, y+60), "Start Time", font=small_font, fill="#666666")
    draw.text((mid_col, y+80), certificate_data['startTime'], font=field_font, fill="#000000")

    draw.text((mid_col, y+120), "End Time", font=small_font, fill="#666666")
    draw.text((mid_col, y+140), certificate_data['endTime'], font=field_font, fill="#000000")

    # Status column
    draw.text((right_col, y), "Status", font=small_font, fill="#666666")
    status_color = "#00A651" if certificate_data['wipeStatus'] == "Completed" else "#FF0000"
    draw.text((right_col, y+20), "● " + certificate_data['wipeStatus'].upper(), 
              font=field_font, fill=status_color)

    draw.text((right_col, y+60), "Files Verified", font=small_font, fill="#666666")
    draw.text((right_col, y+80), str(certificate_data.get('filesVerified', 10)), 
              font=field_font, fill="#000000")

    # Verification Summary Box
    y = 420
    draw.rectangle([100, y, img_width-100, y+180], outline="#EEEEEE", width=2, fill="#FAFAFA")
    draw.text((120, y+20), "VERIFICATION SUMMARY", font=header_font, fill="#000000")
    
    draw.text((120, y+50), f"Total Hashes Verified: {certificate_data.get('filesVerified', 10)}", 
              font=field_font, fill="#333333")
    draw.text((120, y+75), f"All hashes confirmed as wiped from target location", 
              font=field_font, fill="#333333")
    
    # Show first and last hash as examples
    if 'verificationHashes' in certificate_data and len(certificate_data['verificationHashes']) > 0:
        hashes = certificate_data['verificationHashes']
        draw.text((120, y+110), "Sample verified hashes:", font=small_font, fill="#666666")
        draw.text((120, y+130), f"First: {hashes[0][:32]}...", font=small_font, fill="#999999")
        if len(hashes) > 1:
            draw.text((120, y+150), f"Last:  {hashes[-1][:32]}...", font=small_font, fill="#999999")

    # Digital signature preview (truncated)
    y = 620
    draw.text((120, y), "Digital Signature:", font=small_font, fill="#666666")
    sig_hex = signature.hex()
    sig_preview = sig_hex[:6] + "..." + sig_hex[-4:]
    draw.text((120, y+20), sig_preview, font=small_font, fill="#999999")

    # Add "Certified by SecureWipe" above signature line
    y = 680
    draw.text((200, y), "Certified by SecureWipe", font=field_font, fill="#000000")

    # Signature line
    y = 710
    draw.line([(200, y), (500, y)], fill="#000000", width=1)
    draw.text((200, y+10), "Authorized Signature", font=small_font, fill="#666666")

    draw.line([(700, y), (1000, y)], fill="#000000", width=1)
    draw.text((700, y+10), "Date", font=small_font, fill="#666666")
    draw.text((700, y-20), datetime.now().strftime("%Y-%m-%d"), font=field_font, fill="#000000")

    # Footer
    draw.rectangle([0, img_height-40, img_width, img_height], fill="#000000")
    footer_text = "This certificate verifies the complete and secure erasure of all specified data"
    bbox = draw.textbbox((0,0), footer_text, font=small_font)
    w = bbox[2] - bbox[0]
    draw.text(((img_width - w) // 2, img_height-25), footer_text, font=small_font, fill="#FFFFFF")

    img_path = f"{fname_base}.png"
    img.save(img_path)
    print(f"✅ Certificate image generated: {img_path}")
    return img_path

# -----------------------------
# Send Email with Certificate (using SSL on port 465)
# -----------------------------
def send_email(sender_email, sender_password, receiver_email, subject, body, attachments=[]):
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    # Attach files
    for file in attachments:
        try:
            with open(file, "rb") as f:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename={os.path.basename(file)}')
            msg.attach(part)
        except Exception as e:
            print(f"⚠️ Could not attach {file}: {e}")

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg)
        print(f"✅ Email sent to {receiver_email}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

# -----------------------------
# Generate Certificate + Sign
# -----------------------------
def generate_certificate(certificate_data):
    fname_base = f"wipe_certificate_{certificate_data['reportId']}"

    # Save JSON
    with open(f"{fname_base}.json", "w") as f:
        json.dump(certificate_data, f, indent=4)

    # Generate keys
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Save private key (but don't send to user)
    with open(f"{fname_base}_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Save public key
    with open(f"{fname_base}_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # Sign JSON
    with open(f"{fname_base}.json", "rb") as f:
        cert_bytes = f.read()
    signature = private_key.sign(
        cert_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    with open(f"{fname_base}.sig", "wb") as f:
        f.write(signature)

    # Generate certificate image
    img_path = generate_certificate_image(certificate_data, signature, fname_base)

    # Return only files to be sent to user (excluding private key)
    return [f"{fname_base}.json", f"{fname_base}_public.pem", f"{fname_base}.sig", img_path]

# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    print("=== DATA WIPE VERIFICATION TOOL ===\n")

    # Load hashes from file
    hash_file = "diverse_drive_hashes.json"
    hash_list = load_hashes_from_file(hash_file)
    
    if not hash_list:
        print(f"\n❌ No hashes loaded from '{hash_file}'. Please ensure the file exists and contains a JSON array of SHA256 hashes.")
        print("\nExpected format:")
        print('[\n    "hash1",\n    "hash2",\n    ...\n]')
        exit(1)
    
    if len(hash_list) != 10:
        print(f"\n⚠️ Warning: Expected 10 hashes but found {len(hash_list)}")
        proceed = input("Continue anyway? (y/n): ").strip().lower()
        if proceed != 'y':
            exit(1)

    folder_path = input("\nEnter the folder path to scan: ").strip()
    wipeMethod = input("Enter the wipe method used (e.g., DoD 3-pass, NIST 800-88): ").strip()

    deviceName, deviceSerial, deviceType = get_system_info()
    startTime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\nStarting verification process...")

    success, not_found_hashes, found_hashes = verify_multiple_wipes_in_folder(hash_list, folder_path)

    if success:
        endTime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        certificate = {
            "reportId": str(uuid.uuid4()),
            "deviceName": deviceName,
            "deviceSerial": deviceSerial,
            "deviceType": deviceType,
            "wipeMethod": wipeMethod,
            "wipeStatus": "Completed",
            "startTime": startTime,
            "endTime": endTime,
            "filesVerified": len(hash_list),
            "verificationHashes": not_found_hashes,  # List of successfully wiped hashes
            "hashFile": hash_file
        }
       
        attachments = generate_certificate(certificate)
       
        # -----------------------------
        # Send certificate to user (via configured environment or input)
        # -----------------------------
        print("\nEnter email details to send certificate:")
        sender_email = os.environ.get("SECUREWIPE_SMTP_EMAIL", "")
        sender_password = os.environ.get("SECUREWIPE_SMTP_PASSWORD", "")
        if not sender_email:
            sender_email = input("Sender Email (or set SECUREWIPE_SMTP_EMAIL): ").strip()
        if not sender_password:
            sender_password = input("Sender Password / App Key (or set SECUREWIPE_SMTP_PASSWORD): ").strip()
        receiver_email = input("Receiver Email: ").strip()

        if sender_email and sender_password and receiver_email:
            send_email(
                sender_email,
                sender_password,
                receiver_email,
                subject="Data Wipe Verification Certificate - All Files Verified",
            body=f"""Dear User,

Please find attached your data wipe verification certificate and related files.

Verification Summary:
- Total files checked: {len(hash_list)}
- All files successfully verified as wiped
- Certificate ID: {certificate['reportId']}
- Verification completed: {endTime}

The attached certificate confirms that all {len(hash_list)} specified files have been completely erased from the target location.

Best regards,
SecureWipe Verification System""",
            attachments=attachments
        )
       
    else:
        print(f"\n❌ Wipe verification failed. {len(found_hashes)} file(s) still found.")
        print("Certificate not generated.")
        
        # Optionally show which hashes failed
        if found_hashes:
            print("\nFailed hashes (still found in folder):")
            for i, h in enumerate(found_hashes, 1):
                print(f"  {i}. {h}")
