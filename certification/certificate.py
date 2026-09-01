from PIL import Image, ImageDraw, ImageFont
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from datetime import datetime
import json, uuid, hashlib, os

# -----------------------------
# Utility functions
# -----------------------------
def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def build_merkle_root(hashes):
    """Builds Merkle root from list of hex hashes"""
    if not hashes:
        return None
    level = hashes[:]
    while len(level) > 1:
        new_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i+1] if i+1 < len(level) else left  # duplicate last if odd
            new_level.append(sha256((left + right).encode()))
        level = new_level
    return level[0]

# -----------------------------
# Step 1: Generate Certificate
# -----------------------------
certificate = {
    "reportId": str(uuid.uuid4()),
    "deviceName": "Laptop-01",
    "deviceSerial": "SN123456789",
    "deviceType": "SSD",
    "wipeMethod": "DoD 3-pass",
    "wipeStatus": "Completed",
    "startTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "endTime": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
}

# Save initial certificate JSON
with open("wipe_certificate.json", "w") as f:
    json.dump(certificate, f, indent=4)

# -----------------------------
# Step 2: Compute Certificate Hash
# -----------------------------
with open("wipe_certificate.json", "rb") as f:
    cert_bytes = f.read()
verification_hash = sha256(cert_bytes)
certificate["verificationHash"] = verification_hash

# Update JSON with verification hash
with open("wipe_certificate.json", "w") as f:
    json.dump(certificate, f, indent=4)

# -----------------------------
# Step 3: Generate Keys (once per system ideally)
# -----------------------------
if not os.path.exists("private_key.pem"):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
else:
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

# -----------------------------
# Step 4: Sign the JSON certificate
# -----------------------------
signature = private_key.sign(
    cert_bytes,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

with open("wipe_signature.sig", "wb") as f:
    f.write(signature)

# -----------------------------
# Step 5: Generate Image Certificate
# -----------------------------
img_width, img_height = 1000, 700
img = Image.new("RGB", (img_width, img_height), "white")
draw = ImageDraw.Draw(img)

try:
    title_font = ImageFont.truetype("arialbd.ttf", 40)
    field_font = ImageFont.truetype("arial.ttf", 24)
except:
    title_font = ImageFont.load_default()
    field_font = ImageFont.load_default()

# Title
draw.text((img_width // 2 - 200, 40), "Data Wipe Certificate", font=title_font, fill="black")

# Fields
y = 120
line_gap = 50
for key, value in certificate.items():
    draw.text((100, y), f"{key}: {value}", font=field_font, fill="black")
    y += line_gap

# Add signature preview
sig_preview = signature.hex()[:40] + "..."
draw.text((100, y+20), f"Digital Signature: {sig_preview}", font=field_font, fill="black")

# Border
draw.rectangle([20, 20, img_width - 20, img_height - 20], outline="black", width=5)

# Save image
img.save("wipe_certificate.png")

# -----------------------------
# Step 6: Build Merkle Root (simulate multiple certs)
# -----------------------------
# In practice, this would include hashes from many certificates
certificate_hashes = [verification_hash]  

# Example: load previous registry entries
if os.path.exists("registry.json"):
    with open("registry.json", "r") as f:
        registry = json.load(f)
        for entry in registry:
            certificate_hashes.append(entry["hash"])
else:
    registry = []

merkle_root = build_merkle_root(certificate_hashes)

# -----------------------------
# Step 7: Save Registry Entry
# -----------------------------
registry_entry = {
    "reportId": certificate["reportId"],
    "hash": verification_hash,
    "merkleRoot": merkle_root
}
registry.append(registry_entry)

with open("registry.json", "w") as f:
    json.dump(registry, f, indent=4)

print("✅ Certificate JSON + Image + Keys + Signature + Registry updated.")
