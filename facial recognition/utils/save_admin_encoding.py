import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="face_recognition_models")

import os
import face_recognition
import joblib

admin_dir = "dataset/admin"
embeddings_dir = "embeddings"
joblib_file = "admin_encodings.joblib"

os.makedirs(embeddings_dir, exist_ok=True)

admin_encodings = []

if not os.path.exists(admin_dir):
    raise FileNotFoundError(f"❌ Admin folder not found: {admin_dir}")

for img_name in os.listdir(admin_dir):
    path = os.path.join(admin_dir, img_name)
    try:
        image = face_recognition.load_image_file(path)
        encs = face_recognition.face_encodings(image)
        if encs:
            admin_encodings.append(encs[0])
    except Exception as e:
        print(f"⚠️ Could not process {img_name}: {e}")

if len(admin_encodings) == 0:
    raise ValueError("❌ No valid admin faces found in the dataset!")

save_path = os.path.join(embeddings_dir, joblib_file)
joblib.dump(admin_encodings, save_path)
print(f"✅ Saved {len(admin_encodings)} admin encodings to {save_path}")
