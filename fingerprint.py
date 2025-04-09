import os
import shutil
import random

# Define paths for the authorized and unauthorized images
authorized_folder = "fingerprints/authorized"
unauthorized_folder = "fingerprints/unauthorized"

# Create folders if they do not exist
os.makedirs(authorized_folder, exist_ok=True)
os.makedirs(unauthorized_folder, exist_ok=True)

# Assuming you have a list of fingerprint image files
fingerprint_images = [f"fingerprint_{i}.png" for i in range(1, 11)]

# Randomly pick 5 images as authorized
authorized_images = random.sample(fingerprint_images, 5)

# The rest will be unauthorized
unauthorized_images = list(set(fingerprint_images) - set(authorized_images))

# Function to save images to the respective folder
def classify_and_save_images(images, target_folder):
    for image in images:
        # Here we're just creating empty files for demonstration
        open(image, 'a').close()  # Creating empty placeholder files
        shutil.move(image, os.path.join(target_folder, image))

# Classify and save authorized images
classify_and_save_images(authorized_images, authorized_folder)

# Classify and save unauthorized images
classify_and_save_images(unauthorized_images, unauthorized_folder)

print("Fingerprint images classified and saved.")