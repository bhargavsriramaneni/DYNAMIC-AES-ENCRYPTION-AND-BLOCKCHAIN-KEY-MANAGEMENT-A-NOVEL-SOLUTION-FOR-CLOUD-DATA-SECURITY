import numpy as np
from flask import Flask, request, render_template, flash, redirect, send_file, url_for
from werkzeug.utils import secure_filename
from flask import Flask, request, render_template, flash, redirect, url_for, session
import os
import secrets
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from hashlib import blake2b
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from google.oauth2.service_account import Credentials
import io
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.image import load_img, img_to_array
from werkzeug.security import generate_password_hash, check_password_hash
USER_DATA = {
    "admin": generate_password_hash("password123")  # Username: admin, Password: password123
}
# Load the trained model for fingerprint authentication
model = load_model('authorized_unauthorized_model.h5')

# Constants for image processing
IMG_HEIGHT = 224
IMG_WIDTH = 224

# Class labels
CLASS_LABELS = ['Authorized', 'Unauthorized']
# Path to your Google Drive API credentials.json
SERVICE_ACCOUNT_FILE = r'G:\project code january\FILE STORAGE_\credentials.json'

if not os.path.exists(SERVICE_ACCOUNT_FILE):
    raise FileNotFoundError(f"Service account file not found: {SERVICE_ACCOUNT_FILE}")

# Flask app setup
app = Flask(__name__)
app.secret_key = 'AIzaSyClrUJm9TKjjApUb18QaDaPazGZiAoqfdA'

# Temporary folder to store files locally
TEMP_FOLDER = 'temp'
if not os.path.exists(TEMP_FOLDER):
    os.makedirs(TEMP_FOLDER)

# Google Drive API setup
SCOPES = ['https://www.googleapis.com/auth/drive.file']
credentials = Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE, scopes=SCOPES)
drive_service = build('drive', 'v3', credentials=credentials)

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'pptx'}

# Email Configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = "sathiyabenin@gmail.com"  # Replace with your email
EMAIL_PASSWORD = "bnsa kpll fxfk suee"  # Replace with your email password

# ECC key pair generation
private_key = ec.generate_private_key(ec.SECP384R1())
public_key = private_key.public_key()

# Save public key for verification
with open('public_key.pem', 'wb') as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def send_email_with_key(user_email, file_id, encryption_key):
    try:
        subject = "File Shared and Encryption Key"
        body = f"Your file has been shared successfully.\n\nFile ID: {file_id}\nEncryption Key: {encryption_key}"

        message = MIMEMultipart()
        message['From'] = EMAIL_ADDRESS
        message['To'] = user_email
        message['Subject'] = subject

        message.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(message)

        print(f"[DEBUG] Email sent to {user_email} with encryption key and file ID.")
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")


def upload_to_google_drive(filepath, filename):
    try:
        print(f"[DEBUG] Uploading file: {filepath} as {filename}")
        file_metadata = {'name': filename}
        media = MediaFileUpload(filepath, mimetype='application/octet-stream')
        file = drive_service.files().create(body=file_metadata, media_body=media, fields='id').execute()
        file_id = file.get('id')
        print(f"[DEBUG] File uploaded successfully with ID: {file_id}")

        return file_id
    except Exception as e:
        print(f"[ERROR] Error uploading file to Google Drive: {e}")
        raise


def share_uploaded_file(file_id, user_email, encryption_key):
    try:
        permission = {
            'type': 'user',
            'role': 'reader',
            'emailAddress': user_email
        }
        drive_service.permissions().create(fileId=file_id, body=permission).execute()
        print(f"[DEBUG] File shared with email: {user_email}")

        # Send email with file ID and encryption key
        send_email_with_key(user_email, file_id, encryption_key)
    except Exception as e:
        print(f"[ERROR] Unable to share file or send email: {e}")


def list_files_in_drive():
    try:
        results = drive_service.files().list(pageSize=10, fields="files(id, name)").execute()
        items = results.get('files', [])
        if not items:
            return []
        else:
            return items
    except Exception as e:
        print(f"[ERROR] Unable to list files: {e}")
        return []


def download_file_from_google_drive(file_id, destination):
    try:
        request = drive_service.files().get_media(fileId=file_id)
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request)
        done = False
        while not done:
            status, done = downloader.next_chunk()
            print(f"[DEBUG] Download {int(status.progress() * 100)}%.")
        fh.seek(0)
        with open(destination, 'wb') as f:
            f.write(fh.read())
        print(f"[DEBUG] File downloaded successfully to {destination}")
    except Exception as e:
        print(f"[ERROR] Error downloading file from Google Drive: {e}")
        raise

# Route for the initial login page
@app.route('/', methods=['GET', 'POST'])
def check_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Validate user credentials
        if username in USER_DATA and check_password_hash(USER_DATA[username], password):
            session['user'] = username  # Store the user in the session
            flash('Login successful! Proceeding to fingerprint authentication.', 'success')
            return redirect(url_for('home'))  # Redirect to the fingerprint authentication page
        else:
            flash('Invalid username or password. Please try again.', 'danger')

    return render_template('check.html')  # Renders the username and password login page

# Add a route for the login page
# Add a route for the login page
@app.route('/login', methods=['GET', 'POST'])
def home():
    try:
        if request.method == 'POST':
            # Check if a file is uploaded
            if 'fingerprint' not in request.files:
                flash('No fingerprint image uploaded. Please try again.')
                return redirect(request.url)

            file = request.files['fingerprint']
            if file.filename == '':
                flash('No file selected. Please upload your fingerprint.')
                return redirect(request.url)

            # Save the uploaded file temporarily
            filename = secure_filename(file.filename)
            file_path = os.path.join(TEMP_FOLDER, filename)
            file.save(file_path)

            # Verify fingerprint
            if os.path.exists(file_path):
                # Process the image
                try:
                    img = load_img(file_path, target_size=(IMG_HEIGHT, IMG_WIDTH))
                    img_array = img_to_array(img) / 255.0  # Normalize the image
                    img_array = np.expand_dims(img_array, axis=0)  # Add batch dimension

                    # Make prediction
                    prediction = model.predict(img_array)[0][0]
                    predicted_class = int(prediction > 0.5)
                    predicted_label = CLASS_LABELS[predicted_class]

                    # Remove temporary file
                    os.remove(file_path)

                    # Check authentication result
                    if predicted_label == 'Authorized':
                        flash('Access Granted!')
                        return redirect(url_for('upload_page'))  # Redirect to the home page
                    else:
                        flash('Access Denied! Unauthorized fingerprint.')
                        return redirect('/login')
                except Exception as e:
                    flash(f"Error processing the fingerprint: {str(e)}")
                    app.logger.error(f"Fingerprint processing error: {e}")
            else:
                flash('Failed to process the fingerprint image. Please try again.')
                return redirect('/login')
    except Exception as e:
        flash(f"An unexpected error occurred: {str(e)}")
        app.logger.error(f"Unexpected error in /login: {e}")

    return render_template('login.html')

# Ensure the temp folder exists
if not os.path.exists('temp'):
    os.makedirs('temp')



@app.route('/upload', methods=['GET', 'POST'])
def upload_page():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        user_emails = request.form.get('user_emails')

        if not user_emails:
            flash('Email IDs are required to share the encryption key.')
            return redirect(request.url)

        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            temp_filepath = os.path.join(TEMP_FOLDER, filename)
            print(f"[DEBUG] Saving file to temporary path: {temp_filepath}")
            file.save(temp_filepath)

            # Encrypt the file
            shared_key = private_key.private_numbers().private_value.to_bytes(48, byteorder='big')
            kdf = HKDF(
                algorithm=SHA256(),
                length=32,
                salt=None,
                info=b'handshake data'
            )
            key = kdf.derive(shared_key)
            encryption_key = key.hex()
            nonce = secrets.token_bytes(12)
            chacha = ChaCha20Poly1305(key)
            with open(temp_filepath, 'rb') as f:
                plaintext = f.read()
            ciphertext = chacha.encrypt(nonce, plaintext, None)
            encrypted_filepath = temp_filepath + ".encrypted"
            with open(encrypted_filepath, 'wb') as f:
                f.write(nonce + ciphertext)
            print(f"[DEBUG] File encrypted and saved to: {encrypted_filepath}")

            # Upload encrypted file to Google Drive
            try:
                file_id = upload_to_google_drive(encrypted_filepath, filename + ".encrypted")

                # Send the encryption key to all provided email addresses
                email_list = [email.strip() for email in user_emails.split(',')]
                for email in email_list:
                    share_uploaded_file(file_id, email, encryption_key)

                flash(f'File successfully uploaded to Google Drive with ID: {file_id}')
                print(f"[DEBUG] File uploaded successfully with ID: {file_id}")
            except Exception as e:
                flash(f'Failed to upload to Google Drive: {e}')
                print(f"[ERROR] Failed to upload to Google Drive: {e}")

            # Clean up temporary files
            print(f"[DEBUG] Cleaning up temporary files: {temp_filepath} and {encrypted_filepath}")
            os.remove(temp_filepath)
            os.remove(encrypted_filepath)

            return redirect('/upload')
        else:
            flash('Invalid file type')
            print(f"[ERROR] Invalid file type: {file.filename}")
            return redirect('/upload')
    return render_template('upload.html')

@app.route('/download', methods=['GET', 'POST'])
def download_page():
    if request.method == 'POST':
        file_id = request.form.get('file_id')
        decryption_key = request.form.get('decryption_key')

        if not file_id or not decryption_key:
            flash('File ID or decryption key not provided')
            return redirect('/download')

        try:
            print(f"[DEBUG] Downloading file with ID: {file_id}")
            temp_filepath = os.path.join(TEMP_FOLDER, 'downloaded_file.encrypted')
            download_file_from_google_drive(file_id, temp_filepath)

            # Decrypt the file
            try:
                decryption_key_bytes = bytes.fromhex(decryption_key)
            except ValueError:
                flash('Invalid decryption key format. Please provide a valid hexadecimal string.')
                print("[ERROR] Invalid decryption key format.")
                return redirect('/download')

            with open(temp_filepath, 'rb') as f:
                encrypted_data = f.read()
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            chacha = ChaCha20Poly1305(decryption_key_bytes)
            plaintext = chacha.decrypt(nonce, ciphertext, None)

            # Retrieve the original filename from Google Drive metadata
            file_metadata = drive_service.files().get(fileId=file_id, fields="name").execute()
            original_filename = file_metadata['name'].replace(".encrypted", "")  # Remove `.encrypted` suffix

            decrypted_filepath = os.path.join(TEMP_FOLDER, original_filename)
            with open(decrypted_filepath, 'wb') as f:
                f.write(plaintext)

            print(f"[DEBUG] File decrypted successfully to {decrypted_filepath}")
            return send_file(decrypted_filepath, as_attachment=True, download_name=original_filename)
        except Exception as e:
            flash(f"Error during file download or decryption: {e}")
            print(f"[ERROR] {e}")
            return redirect('/download')

    files = list_files_in_drive()
    return render_template('download.html', files=files)


if __name__ == '__main__':
    app.run(debug=True, port=8700)


