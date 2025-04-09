from flask import Flask, render_template, request, redirect, url_for, flash
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.image import load_img, img_to_array
import numpy as np
import os

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'secret_key_here'  # Replace with a secure secret key

# Load the trained model
model = load_model('../authorized_unauthorized_model.h5')

# Path to save uploaded images
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Constants for image processing
IMG_HEIGHT = 224
IMG_WIDTH = 224

# Class labels
CLASS_LABELS = [ 'Authorized' ,'Unauthorized']

@app.route('/')
def login():
    return render_template('login.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'fingerprint' not in request.files:
        flash('No file part')
        return redirect(request.url)

    file = request.files['fingerprint']

    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)

    if file:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)

        # Process the uploaded image
        img = load_img(filepath, target_size=(IMG_HEIGHT, IMG_WIDTH))
        img_array = img_to_array(img) / 255.0  # Normalize the image
        img_array = np.expand_dims(img_array, axis=0)  # Add batch dimension

        # Make prediction
        prediction = model.predict(img_array)[0][0]
        predicted_class = int(prediction > 0.5)
        predicted_label = CLASS_LABELS[predicted_class]

        if predicted_label == 'Authorized':
            flash('Access Granted!')
            return redirect(url_for('index'))
        else:
            flash('Access Denied! Unauthorized fingerprint.')
            return redirect(url_for('login'))

@app.route('/index')
def index():
    return render_template('index.html', message='Welcome to the Index Page!')

if __name__ == '__main__':
    app.run(debug=True)
