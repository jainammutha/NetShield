import os
import wmi
import pythoncom
import warnings
import logging
import base64
import secrets
from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from face_recognition_and_liveness.face_recognition.encode_faces import encode_single_face
import tensorflow as tf
from tensorflow import keras
from face_recognition_and_liveness.face_liveness_detection.face_recognition_liveness_app import recognition_liveness

# Suppress TensorFlow logging
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
logging.getLogger('tensorflow').setLevel(logging.ERROR)

# Suppress scikit-learn warnings
warnings.filterwarnings("ignore", category=UserWarning)

app = Flask(__name__, static_folder='static')
app.secret_key = 'web_app_for_face_recognition_and_liveness'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Users(db.Model):
    username = db.Column(db.String(100), primary_key=True)
    name = db.Column(db.String(100))
    password = db.Column(db.String(128))  # Increased size for hashed passwords
    auth_key = db.Column(db.String(64))  # Column for auth key
    is_admin = db.Column(db.Boolean, default=False)  # New column for admin status

@app.route('/')
def index():
    return redirect(url_for('login'))

def usb_key_path():
    pythoncom.CoInitialize()  # Initialize the COM library for the current thread
    c = wmi.WMI()
    for usb_device in c.Win32_DiskDrive():
        if usb_device.InterfaceType == "USB":
            for partition in usb_device.associators("Win32_DiskDriveToDiskPartition"):
                for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                    drive_letter = logical_disk.DeviceID
                    return os.path.join(drive_letter + "\\", "auth_key.txt")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session.pop('name', None)  # Clear the session name
        
        # Ensure username and password are assigned from the form
        username = request.form.get('username')  # Use .get() to avoid KeyError
        password = request.form.get('password')  # Use .get() to avoid KeyError
        
        # Step 1: Check User Credentials
        user = Users.query.filter_by(username=username).first()  # Ensure user is assigned here
        
        if user is not None and user.password == password:
            # Step 2: Perform USB Authentication
            user_auth_key = user.auth_key  # Get the user's auth key from the database
            usb_auth_key_path = usb_key_path()  # Path to the USB key

            print(f"Checking USB authentication for user: {username}")

            # Check if usb_auth_key_path is valid
            if usb_auth_key_path is not None:
                # Check USB authentication using the user's auth key
                try:
                    with open(usb_auth_key_path, "r") as f:
                        usb_auth_key = f.read().strip()
                        if user_auth_key == usb_auth_key:  # Match the user's auth key with the USB key
                            session['name'] = user.name  # Store the user's name in the session
                            flash("USB authentication successful!", "success")
                            print("Redirecting to main page...")  # Debugging statement
                            return redirect(url_for('main'))  # Redirect to the main page
                        else:
                            print("USB authentication failed. Keys do not match. Proceeding to face recognition.")
                except FileNotFoundError:
                    print(f"Warning: USB auth key file not found at {usb_auth_key_path}. Proceeding to face recognition.")
            else:
                print("Warning: No USB device found. Proceeding to face recognition.")

            # Perform Face Recognition only if USB authentication fails
            try:
                detected_name, label_name = recognition_liveness(
                    'face_recognition_and_liveness/face_liveness_detection/dataset/model.keras',
                    'face_recognition_and_liveness/face_liveness_detection/dataset/label_encoder.pkl',
                    'face_recognition_and_liveness/face_liveness_detection/face_detector',
                    'face_recognition_and_liveness/face_recognition/encoded_faces.pickle',
                    confidence=0.5
                )

                if user.name == detected_name and label_name == 'real':
                    session['name'] = user.name
                    flash("Face recognition successful!", "success")
                    return redirect(url_for('main'))
                else:
                    return render_template('login_page.html', invalid_user=True, username=username)
            except Exception as e:
                print(f"Face recognition error: {e}")
                return render_template('login_page.html', error="Face recognition failed.")
        else:
            return render_template('login_page.html', incorrect=True)

    return render_template('login_page.html')

@app.route('/main', methods=['GET'])
def main():
    if 'name' in session:
        name = session['name']
        return render_template('main_page.html', name=name)
    else:
        return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        name = request.form['name']
        password = request.form['password']
        face_image = request.form['face_image']
        
        # Check if username already exists
        existing_user = Users.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error="Username already exists")
        
        # Generate a random key for USB authentication
        auth_key = secrets.token_hex(16)

        # Save the key to a file
        auth_key_path = f"face_recognition_and_liveness/face_recognition/dataset/{username}_auth_key.txt"
        with open(auth_key_path, "w") as f:
            f.write(auth_key)
        
        # Inform the user to save the key on a USB drive
        flash(f"Your USB authentication key has been generated. Please save it as 'auth_key.txt' on your USB drive. Key: {auth_key}", "info")
        
        # Save the face image
        if face_image:
            # Remove the data URL prefix
            face_image = face_image.split(',')[1]
            face_image_data = base64.b64decode(face_image)
            image_path = f"face_recognition_and_liveness/face_recognition/dataset/{username}.jpg"
            with open(image_path, "wb") as f:
                f.write(face_image_data)

            encodings_path = "face_recognition_and_liveness/face_recognition/encoded_faces.pickle"
            encode_single_face(image_path, name, encodings_path)
        else:
            return render_template('register.html', error="Face image is required")
        
        # Create new user with the auth key
        new_user = Users(username=username, name=name, password=password, auth_key=auth_key)
        db.session.add(new_user)
        db.session.commit()
        
        # Redirect to login page after successful registration
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/update_face', methods=['GET', 'POST'])
def update_face():
    if 'name' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        face_image = request.form['face_image']
        
        if face_image:
            # Remove the data URL prefix
            face_image = face_image.split(',')[1]
            face_image_data = base64.b64decode(face_image)
            
            # Get the username of the logged-in user
            user = Users.query.filter_by(name=session['name']).first()
            if not user:
                return render_template('update_face.html', error="User not found")
            
            image_path = f"face_recognition_and_liveness/face_recognition/dataset/{user.username}.jpg"
            with open(image_path, "wb") as f:
                f.write(face_image_data)
            
            # Encode the face
            encodings_path = "face_recognition_and_liveness/face_recognition/encoded_faces.pickle"
            encode_single_face(image_path, session['name'], encodings_path)
            
            return render_template('update_face.html', success="Face updated successfully")
        else:
            return render_template('update_face.html', error="Face image is required")
    
    return render_template('update_face.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'name' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        user = Users.query.filter_by(name=session['name']).first()

        if not user or user.password != current_password:
            flash("Current password is incorrect", "error")
            return render_template('change_password.html')

        if new_password != confirm_password:
            flash("New passwords do not match", "error")
            return render_template('change_password.html')

        if len(new_password) < 8:
            flash("New password must be at least 8 characters long", "error")
            return render_template('change_password.html')

        user.password = new_password
        db.session.commit()

        flash("Password changed successfully", "success")
        return redirect(url_for('main'))

    return render_template('change_password.html')

@app.route('/delete_user', methods=['GET', 'POST'])
def delete_user_page():
    if request.method == 'POST':
        username = request.form.get('username')
        user = Users.query.filter_by(username=username).first()
        
        if user:
            # Construct the paths to the user's files
            face_image_path = f"face_recognition_and_liveness/face_recognition/dataset/{username}.jpg"
            auth_key_path = f"face_recognition_and_liveness/face_recognition/dataset/{username}_auth_key.txt"
            
            # Delete the user from the database
            db.session.delete(user)
            db.session.commit()
            
            # Delete the user's face image file if it exists
            if os.path.exists(face_image_path):
                os.remove(face_image_path)
                logging.info(f"Deleted face image for user: {username}")
            
            # Delete the user's authentication key file if it exists
            if os.path.exists(auth_key_path):
                os.remove(auth_key_path)
                logging.info(f"Deleted auth key for user: {username}")
            
            flash("User deleted successfully", "success")
        else:
            flash("User not found", "error")
        
        return redirect(url_for('delete_user_page'))  # Redirect to the same page after deletion

    return render_template('delete_user.html')  # Render the delete user page for GET requests

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        db.session.commit()

    app.run(debug=True)