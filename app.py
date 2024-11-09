import os
import warnings
import logging
import base64
from face_recognition_and_liveness.face_recognition.encode_faces import encode_single_face
import tensorflow as tf
from tensorflow import keras
# Suppress TensorFlow logging
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # 0 = all messages are logged, 1 = INFO messages are not printed, 2 = INFO and WARNING messages are not printed, 3 = INFO, WARNING, and ERROR messages are not printed
logging.getLogger('tensorflow').setLevel(logging.ERROR)  # Only show errors

# Suppress scikit-learn warnings
warnings.filterwarnings("ignore", category=UserWarning)

from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy

# import our model from folder
from face_recognition_and_liveness.face_liveness_detection.face_recognition_liveness_app import recognition_liveness

app = Flask(__name__, static_folder='static')
app.secret_key = 'web_app_for_face_recognition_and_liveness' # something super secret
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Users(db.Model):
    username = db.Column(db.String(100), primary_key=True)
    name = db.Column(db.String(100))
    password = db.Column(db.String(100))

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        session.pop('name', None)
        username = request.form['username']
        password = request.form['password']
        user = Users.query.filter_by(username=username).first()
        print(user)
        if user is not None and user.password == password:
            session['name'] = user.name # store variable in session
            detected_name, label_name = recognition_liveness('face_recognition_and_liveness/face_liveness_detection/liveness.model',
                                                    'face_recognition_and_liveness/face_liveness_detection/label_encoder.pickle',
                                                    'face_recognition_and_liveness/face_liveness_detection/face_detector',
                                                    'face_recognition_and_liveness/face_recognition/encoded_faces.pickle',
                                                    confidence=0.5)
            if user.name == detected_name and label_name == 'real':
                return redirect(url_for('main'))
            else:
                return render_template('login_page.html', invalid_user=True, username=username)
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
        
        # Save the face image
        if face_image:
            # Remove the data URL prefix
            face_image = face_image.split(',')[1]
            face_image_data = base64.b64decode(face_image)
            image_path = f"face_recognition_and_liveness/face_recognition/dataset/{username}.jpg"
            with open(image_path, "wb") as f:
                f.write(face_image_data)
            
            # Encode the face
            encodings_path = "face_recognition_and_liveness/face_recognition/encoded_faces.pickle"
            encode_single_face(image_path, name, encodings_path)
        else:
            return render_template('register.html', error="Face image is required")
        
        # Create new user
        new_user = Users(username=username, name=name, password=password)
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # add users to database
        if not Users.query.filter_by(username='jom_ariya').first():
            new_user = Users(username='jom_ariya', password='123456789', name='Ariya')
            db.session.add(new_user)

        if not Users.query.filter_by(username='earth_ekaphat').first():
            new_user_2 = Users(username='earth_ekaphat', password='123456789', name='Ekaphat')
            db.session.add(new_user_2)

        if not Users.query.filter_by(username='bonus_ekkawit').first():
            new_user_3 = Users(username='bonus_ekkawit', password='123456789', name='Ekkawit')
            db.session.add(new_user_3)

        db.session.commit()

    app.run(debug=True)