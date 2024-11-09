import face_recognition
import pickle
import cv2
import os
import numpy as np

def encode_faces(dataset_path, encodings_path):
    # Initialize the list of known encodings and known names
    known_encodings = []
    known_names = []

    # Loop over the image paths in our dataset
    for name in os.listdir(dataset_path):
        person_dir = os.path.join(dataset_path, name)
        if os.path.isdir(person_dir):
            for filename in os.listdir(person_dir):
                img_path = os.path.join(person_dir, filename)
                image = cv2.imread(img_path)
                rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)

                # Detect the (x, y)-coordinates of the bounding boxes
                boxes = face_recognition.face_locations(rgb, model="hog")

                # Compute the facial embedding for the face
                encodings = face_recognition.face_encodings(rgb, boxes)

                # Loop over the encodings
                for encoding in encodings:
                    known_encodings.append(encoding)
                    known_names.append(name)

    # Dump the facial encodings + names to disk
    print("[INFO] Serializing encodings...")
    data = {"encodings": known_encodings, "names": known_names}
    with open(encodings_path, "wb") as f:
        f.write(pickle.dumps(data))

def encode_single_face(image_path, name, encodings_path):
    # Load the existing encodings
    if os.path.exists(encodings_path):
        with open(encodings_path, "rb") as f:
            data = pickle.load(f)
        known_encodings = data["encodings"]
        known_names = data["names"]
    else:
        known_encodings = []
        known_names = []

    # Load and encode the new face
    image = cv2.imread(image_path)
    rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
    boxes = face_recognition.face_locations(rgb, model="hog")
    encodings = face_recognition.face_encodings(rgb, boxes)

    # Add the new encoding
    for encoding in encodings:
        known_encodings.append(encoding)
        known_names.append(name)

    # Save the updated encodings
    data = {"encodings": known_encodings, "names": known_names}
    with open(encodings_path, "wb") as f:
        f.write(pickle.dumps(data))

if __name__ == "__main__":
    dataset_path = "face_recognition_and_liveness/face_recognition/dataset"
    encodings_path = "face_recognition_and_liveness/face_recognition/encoded_faces.pickle"
    encode_faces(dataset_path, encodings_path)
