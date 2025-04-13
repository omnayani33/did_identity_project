"""
Utilities for face recognition

Note: This is a simplified version that doesn't use face_recognition library
but instead just stores the images and simulates recognition for demonstration purposes.
"""
import os
import uuid
import json
import hashlib
import logging
from pathlib import Path
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from PIL import Image

logger = logging.getLogger(__name__)

def save_face_encoding(user_id, face_image, face_data_dir):
    """
    Process face image and save it along with a simulated encoding
    """
    # Create face data directory if it doesn't exist
    os.makedirs(face_data_dir, exist_ok=True)
    
    # Generate unique filenames
    encoding_filename = f"face_encoding_{user_id}.json"
    image_filename = f"face_image_{user_id}.jpg"
    
    encoding_path = os.path.join(face_data_dir, encoding_filename)
    image_path = os.path.join(face_data_dir, image_filename)
    
    # Save the uploaded image temporarily
    temp_path = default_storage.save(f'temp_face_{uuid.uuid4()}.jpg', ContentFile(face_image.read()))
    temp_file_path = default_storage.path(temp_path)
    
    try:
        # Load image with PIL
        with Image.open(temp_file_path) as img:
            # Resize for consistency
            img = img.resize((250, 250))
            # Save the image
            img.save(image_path)
        
        # Create a simplified "encoding" by generating a hash of the image
        # This is not real face recognition, just a demo placeholder
        image_hash = hashlib.md5(open(image_path, 'rb').read()).hexdigest()
        
        # Save a simple encoding (just metadata and hash in this demo)
        encoding_data = {
            'user_id': user_id,
            'image_hash': image_hash,
            'image_path': image_path
        }
        
        with open(encoding_path, 'w') as f:
            json.dump(encoding_data, f)
        
        logger.info(f"Saved face data for user {user_id}")
        return encoding_path, image_path
    
    except Exception as e:
        logger.error(f"Error processing face image: {str(e)}")
        raise
    finally:
        # Clean up the temporary file
        default_storage.delete(temp_path)

def compare_face_encodings(uploaded_face, face_data_dir):
    """
    Compare uploaded face with stored encodings
    
    This is a simplified demo version that just compares image hashes
    """
    # Save the uploaded image temporarily
    temp_path = default_storage.save(f'temp_face_{uuid.uuid4()}.jpg', ContentFile(uploaded_face.read()))
    temp_file_path = default_storage.path(temp_path)
    
    try:
        # Create a hash of the uploaded image
        with Image.open(temp_file_path) as img:
            img = img.resize((250, 250))
            img.save(temp_file_path)
        
        # Generate hash for the uploaded image
        uploaded_hash = hashlib.md5(open(temp_file_path, 'rb').read()).hexdigest()
        
        # Scan through all stored face encodings
        face_data_path = Path(face_data_dir)
        for encoding_file in face_data_path.glob("face_encoding_*.json"):
            # Extract user_id from filename
            user_id = encoding_file.stem.split('_')[-1]
            
            # Load the stored encoding data
            with open(encoding_file, 'r') as f:
                stored_data = json.load(f)
            
            stored_hash = stored_data.get('image_hash')
            
            # In a real face recognition system, this would do actual face comparison
            # For this demo, we'll just check if the hashes are similar enough
            # (This is a very simplified simulation and not secure for real use)
            if stored_hash and uploaded_hash[:10] == stored_hash[:10]:
                return int(user_id)
        
        # If no match found
        return None
    
    except Exception as e:
        logger.error(f"Error comparing face images: {str(e)}")
        return None
    finally:
        # Clean up the temporary file
        default_storage.delete(temp_path)
