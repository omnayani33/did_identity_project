"""
Utilities for Decentralized Identifiers (DIDs) and cryptographic operations
"""
import os
import uuid
import hashlib
import base64
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Environment variable for encryption key
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', 'g9EbzknMXhjLhHCQf4WTgZG9YZbRZQfRNtxwsIbm3d8=')

def generate_did():
    """
    Generate a new DID with associated key pair
    """
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Get public key
    public_key = private_key.public_key()
    
    # Serialize keys to PEM format
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    # Generate DID
    did_uuid = str(uuid.uuid4())
    did_hash = hashlib.sha256(did_uuid.encode()).hexdigest()
    did_string = f"did:example:{did_hash}"
    
    return did_string, pem_public, pem_private

def encrypt_private_key(private_key):
    """
    Encrypt private key for secure storage
    """
    # Initialize Fernet with encryption key
    key = ENCRYPTION_KEY.encode()
    f = Fernet(key)
    
    # Encrypt private key
    encrypted_key = f.encrypt(private_key.encode())
    
    return encrypted_key.decode()

def decrypt_private_key(encrypted_private_key):
    """
    Decrypt private key for use
    """
    # Initialize Fernet with encryption key
    key = ENCRYPTION_KEY.encode()
    f = Fernet(key)
    
    # Decrypt private key
    decrypted_key = f.decrypt(encrypted_private_key.encode())
    
    return decrypted_key.decode()

def sign_credential(credential_data, private_key_pem):
    """
    Sign credential data with private key
    """
    # Create unique credential ID
    credential_id = f"vc:{str(uuid.uuid4())}"
    
    # Add ID to credential data
    credential_data['id'] = credential_id
    
    # Serialize credential data to JSON
    credential_json = json.dumps(credential_data, sort_keys=True)
    
    # Load private key
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )
    
    # Sign credential data
    signature = private_key.sign(
        credential_json.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    # Base64 encode signature
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    
    return credential_id, signature_b64

def verify_credential(credential_id, credential_data, signature_b64, public_key_pem):
    """
    Verify credential signature with public key
    """
    # Add ID to credential data for verification
    credential_data['id'] = credential_id
    
    # Serialize credential data to JSON
    credential_json = json.dumps(credential_data, sort_keys=True)
    
    # Load public key
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend()
    )
    
    # Decode signature
    signature = base64.b64decode(signature_b64)
    
    try:
        # Verify signature
        public_key.verify(
            signature,
            credential_json.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
