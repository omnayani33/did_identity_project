# Decentralized Identity Verification (DID) Platform

A secure, decentralized identity platform where users can:
- Register and log in using Django auth
- Generate DIDs (Decentralized Identifiers) using public-private key pairs
- Log in with biometric face recognition (image upload-based)
- Generate QR codes containing DID/public key
- Issue and verify verifiable credentials (VCs)
- Simulate blockchain to store credential hashes
- Admin panel to manage users and credentials

## Features

1. **User Registration & Login**  
   - Django's built-in `User` model + Django REST Framework (DRF)

2. **DID Generation**  
   - Generate using cryptography (public/private keys)
   - Securely encrypt private key in database

3. **Biometric Face Login**  
   - Upload face photo for biometric authentication
   - Uses `face_recognition` library

4. **QR Code Generation**  
   - Generate QR codes with DID and public key for sharing

5. **Verifiable Credentials (VC)**  
   - Issue and digitally sign credentials
   - Verify signatures with issuer's public key

6. **Blockchain Simulation**  
   - Simulate blockchain for storing credential hashes

7. **Admin Panel**  
   - Manage users, DIDs, and credentials

## API Endpoints

- `POST /api/register/` → Register user  
- `POST /api/login/` → Login  
- `POST /api/logout/` → Logout  
- `POST /api/generate_did/` → Generate DID  
- `POST /api/upload_face/` → Upload face image  
- `POST /api/face_login/` → Login using face image  
- `GET /api/qr/` → Get QR code data  
- `GET /api/qr/download/` → Download QR code image  
- `GET /api/qr/display/` → Display QR code in template  
- `POST /api/issue_credential/` → Issue a credential  
- `POST /api/verify_credential/` → Verify credential  
- `GET /api/credentials/` → Get user's credentials  
- `GET /api/credentials/<credential_id>/` → Get credential details  

## Setup Instructions

```bash
# 1. Create virtual environment
python -m venv venv && source venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run migrations
python manage.py makemigrations
python manage.py migrate

# 4. Create superuser (admin)
python manage.py createsuperuser

# 5. Start server
python manage.py runserver
