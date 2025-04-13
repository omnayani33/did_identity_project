# did_identity_project
# Decentralized Identity Verification (DID) System

This project is a Decentralized Identity Verification (DID) system built using Django and Python for the backend, focused on creating, managing, and verifying digital identities using decentralized methods, including blockchain-like transaction simulation. The system incorporates user authentication, face recognition-based login, verifiable credential issuance, and QR code handling.

## Features

- **User Authentication**: Secure user registration and login mechanisms.
- **DID Creation**: Generation of Decentralized Identifiers (DIDs) for each user.
- **Face Recognition-based Login**: Users can log in using face recognition for secure authentication.
- **Verifiable Credential Issuance**: Issuance and storage of verifiable credentials to users.
- **Credential Verification**: Verification of issued credentials.
- **QR Code Handling**: Generation and scanning of QR codes to retrieve credentials and DID-related information.
- **Blockchain Transaction Simulation**: Simulated blockchain transactions to demonstrate the DID process.

## Technologies Used

- **Backend**: Django (Python)
- **Face Recognition**: OpenCV, Face Recognition library
- **Database**: SQLite (for simplicity, but can be extended to PostgreSQL/MySQL)
- **QR Code Generation**: `qrcode` library
- **Blockchain Simulation**: Basic simulation of blockchain transactions
- **Django REST Framework**: For building the API endpoints

## Project Setup

### Prerequisites

- Python 3.x
- Django 4.x
- Django REST Framework
- OpenCV
- Face Recognition library
- `qrcode` Python library

### Installation

1. Clone this repository:

   ```bash
   git clone https://github.com/yourusername/did-system.git
   cd did-system
