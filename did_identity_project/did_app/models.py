from django.db import models
from django.contrib.auth.models import User
import json

class DID(models.Model):
    """
    Decentralized Identifier model with cryptographic key pairs
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='did')
    did = models.CharField(max_length=100, unique=True)
    public_key = models.TextField()
    encrypted_private_key = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"DID: {self.did} - User: {self.user.username}"

class FaceData(models.Model):
    """
    Model to store references to user's face data for biometric authentication
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='face_data')
    face_encoding_path = models.CharField(max_length=255)
    face_image_path = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Face Data for {self.user.username}"

class VerifiableCredential(models.Model):
    """
    Model for Verifiable Credentials (VC)
    """
    CREDENTIAL_TYPES = (
        ('identity', 'Identity Credential'),
        ('email', 'Email Verification'),
        ('address', 'Address Verification'),
        ('employment', 'Employment Verification'),
        ('education', 'Education Verification'),
        ('custom', 'Custom Credential'),
    )

    STATUS_CHOICES = (
        ('active', 'Active'),
        ('revoked', 'Revoked'),
        ('expired', 'Expired'),
    )

    # Credential information
    id = models.CharField(max_length=100, primary_key=True)
    credential_type = models.CharField(max_length=20, choices=CREDENTIAL_TYPES)
    subject_did = models.ForeignKey(DID, on_delete=models.CASCADE, related_name='subject_credentials')
    issuer_did = models.ForeignKey(DID, on_delete=models.CASCADE, related_name='issued_credentials')
    
    # Credential claims/attributes stored as JSON
    claims = models.JSONField(default=dict)
    
    # Credential verification
    signature = models.TextField()
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='active')
    
    # Blockchain reference
    blockchain_hash = models.CharField(max_length=66, blank=True, null=True)
    blockchain_tx_id = models.CharField(max_length=66, blank=True, null=True)
    
    # Timestamps
    issuance_date = models.DateTimeField(auto_now_add=True)
    expiration_date = models.DateTimeField(null=True, blank=True)
    revocation_date = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.credential_type} credential for {self.subject_did.user.username}"

    def get_claims_as_json(self):
        return json.dumps(self.claims)

class BlockchainTransaction(models.Model):
    """
    Model to simulate blockchain transactions for credentials
    """
    tx_hash = models.CharField(max_length=66, primary_key=True)
    credential_hash = models.CharField(max_length=66)
    block_number = models.IntegerField()
    timestamp = models.DateTimeField(auto_now_add=True)
    data = models.TextField()  # JSON representation of the transaction

    def __str__(self):
        return self.tx_hash
