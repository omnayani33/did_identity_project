from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from .models import DID, FaceData, VerifiableCredential, BlockchainTransaction
import base64
import uuid
import os

class UserRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration
    """
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'password', 'password2', 'first_name', 'last_name')

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            password=validated_data['password']
        )
        return user

class UserLoginSerializer(serializers.Serializer):
    """
    Serializer for user login
    """
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)

class DIDSerializer(serializers.ModelSerializer):
    """
    Serializer for DID model
    """
    username = serializers.ReadOnlyField(source='user.username')
    
    class Meta:
        model = DID
        fields = ('did', 'public_key', 'username', 'created_at')
        read_only_fields = ('did', 'public_key', 'created_at')

class FaceDataUploadSerializer(serializers.Serializer):
    """
    Serializer for face data upload
    """
    face_image = serializers.ImageField(required=True)

class FaceLoginSerializer(serializers.Serializer):
    """
    Serializer for face login
    """
    face_image = serializers.ImageField(required=True)

class VerifiableCredentialSerializer(serializers.ModelSerializer):
    """
    Serializer for Verifiable Credentials
    """
    issuer_username = serializers.ReadOnlyField(source='issuer_did.user.username')
    subject_username = serializers.ReadOnlyField(source='subject_did.user.username')
    human_readable_claims = serializers.SerializerMethodField()
    
    class Meta:
        model = VerifiableCredential
        fields = ('id', 'credential_type', 'issuer_username', 'subject_username', 
                  'claims', 'human_readable_claims', 'status', 'issuance_date', 'expiration_date', 
                  'blockchain_hash', 'blockchain_tx_id')
        read_only_fields = ('id', 'signature', 'issuer_username', 'subject_username', 
                           'issuance_date', 'blockchain_hash', 'blockchain_tx_id', 'human_readable_claims')
    
    def get_human_readable_claims(self, obj):
        """Convert claims to human-readable format"""
        if not obj.claims:
            return []
            
        human_readable_claims = []
        for key, value in obj.claims.items():
            # Convert snake_case or camelCase to title case with spaces
            readable_key = key.replace('_', ' ').replace('-', ' ')
            # Convert camelCase to words with spaces
            readable_key = ''.join(' ' + c if c.isupper() else c for c in readable_key).strip()
            # Title case the result
            readable_key = readable_key.title()
            
            # Handle nested dictionaries
            if isinstance(value, dict):
                nested_values = []
                for k, v in value.items():
                    nested_key = k.replace('_', ' ').replace('-', ' ')
                    nested_key = ''.join(' ' + c if c.isupper() else c for c in nested_key).strip()
                    nested_key = nested_key.title()
                    nested_values.append(f"{nested_key}: {v}")
                value_str = ", ".join(nested_values)
            elif isinstance(value, list):
                value_str = ", ".join(str(item) for item in value)
            elif isinstance(value, bool):
                value_str = "Yes" if value else "No"
            else:
                value_str = str(value)
                
            human_readable_claims.append({
                "name": readable_key,
                "value": value_str
            })
        
        return human_readable_claims

class CredentialIssueSerializer(serializers.Serializer):
    """
    Serializer for issuing credentials
    """
    subject_username = serializers.CharField(required=True)
    credential_type = serializers.ChoiceField(choices=VerifiableCredential.CREDENTIAL_TYPES)
    claims = serializers.JSONField(required=True)
    expiration_date = serializers.DateTimeField(required=False, allow_null=True)

class CredentialVerifySerializer(serializers.Serializer):
    """
    Serializer for verifying credentials
    """
    credential_id = serializers.CharField(required=True)
    
class QRCodeSerializer(serializers.Serializer):
    """
    Serializer for QR code generation
    """
    did = serializers.CharField(read_only=True)
    qr_code = serializers.CharField(read_only=True)  # Base64 encoded QR code

class BlockchainTransactionSerializer(serializers.ModelSerializer):
    """
    Serializer for blockchain transactions
    """
    class Meta:
        model = BlockchainTransaction
        fields = ('tx_hash', 'credential_hash', 'block_number', 'timestamp', 'data')
        read_only_fields = ('tx_hash', 'block_number', 'timestamp')
