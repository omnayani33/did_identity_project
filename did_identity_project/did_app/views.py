import os
import io
import json
import logging
from django.conf import settings
from django.shortcuts import get_object_or_404, render
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.utils import timezone
from django.views.generic import TemplateView
from rest_framework import status, generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import api_view, permission_classes

from .models import DID, FaceData, VerifiableCredential, BlockchainTransaction
from .serializers import (
    UserRegistrationSerializer, UserLoginSerializer, DIDSerializer,
    FaceDataUploadSerializer, FaceLoginSerializer, VerifiableCredentialSerializer,
    CredentialIssueSerializer, CredentialVerifySerializer, QRCodeSerializer,
    BlockchainTransactionSerializer
)
from .did_utils import generate_did, encrypt_private_key, decrypt_private_key, sign_credential, verify_credential
from .face_recognition_utils import save_face_encoding, compare_face_encodings
from .qr_utils import generate_qr_code
from .blockchain import simulate_blockchain_transaction

logger = logging.getLogger(__name__)

class IndexView(TemplateView):
    """
    View for displaying the home page
    """
    template_name = 'index.html'
    permission_classes = [AllowAny]

class RegisterPageView(TemplateView):
    """
    View for displaying the registration page
    """
    template_name = 'register.html'
    permission_classes = [AllowAny]

class LoginPageView(TemplateView):
    """
    View for displaying the login page
    """
    template_name = 'login.html'
    permission_classes = [AllowAny]
    
class DashboardView(TemplateView):
    """
    View for displaying the user dashboard
    """
    template_name = 'dashboard.html'
    permission_classes = [IsAuthenticated]
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        
        user = self.request.user
        context['user'] = user
        
        # Check if user has a DID
        if hasattr(user, 'did'):
            context['has_did'] = True
            context['did'] = user.did.did
            context['did_created_at'] = user.did.created_at
        else:
            context['has_did'] = False
            
        # Check if user has face data
        if hasattr(user, 'face_data'):
            context['has_face_data'] = True
        else:
            context['has_face_data'] = False
            
        # Get user's credentials
        try:
            if hasattr(user, 'did'):
                subject_credentials = VerifiableCredential.objects.filter(subject_did=user.did)
                context['credentials'] = subject_credentials
            else:
                context['credentials'] = []
        except:
            context['credentials'] = []
            
        return context

class RegisterView(generics.CreateAPIView):
    """
    API view for user registration
    """
    permission_classes = [AllowAny]
    serializer_class = UserRegistrationSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({
                "message": "User registered successfully",
                "user_id": user.id,
                "username": user.username
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    """
    API view for user login
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']
            
            user = authenticate(request, username=username, password=password)
            if user:
                login(request, user)
                return Response({
                    "message": "Login successful",
                    "user_id": user.id,
                    "username": user.username
                })
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    """
    API view for user logout
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        logout(request)
        return Response({"message": "Logged out successfully"})

class GenerateDIDView(APIView):
    """
    API view for generating DID
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        user = request.user
        
        # Check if user already has a DID
        if hasattr(user, 'did'):
            return Response(
                {"error": "User already has a DID"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Generate DID and keys
        did_string, public_key, private_key = generate_did()
        
        # Encrypt private key
        encrypted_private_key = encrypt_private_key(private_key)
        
        # Save DID
        did = DID.objects.create(
            user=user,
            did=did_string,
            public_key=public_key,
            encrypted_private_key=encrypted_private_key
        )
        
        serializer = DIDSerializer(did)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class UploadFaceView(APIView):
    """
    API view for uploading face data for biometric authentication
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """
        Handle GET requests by returning information about the face upload endpoint
        """
        user = request.user
        has_face_data = hasattr(user, 'face_data')
        
        return Response({
            "message": "Face data upload endpoint. Use POST method with a face_image to upload biometric data.",
            "endpoint": "/api/upload_face/",
            "method": "POST",
            "required_fields": ["face_image"],
            "has_face_data": has_face_data
        })
    
    def post(self, request):
        serializer = FaceDataUploadSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            face_image = serializer.validated_data['face_image']
            
            # Create face data directory if it doesn't exist
            os.makedirs(settings.FACE_DATA_DIR, exist_ok=True)
            
            # Save face encoding
            try:
                encoding_path, image_path = save_face_encoding(user.id, face_image, settings.FACE_DATA_DIR)
                
                # Save or update face data record
                face_data, created = FaceData.objects.update_or_create(
                    user=user,
                    defaults={
                        'face_encoding_path': encoding_path,
                        'face_image_path': image_path
                    }
                )
                
                return Response({
                    "message": "Face data saved successfully",
                    "created": created
                }, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)
                
            except Exception as e:
                logger.error(f"Error saving face data: {str(e)}")
                return Response(
                    {"error": f"Failed to process face image: {str(e)}"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class FaceLoginView(APIView):
    """
    API view for login with face recognition
    """
    permission_classes = [AllowAny]
    
    def get(self, request):
        """
        Handle GET requests by returning information about the face login endpoint
        """
        return Response({
            "message": "Face login endpoint. Use POST method with a face_image to authenticate.",
            "endpoint": "/api/face_login/",
            "method": "POST",
            "required_fields": ["face_image"]
        })
    
    def post(self, request):
        serializer = FaceLoginSerializer(data=request.data)
        if serializer.is_valid():
            face_image = serializer.validated_data['face_image']
            
            try:
                # Compare face with stored encodings
                user_id = compare_face_encodings(face_image, settings.FACE_DATA_DIR)
                
                if user_id:
                    user = User.objects.get(id=user_id)
                    login(request, user)
                    return Response({
                        "message": "Face login successful",
                        "user_id": user.id,
                        "username": user.username
                    })
                else:
                    return Response(
                        {"error": "Face not recognized"}, 
                        status=status.HTTP_401_UNAUTHORIZED
                    )
                    
            except Exception as e:
                logger.error(f"Face login error: {str(e)}")
                return Response(
                    {"error": f"Face login failed: {str(e)}"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class GenerateQRView(APIView):
    """
    API view for generating QR code with DID
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        
        # Check if user has a DID
        if not hasattr(user, 'did'):
            return Response(
                {"error": "User does not have a DID"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Generate QR code
        qr_data = {
            "did": user.did.did,
            "public_key": user.did.public_key
        }
        
        qr_code_base64 = generate_qr_code(json.dumps(qr_data))
        
        return Response({
            "did": user.did.did,
            "qr_code": qr_code_base64
        })

class QRCodeDownloadView(APIView):
    """
    API view for downloading QR code
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, user_id=None):
        if user_id:
            user = get_object_or_404(User, id=user_id)
        else:
            user = request.user
        
        # Check if user has a DID
        if not hasattr(user, 'did'):
            return Response(
                {"error": "User does not have a DID"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Generate QR code
        qr_data = {
            "did": user.did.did,
            "public_key": user.did.public_key
        }
        
        qr_code_img = generate_qr_code(json.dumps(qr_data), as_image=True)
        
        # Create HTTP response with image
        response = HttpResponse(content_type="image/png")
        # Save QR code image to response
        img_byte_arr = io.BytesIO()
        qr_code_img.save(img_byte_arr, format='PNG')
        response.write(img_byte_arr.getvalue())
        response['Content-Disposition'] = f'attachment; filename="did_qr_{user.username}.png"'
        
        return response

class IssueCredentialView(APIView):
    """
    API view for issuing verifiable credentials
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = CredentialIssueSerializer(data=request.data)
        if serializer.is_valid():
            # Get issuer DID
            issuer = request.user
            if not hasattr(issuer, 'did'):
                return Response(
                    {"error": "You don't have a DID to issue credentials"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get subject DID
            subject_username = serializer.validated_data['subject_username']
            try:
                subject = User.objects.get(username=subject_username)
                if not hasattr(subject, 'did'):
                    return Response(
                        {"error": f"User {subject_username} doesn't have a DID"}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
            except User.DoesNotExist:
                return Response(
                    {"error": f"User {subject_username} not found"}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            
            # Get credential data
            credential_type = serializer.validated_data['credential_type']
            claims = serializer.validated_data['claims']
            expiration_date = serializer.validated_data.get('expiration_date')
            
            # Create credential data
            credential_data = {
                "type": credential_type,
                "issuer": issuer.did.did,
                "subject": subject.did.did,
                "claims": claims,
                "issuanceDate": str(request.data)
            }
            
            if expiration_date:
                credential_data["expirationDate"] = expiration_date.isoformat()
            
            # Sign credential
            try:
                # Decrypt issuer's private key
                private_key = decrypt_private_key(issuer.did.encrypted_private_key)
                
                # Sign credential data
                credential_id, signature = sign_credential(credential_data, private_key)
                
                # Create credential in database
                credential = VerifiableCredential.objects.create(
                    id=credential_id,
                    credential_type=credential_type,
                    issuer_did=issuer.did,
                    subject_did=subject.did,
                    claims=claims,
                    signature=signature,
                    expiration_date=expiration_date
                )
                
                # Simulate blockchain transaction
                tx_hash, block_number = simulate_blockchain_transaction(credential_id, signature)
                
                # Update credential with blockchain info
                credential.blockchain_hash = f"0x{tx_hash}"
                credential.blockchain_tx_id = f"0x{tx_hash}"
                credential.save()
                
                # Create blockchain transaction record
                BlockchainTransaction.objects.create(
                    tx_hash=f"0x{tx_hash}",
                    credential_hash=f"0x{tx_hash}",
                    block_number=block_number,
                    data=json.dumps({
                        "credential_id": credential_id,
                        "issuer": issuer.did.did,
                        "subject": subject.did.did,
                        "type": credential_type
                    })
                )
                
                # Return the credential
                return Response({
                    "message": "Credential issued successfully",
                    "credential_id": credential_id,
                    "blockchain_tx": f"0x{tx_hash}"
                }, status=status.HTTP_201_CREATED)
                
            except Exception as e:
                logger.error(f"Error issuing credential: {str(e)}")
                return Response(
                    {"error": f"Failed to issue credential: {str(e)}"}, 
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class VerifyCredentialView(APIView):
    """
    API view for verifying credentials
    """
    permission_classes = [AllowAny]
    
    def get(self, request):
        # Support GET requests for verification with query parameters
        credential_id = request.query_params.get('credential_id')
        if credential_id:
            return self._verify_credential(credential_id)
        return Response(
            {"error": "Credential ID is required"}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    def post(self, request):
        serializer = CredentialVerifySerializer(data=request.data)
        if serializer.is_valid():
            credential_id = serializer.validated_data['credential_id']
            return self._verify_credential(credential_id)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
    def _verify_credential(self, credential_id, request=None):
        if not credential_id:
            return Response(
                {"error": "Credential ID is required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            # Get credential
            credential = get_object_or_404(VerifiableCredential, id=credential_id)
            
            # Check if credential is active
            if credential.status != 'active':
                return Response({
                    "verified": False,
                    "error": f"Credential is {credential.status}"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Get issuer's public key
            issuer_public_key = credential.issuer_did.public_key
            
            # Recreate credential data
            credential_data = {
                "type": credential.credential_type,
                "issuer": credential.issuer_did.did,
                "subject": credential.subject_did.did,
                "claims": credential.claims,
                "issuanceDate": credential.issuance_date.isoformat()
            }
            
            if credential.expiration_date:
                credential_data["expirationDate"] = credential.expiration_date.isoformat()
            
            # Verify signature
            is_valid = verify_credential(
                credential_id,
                credential_data,
                credential.signature,
                issuer_public_key
            )
            
            if is_valid:
                # Check blockchain confirmation
                try:
                    tx = BlockchainTransaction.objects.get(tx_hash=credential.blockchain_tx_id)
                    blockchain_confirmed = True
                    block_info = {
                        "tx_hash": tx.tx_hash,
                        "block_number": tx.block_number,
                        "timestamp": tx.timestamp.isoformat()
                    }
                except BlockchainTransaction.DoesNotExist:
                    blockchain_confirmed = False
                    block_info = None
                
                return Response({
                    "verified": True,
                    "credential_type": credential.credential_type,
                    "issuer": credential.issuer_did.user.username,
                    "subject": credential.subject_did.user.username,
                    "issuance_date": credential.issuance_date.isoformat(),
                    "blockchain_confirmed": blockchain_confirmed,
                    "blockchain_info": block_info
                })
            else:
                return Response({
                    "verified": False,
                    "error": "Invalid signature"
                }, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f"Error verifying credential: {str(e)}")
            return Response({
                "verified": False,
                "error": f"Verification failed: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserCredentialsView(APIView):
    """
    API view for getting user's credentials
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        
        # Check if user has a DID
        if not hasattr(user, 'did'):
            return Response(
                {"error": "User does not have a DID"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get credentials where user is the subject
        subject_credentials = VerifiableCredential.objects.filter(subject_did=user.did)
        
        # Get credentials where user is the issuer
        issued_credentials = VerifiableCredential.objects.filter(issuer_did=user.did)
        
        # Serialize credentials
        subject_serializer = VerifiableCredentialSerializer(subject_credentials, many=True)
        issuer_serializer = VerifiableCredentialSerializer(issued_credentials, many=True)
        
        return Response({
            "received_credentials": subject_serializer.data,
            "issued_credentials": issuer_serializer.data
        })

class CredentialDetailView(APIView):
    """
    API view for getting credential details
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request, credential_id=None):
        # Allow credential_id to be passed as a URL parameter or query parameter
        if credential_id is None:
            credential_id = request.query_params.get('credential_id')
        user = request.user
        
        # Check if user has a DID
        if not hasattr(user, 'did'):
            return Response(
                {"error": "User does not have a DID"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Get credential
        try:
            credential = VerifiableCredential.objects.get(id=credential_id)
            
            # Check if user is the subject or issuer
            if credential.subject_did.user != user and credential.issuer_did.user != user:
                return Response(
                    {"error": "You don't have permission to view this credential"}, 
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Serialize credential
            serializer = VerifiableCredentialSerializer(credential)
            
            # Get blockchain info
            try:
                tx = BlockchainTransaction.objects.get(tx_hash=credential.blockchain_tx_id)
                blockchain_info = {
                    "tx_hash": tx.tx_hash,
                    "block_number": tx.block_number,
                    "timestamp": tx.timestamp.isoformat(),
                    "data": json.loads(tx.data)
                }
            except BlockchainTransaction.DoesNotExist:
                blockchain_info = None
            
            return Response({
                "credential": serializer.data,
                "blockchain_info": blockchain_info
            })
            
        except VerifiableCredential.DoesNotExist:
            return Response(
                {"error": "Credential not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )

class QRDisplayView(TemplateView):
    """
    View for displaying QR code in a template
    """
    template_name = 'qr_display.html'
    permission_classes = [AllowAny]
    
class IssueCredentialPageView(TemplateView):
    """
    View for displaying the credential issuance page
    """
    template_name = 'issue_credential.html'
    permission_classes = [IsAuthenticated]
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        context['user'] = user
        
        # Check if user has a DID
        if hasattr(user, 'did'):
            context['has_did'] = True
        else:
            context['has_did'] = False
            
        return context

class VerifyCredentialPageView(TemplateView):
    """
    View for displaying the credential verification page
    """
    template_name = 'verify_credential.html'
    permission_classes = [AllowAny]
    
class CredentialsPageView(TemplateView):
    """
    View for displaying the user's credentials
    """
    template_name = 'credentials.html'
    permission_classes = [IsAuthenticated]
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        context['user'] = user
        
        # Check if user has a DID
        if hasattr(user, 'did'):
            context['has_did'] = True
            context['did'] = user.did.did
            
            # Get user's credentials (both issued and received)
            subject_credentials = VerifiableCredential.objects.filter(subject_did=user.did)
            issued_credentials = VerifiableCredential.objects.filter(issuer_did=user.did)
            
            context['subject_credentials'] = subject_credentials
            context['issued_credentials'] = issued_credentials
        else:
            context['has_did'] = False
            context['subject_credentials'] = []
            context['issued_credentials'] = []
            
        return context
    
class CredentialDetailPageView(TemplateView):
    """
    View for displaying the details of a single credential
    """
    template_name = 'credential_detail.html'
    permission_classes = [IsAuthenticated]
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        context['user'] = user
        
        # Get credential ID from URL
        credential_id = self.kwargs.get('credential_id')
        
        try:
            # Get credential
            credential = VerifiableCredential.objects.get(id=credential_id)
            
            # Check if user is issuer or subject (authorized to view)
            is_authorized = False
            is_issuer = False
            
            if hasattr(user, 'did'):
                if credential.issuer_did == user.did:
                    is_authorized = True
                    is_issuer = True
                elif credential.subject_did == user.did:
                    is_authorized = True
            
            if is_authorized:
                context['credential'] = credential
                context['is_issuer'] = is_issuer
                
                # Format claims as pretty JSON
                context['claims_json'] = json.dumps(credential.claims, indent=2)
                
                # Generate QR code for credential
                qr_data = {
                    "credential_id": credential.id,
                    "type": credential.credential_type,
                    "issuer": credential.issuer_did.did,
                    "subject": credential.subject_did.did
                }
                
                qr_code_base64 = generate_qr_code(json.dumps(qr_data))
                context['qr_code'] = qr_code_base64
            else:
                context['credential'] = None
        except VerifiableCredential.DoesNotExist:
            context['credential'] = None
            
        return context
    
class RevokeCredentialView(APIView):
    """
    API view for revoking a credential
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        credential_id = request.data.get('credential_id')
        
        if not credential_id:
            return Response(
                {"error": "Credential ID is required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )
            
        try:
            credential = get_object_or_404(VerifiableCredential, id=credential_id)
            
            # Check if user is the issuer
            user = request.user
            if not hasattr(user, 'did') or credential.issuer_did != user.did:
                return Response(
                    {"error": "Only the issuer can revoke a credential"}, 
                    status=status.HTTP_403_FORBIDDEN
                )
                
            # Check if already revoked
            if credential.status != 'active':
                return Response(
                    {"error": f"Credential is already {credential.status}"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                
            # Update status to revoked
            credential.status = 'revoked'
            credential.revocation_date = timezone.now()
            credential.save()
            
            return Response({
                "success": True,
                "message": "Credential revoked successfully"
            })
            
        except VerifiableCredential.DoesNotExist:
            return Response(
                {"error": "Credential not found"}, 
                status=status.HTTP_404_NOT_FOUND
            )
