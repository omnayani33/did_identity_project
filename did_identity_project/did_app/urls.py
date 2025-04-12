from django.urls import path
from .views import (
    RegisterView, LoginView, LogoutView, 
    GenerateDIDView, UploadFaceView, FaceLoginView, GenerateQRView, 
    QRCodeDownloadView, IssueCredentialView, VerifyCredentialView, 
    UserCredentialsView, CredentialDetailView, QRDisplayView, RevokeCredentialView
)

urlpatterns = [    
    # API endpoints
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    
    # DID management
    path('generate_did/', GenerateDIDView.as_view(), name='generate_did'),
    
    # Face recognition
    path('upload_face/', UploadFaceView.as_view(), name='upload_face'),
    path('face_login/', FaceLoginView.as_view(), name='face_login'),
    
    # QR code
    path('qr/', GenerateQRView.as_view(), name='generate_qr'),
    path('qr/download/', QRCodeDownloadView.as_view(), name='download_qr'),
    path('qr/download/<int:user_id>/', QRCodeDownloadView.as_view(), name='download_user_qr'),
    path('qr/display/', QRDisplayView.as_view(), name='display_qr'),
    
    # Credentials
    path('issue_credential/', IssueCredentialView.as_view(), name='issue_credential'),
    path('verify_credential/', VerifyCredentialView.as_view(), name='verify_credential'),
    path('revoke_credential/', RevokeCredentialView.as_view(), name='revoke_credential'),
    path('credentials/', UserCredentialsView.as_view(), name='user_credentials'),
    path('credentials/<str:credential_id>/', CredentialDetailView.as_view(), name='credential_detail'),
]
