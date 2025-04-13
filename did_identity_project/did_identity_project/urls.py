"""
URL configuration for did_identity_project project.
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from did_app.views import (
    IndexView, RegisterPageView, LoginPageView, QRDisplayView, DashboardView,
    IssueCredentialPageView, VerifyCredentialPageView, CredentialsPageView,
    CredentialDetailPageView
)

urlpatterns = [
    path('', IndexView.as_view(), name='index'),
    path('register/', RegisterPageView.as_view(), name='register_page'),
    path('login/', LoginPageView.as_view(), name='login_page'),
    path('dashboard/', DashboardView.as_view(), name='dashboard'),
    path('qr/display/', QRDisplayView.as_view(), name='qr_display'),
    path('issue_credential/', IssueCredentialPageView.as_view(), name='issue_credential'),
    path('verify_credential/', VerifyCredentialPageView.as_view(), name='verify_credential'),
    path('credentials/', CredentialsPageView.as_view(), name='credentials'),
    path('credential/<str:credential_id>/', CredentialDetailPageView.as_view(), name='credential_detail'),
    path('admin/', admin.site.urls),
    path('api/', include('did_app.urls')),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
