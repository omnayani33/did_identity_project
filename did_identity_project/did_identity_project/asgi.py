"""
ASGI config for did_identity_project project.
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'did_identity_project.settings')

application = get_asgi_application()
