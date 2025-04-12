"""
WSGI config for did_identity_project project.
"""

import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'did_identity_project.settings')

application = get_wsgi_application()
