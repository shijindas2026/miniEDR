import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'edr_server.settings')
django.setup()

from django.contrib.auth.models import User
from alerts.models import UserProfile

roles = ['admin', 'analyst', 'viewer']
for r in roles:
    u, created = User.objects.get_or_create(username=r)
    u.set_password(r) # Password same as role
    u.save()
    p, _ = UserProfile.objects.get_or_create(user=u)
    p.role = r
    p.save()
    print(f"User '{r}' (role: {r}) synced successfully")
