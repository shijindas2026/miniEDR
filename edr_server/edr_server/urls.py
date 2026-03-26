from django.contrib import admin
from django.urls import path, include
from alerts.views import home, dashboard_page, alerts_page, machines_page, rules_page

urlpatterns = [

    # Home
    path('', home),

    # Django admin
    path('admin/', admin.site.urls),

    # Authentication
    path('accounts/', include('django.contrib.auth.urls')),

    # Include all urls from alerts
    path('', include('alerts.urls')),

]