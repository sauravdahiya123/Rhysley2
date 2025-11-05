from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
import uuid
from django.conf.urls import handler404

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('esign.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)



handler404 = 'esign.views.handle_not_found'
