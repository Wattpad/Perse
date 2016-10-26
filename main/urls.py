from django.conf.urls import include
from django.conf.urls import url


urlpatterns = [
    url(r'^web/', include('web.urls', namespace='web')),
]
