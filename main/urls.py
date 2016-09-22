from django.conf.urls import include
from django.conf.urls import url


urlpatterns = [
    url(r'^proxy/', include('proxy.urls'), name='proxy'),
]
