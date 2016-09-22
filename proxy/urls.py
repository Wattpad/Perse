from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^store/?$', views.store, name='store'),
    url(r'^fetch/?$', views.fetch, name='fetch'),
    url(r'^delete/?$', views.delete, name='delete'),
]
