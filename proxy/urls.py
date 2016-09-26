from django.conf.urls import url

from . import views

app_name = 'proxy'

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^store/?$', views.store, name='store'),
    url(r'^fetch/?$', views.fetch, name='fetch'),
    url(r'^delete/?$', views.delete, name='delete'),
    url(r'^delete_id/?$', views.delete_id, name='delete_id'),
]
