from django.urls import path
from . import views

app_name = 'viewer'

urlpatterns = [
    path('', views.index, name='index'),
    path('download/<path:file_path>', views.download_file, name='download_file'),
    path('download_zip/', views.download_zip, name='download_zip'),
]
