from django.urls import path
from oilpainting import views

urlpatterns = [
        path('imgtoop/', views.ImageUploadview.as_view(), name='image_upload_view'),
]