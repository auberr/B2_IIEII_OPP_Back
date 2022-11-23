from django.urls import path
from oilpainting import views

urlpatterns = [
        path('imgtoop/', views.ImageUploadview.as_view(), name='image_upload_view'),
        path('imgtoop/2/',views.ArticleView.as_view(), name = 'article_view'),
]