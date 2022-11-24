from django.urls import path
from oilpainting import views

urlpatterns = [
        path('', views.MainView().as_view(), name = 'main'),
        path('imgtoop/', views.ImageUploadview.as_view(), name='image_upload_view'),
        path('imgtoop/2/',views.ArticleView.as_view(), name = 'article_view'),
        path('<int:article_id>/detail/', views.ArticleDetailView.as_view(), name = 'detail_view'),
        path('<int:article_id>/likes/', views.LikeView.as_view(), name = 'like_view'),
]