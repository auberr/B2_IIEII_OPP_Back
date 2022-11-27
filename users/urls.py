from django.urls import path
from users import views
from rest_framework_simplejwt.views import TokenRefreshView
from django.urls import path



urlpatterns = [
    path('signup/', views.UserCreateView.as_view(), name='user_create_view'),
    path('signin/', views.UserAuthView.as_view(), name='user_auth_view'),
    path('signout/', views.SignoutView.as_view(), name='user_signout_view'),
    # 토큰 발행
    path('api/token/', views.CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('<int:user_id>/profile/', views.ProfileView.as_view(), name='profile_view'),
    path('<int:user_id>/follow/', views.FollowView.as_view(), name='follow_view'),
    #로그인 요청을 보낼 url
    path('signin/kakao/', views.KakaoSignInView.as_view(), name='kakao_login'),
    #받은 인가 코드로 접근 토근을 받아 유저의 정보를 가져올 url
    path('signin/kakao/callback/', views.KakaoSignInCallbackView.as_view(), name='kakao_login_callback'),
]