from users.models import User
from users.serializers import UserSerializer, UserCreateSerializer, CustomTokenObtainPairSerializer
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.response import Response
from users.serializers import UserSerializer, CustomTokenObtainPairSerializer, UserprofileSerializer, UserprofileImageCreateSerializer, FollowSerializer
from users.models import User
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.generics import get_object_or_404
from django.contrib.auth import authenticate, logout
from django.contrib.auth.hashers import check_password
from django.shortcuts import redirect, render
import requests
import json 

class UserCreateView(APIView):
    def post(self, request):
        # 가입시 password 1 과 password2 가 일치하지 않을 때
        if request.data['password'] != request.data['password1']:
            return Response({"message":f"password가 일치하지 않습니다."}, status=status.HTTP_400_BAD_REQUEST)
        
        # username 의 길이가 50자 이상이거나 없을때
        if len(request.data['username'])>50 or len(request.data['username'])<1:
            return Response({"message":f"username이 50자를 넘거나 1자이내일 수 없습니다"}, status=status.HTTP_400_BAD_REQUEST)
        
        # username 이 존재할때 
        exist_user = User.objects.filter(username=request.data['username'])
        if exist_user:
            return Response({"message":f"다른 아이디를 사용해주세요."}, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = UserCreateSerializer(data=request.data)
        
        if serializer.is_valid():
            serializer.save()
            return Response({"message":"가입완료!"}, status=status.HTTP_201_CREATED)
        else:
            return Response({"message":f"${serializer.errors}"}, status=status.HTTP_400_BAD_REQUEST)


class UserAuthView(APIView):
    def get(self, request):
        # token 있는데 signin.html 접속할 때
        try:
            access_token = request.headers['Authorization']
            if request.headers['Authorization'] is not None:
                token = request.headers['Authorization']
                refresh_token = str(token)
                access_token = str(token)
                
                if access_token:
                    return Response(
                        {
                            "refresh" : refresh_token,
                            "access": access_token
                        }, status=status.HTTP_200_OK)
            
        except:
            return Response({"message": "KEY_ERROR"}, status=400)
    
    def post(self, request):
        
        # 존재하지 않는 유저일때
        exist_user = User.objects.filter(username=request.data['username'])
        if not exist_user:
            return Response({"message":f"존재하지 않는 유저입니다."}, status=status.HTTP_400_BAD_REQUEST)
        
        # 비밀번호가 틀렸을때
        username=User.objects.get(username=request.data['username'])
        password=request.data.get("password")
        if not check_password(password, username.password):
            return Response({"message":f"잘못된 패스워드입니다."}, status=status.HTTP_400_BAD_REQUEST)
        
        user = authenticate(username=request.data.get("username"), password=request.data.get("password"))
        
        if user.is_authenticated:
            token = CustomTokenObtainPairSerializer.get_token(user)
            refresh_token = str(token)
            access_token = str(token.access_token)
            print(access_token)
            serializer = UserSerializer(user)
            response = Response(
                {
                    "refresh" : refresh_token,
                    "access": access_token
                }, status=status.HTTP_200_OK)
            
            return response
        

        
class SignoutView(APIView) :
    def post(self,request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            "message" : 'success'
        }
        return response


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer



class ProfileView(APIView):
    def get(self, request, user_id):
        profile = get_object_or_404(User, id=user_id)
        serializer = UserprofileSerializer(profile)
        return Response(serializer.data)

    def put(self, request, user_id):
        profile = User.objects.get(id=user_id)
        update_serializer = UserprofileImageCreateSerializer(profile, data=request.data)
        if update_serializer.is_valid():
            update_serializer.save()
            return Response(update_serializer.data, status=status.HTTP_200_OK)
        else:
            return Response({"message":f"${update_serializer.errors}"}, status=status.HTTP_400_BAD_REQUEST)

# 팔로우 기능
class FollowView(APIView):
    # 팔로우 정보 테스트용
    def get(self, request, user_id):
        users = User.objects.all()
        users_serializer = FollowSerializer(users, many=True)
        return Response(users_serializer.data, status=status.HTTP_200_OK)
    
    # 팔로우/언팔로우 기능
    def post(self, request, user_id):
        person = get_object_or_404(User, id=user_id)
        if person.followers.filter(pk=request.user.pk).exists():
            person.followers.remove(request.user)
            return Response("unfollow", status=status.HTTP_200_OK)
        else:
            person.followers.add(request.user)
            return Response("follow", status=status.HTTP_200_OK)
        

class KakaoSignInView(APIView):
    def get(self, request):
        client_id = '383932bc9488431b9961d6fc0b2e5cc8'
        redirect_uri = "http://127.0.0.1:5500/html/main.html"
        # 리다이렉트를 여기서 
        return redirect(
            f"https://kauth.kakao.com/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&response_type=code"
        )
        
# 중간에 프론트 리다이렉트 uri 에서 callback CallbackVEiw 함수로 넘겨준다.
        
class KakaoSignInCallbackView(APIView):
    def post(self, request):

        try:
            print(2)
            # code = request.GET.get("code")
            code = json.loads(request.body)
            code = code["code"]
            print(3)
            print(code)
            client_id = '3e14ee98dc81007009e23c953ca452c8'
            redirect_uri = "http://127.0.0.1:5500/html/main.html"
            
            token_request = requests.get(
                f"https://kauth.kakao.com/oauth/token?grant_type=authorization_code&client_id={client_id}&redirect_uri={redirect_uri}&code={code}"
            )
            print(token_request)

            token_json = token_request.json()
            print(token_json)
            print(token_json['access_token'])
            
            error = token_json.get("error",None)

            if error is not None :
                return Response({"message": "INVALID_CODE"}, status = 400)
            
            access_token = token_json['access_token']

        except KeyError:
            return Response({"message" : "INVALID_TOKEN"}, status = 400)

        except access_token.DoesNotExist:
            return Response({"message" : "INVALID_TOKEN"}, status = 400)

        profile_request = requests.get(
            "https://kapi.kakao.com/v2/user/me", headers={"Authorization": f"Bearer {access_token}"},
        )
        # ------get kakaotalk profile info------#

        print(profile_request)
        # # profile_json = request.data.get("access")
        # print(profile_json)
        # profile_request = requests.get(
        #     "https://kapi.kakao.com/v2/user/me", headers={"Authorization": f"Bearer {profile_json}"},
        # )
        account_info = profile_request.json()
        print(account_info)
        kakao_id = account_info.get("id") 
        # # print(profile_json)
        print(f"카카오id{kakao_id}")
        
        if User.objects.filter(username=kakao_id).exists():
            print(1)
            user = User.objects.get(username=kakao_id)
            print(user)
            token = CustomTokenObtainPairSerializer.get_token(user)
            refresh_token = str(token)
            access_token = str(token.access_token)
            response = Response(
                {
                    "refresh" : refresh_token,
                    "access": access_token
                }, status=status.HTTP_200_OK)
            print(refresh_token)
            print(access_token)
            return response
        
        # response = Response(
        #     {
        #         "refresh" : 'temp',
        #         "access": 'temp'
        #     }, status=status.HTTP_200_OK)
        
        # return response
        
        else:
            User(username=kakao_id).save()
            user_check = User.objects.filter(username=kakao_id)
            print(user_check)
            token = CustomTokenObtainPairSerializer.get_token(user)
            refresh_token = str(token)
            access_token = str(token.access_token)
            response = Response(
                {
                    "refresh" : refresh_token,
                    "access": access_token
                }, status=status.HTTP_200_OK)
            
            return response
        