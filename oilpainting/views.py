from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import Image
from .serializers import InputImageSerializer,ArticleImageSerializer,ArticleCreateSerializer
from nst import styletransfer


# 이미지 업로드 - 유화 변환 기능
class ImageUploadview(APIView):
    def post(self, request):
        input_img_serializer = InputImageSerializer(data=request.data)
        dnn_num = request.data['number']
        if input_img_serializer.is_valid():
            input_img_serializer.save(image_user=request.user)
            
            # 이미지 변환 함수 호출
            latest_idx = Image.objects.order_by('-pk')[0].pk
            styletransfer(latest_idx, dnn_num)
            
            return Response("저장 완료", status=status.HTTP_200_OK)
        else:
            return Response("실패", status=status.HTTP_400_BAD_REQUEST)
        
class ArticleView(APIView):
    def post(self, request):
        article_serializer = ArticleCreateSerializer(data = request.data)
        print(request.data)
        if article_serializer.is_valid():
            article_serializer.save(article_user = request.user)
            return Response("저장완료", status=status.HTTP_201_CREATED)
        return Response(article_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get(self, request):
        article_img = Image.objects.filter(img_user = request.user).last() #로그인 한 유저의 이미지 모델 중 최근 모델
        article_img_serializer = ArticleImageSerializer(article_img)
        return Response(article_img_serializer.data, status = status.HTTP_200_OK)