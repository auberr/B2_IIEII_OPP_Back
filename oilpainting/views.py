from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import Image
from .serializers import InputImageSerializer
from nst import styletransfer
# Create your views here.


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