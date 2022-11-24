from rest_framework.generics import get_object_or_404
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from .models import Image, Article
from .serializers import InputImageSerializer,ArticleImageSerializer,ArticleCreateSerializer, ArticleSerializer,ArticleDetailSerializer,ArticleListSerializer,ArticleCommentSerializer,ArticleCommentCreateSerializer
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
        article_img = Image.objects.filter(image_user = request.user).last() #로그인 한 유저의 이미지 모델 중 최근 모델
        article_img_serializer = ArticleImageSerializer(article_img)
        return Response(article_img_serializer.data, status = status.HTTP_200_OK)



class LikeView(APIView):
    # 좋아요 한적 없으면 post 가능하게 / 있으면 아무기능 없게
    def post(self, request, article_id):
        article = get_object_or_404(Article, id=article_id)
        if request.user in article.likes.all():
            article.likes.remove(request.user)
            return Response("unlike", status=status.HTTP_200_OK)
        else:
            article.likes.add(request.user)
            return Response("like", status=status.HTTP_200_OK)
        

class MainView(APIView):
    def get(self, request):
        articles = Article.objects.all()
        article_serializer = ArticleSerializer(articles, many = True)
        return Response(article_serializer.data, status = status.HTTP_200_OK )

class ArticleDetailView(APIView):
    def get(self, request, article_id):
        article = Article.objects.get(id= article_id)
        article_serializer = ArticleDetailSerializer(article)        
        return Response(article_serializer.data, status = status.HTTP_200_OK )
    
    def put(self, request, article_id):
        article = get_object_or_404(Article,id=article_id)
        article_serializer = ArticleCreateSerializer(article,data=request.data)
        if request.user == article.article_user:
            if article_serializer.is_valid():
                article_serializer.save()
                return Response(article_serializer.data,status=status.HTTP_200_OK)
            else:
                return Response(article_serializer.errors,status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response("권한이 없습니다.",status=status.HTTP_403_FORBIDDEN)
        
    def delete(self,request,article_id):
        article = get_object_or_404(Article,id=article_id)
        if request.user == article.article_user:
            article.delete()
            return Response("삭제 되었습니다.",status=status.HTTP_200_OK)
        else:
            return Response("권한이 없습니다.",status=status.HTTP_403_FORBIDDEN)
        
class ArticleCommentView(APIView):
    def get(self,request,article_id):
        article = Article.objects.get(id=article_id)
        comments = article.comment_set.all()
        article_serializer = ArticleCommentSerializer(comments,many=True)
        return Response(article_serializer.data,status=status.HTTP_200_OK)
    
    def post(self,request,article_id):
        article_serializer = ArticleCommentCreateSerializer(data=request.data)
        if article_serializer.is_valid():
            article_serializer.save(user=request.user,article_id = article_id)
            return Response(article_serializer.data,status=status.HTTP_201_CREATED)
        else:
            return Response(article_serializer.errors,status=status.HTTP_400_BAD_REQUEST)
        
        