from rest_framework import serializers
from oilpainting.models import Image, Article


class InputImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Image
        fields = ("input_image",)
        
class ArticleImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Image
        fields = '__all__'

class ArticleCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Article
        fields = ['title','content','img']

class ArticleListSerializer(serializers.ModelSerializer):
    article_user = serializers.SerializerMethodField()

    # 1. list를 불러올때 좋아요 갯수도 불러오고싶을때! + commnets_count도 동일!
    likes_count = serializers.SerializerMethodField()

    # 여기서 정의된 user의 email이 위에 user값에 들어가게 된다
    def get_article_user(self, obj):
        return obj.article_user.username

    # 2. 위에서 좋아요 수 정의 해주고, 여기서 갯수 받아오는 함수 정의
    def get_likes_count(self, obj):
        return obj.likes.count()

    class Meta:
        model = Article
        # 3. likes_count : 좋아요 수 보여주는 필드 추가
        fields = ("article_user", "title", "content", "likes_count")
        
class ImageSerializer(serializers.ModelSerializer):
   class Meta:
        model = Image
        fields = ['input_image','output_image']

class ArticleSerializer(serializers.ModelSerializer): # main get
    img = ImageSerializer()
    likes_count = serializers.SerializerMethodField()
    def get_likes_count(self, obj):
        return obj.likes.count()
    class Meta:
        model = Article
        fields = ['id','img','article_user','likes','likes_count']

class ArticleDetailSerializer(serializers.ModelSerializer):
    img = ImageSerializer()
    class Meta:
        model = Article
        fields = '__all__'