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
