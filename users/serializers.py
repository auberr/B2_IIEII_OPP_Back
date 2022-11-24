from rest_framework import serializers
from users.models import User
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from oilpainting.serializers import ArticleListSerializer


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"

class UserCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        exclude = ('followings',)

    def create(self, validated_data):   
        user = super().create(validated_data)
        password = user.password
        user.set_password(password)
        user.save()
        return user

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['username'] = user.username

        return token



class UserprofileSerializer(serializers.ModelSerializer):

    # 내가 작성한 게시글 보기
    article_set = ArticleListSerializer(many=True)

    # 내가 좋아요 한 게시글 보기
    liked_article = ArticleListSerializer(many=True)

    class Meta:
        model = User
        fields = ("username", 'profile_img', 'article_set', 'liked_article')


class UserprofileImageCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("username", 'profile_img')
        

# 팔로잉 하는 유저 목록을 간단히 가져오기위한 시리얼라이저
class FollowingBaseSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("id", "username", "profile_img",)


# 팔로우와 관련된 정보들을 담는 시리얼라이저
class FollowSerializer(serializers.ModelSerializer):
    # 팔로잉 하는 유저 정보
    followinglist = FollowingBaseSerializer(many=True)
    
    # 팔로잉 수
    following = serializers.SerializerMethodField()
    def get_following(self, obj):
        return obj.followings.count()
    
    # 팔로워 수
    follower = serializers.SerializerMethodField()
    def get_follower(self, obj):
        return len(obj.followers.all())
    
    class Meta:
        model = User
        fields = ("id", "username", "follower", "following", "followinglist", )