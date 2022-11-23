from django.db import models
from users.models import User
# Create your models here.


class Image(models.Model):
    image_user = models.ForeignKey(User, on_delete=models.CASCADE)
    input_image = models.ImageField(null=True)
    output_image = models.ImageField(null=True)
    

class Article(models.Model):
    article_user = models.ForeignKey(User, on_delete=models.CASCADE)
    img = models.ForeignKey(Image, on_delete=models.CASCADE)
    title = models.CharField(max_length=50)
    content = models.TextField()
    likes = models.ManyToManyField(User,related_name='liked_article')