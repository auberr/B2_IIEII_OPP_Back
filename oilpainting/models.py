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
    
class Comment(models.Model):
    article_user = models.ForeignKey(User,on_delete=models.CASCADE)
    article = models.ForeignKey(Article,on_delete=models.CASCADE)
    content = models.TextField()
    create_at = models.DateTimeField(auto_now_add=True)
    update_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return str(self.content)