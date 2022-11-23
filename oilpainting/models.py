from django.db import models
from users.models import User
# Create your models here.


class Image(models.Model):
    image_user = models.ForeignKey(User, on_delete=models.CASCADE)
    input_image = models.ImageField(null=True)
    output_image = models.ImageField(null=True)