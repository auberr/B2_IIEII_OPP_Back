from rest_framework import serializers
from oilpainting.models import Image


class InputImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Image
        fileds = ("input_image",)