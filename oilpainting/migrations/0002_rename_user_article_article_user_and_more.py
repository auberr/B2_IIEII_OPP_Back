# Generated by Django 4.1.3 on 2022-11-24 01:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("oilpainting", "0001_initial"),
    ]

    operations = [
        migrations.RenameField(
            model_name="article",
            old_name="user",
            new_name="article_user",
        ),
        migrations.RenameField(
            model_name="image",
            old_name="user",
            new_name="image_user",
        ),
        migrations.RemoveField(
            model_name="image",
            name="input_img",
        ),
        migrations.RemoveField(
            model_name="image",
            name="output_img",
        ),
        migrations.AddField(
            model_name="image",
            name="input_image",
            field=models.ImageField(null=True, upload_to=""),
        ),
        migrations.AddField(
            model_name="image",
            name="output_image",
            field=models.ImageField(null=True, upload_to=""),
        ),
    ]