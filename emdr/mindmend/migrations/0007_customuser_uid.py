# Generated by Django 5.0.6 on 2024-07-02 18:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mindmend', '0006_rename_after_therapy_scores_after_therapy_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='uid',
            field=models.CharField(blank=True, default='', max_length=500, null=True),
        ),
    ]