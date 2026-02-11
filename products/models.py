from django.db import models
from django.conf import settings

# Create your models here.
class Product(models.Model):
    name = models.CharField(max_length=300)
    category = models.CharField(max_length=300)
    price = models.CharField(max_length=300)
    discount = models.CharField(max_length=300, default="0")
    ratings = models.CharField(max_length=300)
    reviews = models.CharField(max_length=300)
    description = models.CharField(max_length=300)
    slug = models.CharField(max_length=300)
    time_added = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return str(self.name)
    

class Added_Image(models.Model):
    image = models.ImageField()
    product = models.ForeignKey(Product, on_delete=models.CASCADE, null=True)
    
    def __str__(self):
        return self.image.name
    
    def delete(self, *args, **kwargs):
        self.image.delete()
        
        super().delete(*args, **kwargs)