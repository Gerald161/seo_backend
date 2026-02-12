from .models import Product, Added_Image
from rest_framework.views import APIView
from rest_framework.response import Response

class allProducts(APIView):
    def get(self, request, *args, **kwargs):
        products = Product.objects.all()[:10]

        all_products = []

        for product in products:
            added_image = Added_Image.objects.filter(product=product).first()

            all_products.append({
                "name": product.name,
                "category": product.category,
                "slug": product.slug,
                "price": product.price,
                "discount": product.discount,
                "ratings": product.ratings,
                "reviews": product.reviews,
                "description": product.description,
                "image": added_image.image.url,
            })

        return Response({
            'all_products': all_products, 
        })


class productSearch(APIView):
    def get(self, request, *args, **kwargs):
        slug = self.kwargs['slug']

        slug = slug.replace("-", " ")

        products = Product.objects.filter(name__istartswith=slug)

        all_products = []

        for product in products:
            added_image = Added_Image.objects.filter(product=product).first()

            all_products.append({
                "name": product.name,
                "category": product.category,
                "slug": product.slug,
                "price": product.price,
                "discount": product.discount,
                "ratings": product.ratings,
                "reviews": product.reviews,
                "description": product.description,
                "image": added_image.image.url,
            })

        return Response({
            'all_products': all_products, 
        })
    

class product(APIView):
    def get(self, request, *args, **kwargs):
        slug = self.kwargs['slug']

        product = Product.objects.filter(slug__iexact=slug).first()

        if product:
            added_images = Added_Image.objects.filter(product=product)

            all_added_images = []

            for added_image in added_images:
                all_added_images.append(added_image.image.url)

            return Response({
                'product': {
                    "name": product.name,
                    "category": product.category,
                    "slug": product.slug,
                    "price": product.price,
                    "discount": product.discount,
                    "ratings": product.ratings,
                    "reviews": product.reviews,
                    "description": product.description,
                    "images": all_added_images,
                }, 
                "status": "ok"
            })
        else:
            return Response({
                'status': "none", 
            })
        