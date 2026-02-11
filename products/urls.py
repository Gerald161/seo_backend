from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
   path('all-products', views.allProducts.as_view()),
   path('search/<slug:slug>', views.productSearch.as_view()),
   path('<slug:slug>', views.product.as_view()),
]