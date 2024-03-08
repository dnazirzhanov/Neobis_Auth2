from django.urls import path
from products.views import ProductListView, ProductUserView, ProductDetailView, ProductCreateView, ProductDeleteView, ProductAddFavoriteView, FavoriteProductListView, ProductRemoveFavoriteView

urlpatterns = [
    path('products/', ProductListView.as_view(), name='product-list'),
    path('products/myproduct/<str:username>/', ProductUserView.as_view(), name='product-user'),
    path('products/<int:pk>/', ProductDetailView.as_view(), name='product-detail'),
    path('products/myproduct/<str:username>/create/', ProductCreateView.as_view(), name='product-create'),
    path('products/myproduct/<str:username>/<int:pk>/delete/', ProductDeleteView.as_view(), name='product-delete'),
    path('products/favorite/<str:username>/<int:pk>/', ProductAddFavoriteView.as_view(), name='product-favorite'),
    path('products/favorites/<str:username>/', FavoriteProductListView.as_view(), name='favorite-product-list'),
    path('products/favorite/<str:username>/<int:pk>/remove/', ProductRemoveFavoriteView.as_view(), name='product-remove-favorite'),
]