from rest_framework import generics
from .models import Product
from users.models import User
from .serializers import ProductSerializer, ProductDetailSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status


class ProductListView(generics.ListAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer


class ProductUserView(generics.ListAPIView):
    serializer_class = ProductSerializer

    def get_queryset(self):
        username = self.kwargs['username']
        return Product.objects.filter(username__username=username)


class ProductDetailView(generics.RetrieveAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductDetailSerializer
    lookup_field = 'pk'


class ProductCreateView(generics.CreateAPIView):
    permission_classes = [IsAuthenticated]

    serializer_class = ProductDetailSerializer

    def perform_create(self, serializer):
        username = self.kwargs['username']
        user = User.objects.get(username=username)
        serializer.save(username=user)


class ProductDeleteView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated]

    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    lookup_field = 'pk'

    def get_queryset(self):
        queryset = super().get_queryset()
        username = self.kwargs['username']
        return queryset.filter(username__username=username)


class ProductAddFavoriteView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, username, pk):
        product = Product.objects.get(pk=pk)

        if product.username.username == username:
            return Response({"message": "You cannot add your own product to favorites."})

        if request.user in product.favorites.all():
            return Response({"message": "The product is already in favorites."})

        product.is_favorite = True
        product.favorite_count += 1
        product.favorites.add(request.user)
        product.save()
        return Response({"message": "The product was added to favorites."})


class FavoriteProductListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ProductSerializer

    def get_queryset(self):
        username = self.kwargs['username']
        return Product.objects.filter(username__username=username, is_favorite=True)


class ProductRemoveFavoriteView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, username, pk):

        product = Product.objects.get(pk=pk)

        if product.username.username == username:
            return Response({"message": "You cannot remove your own product from favorites."},
                            status=status.HTTP_403_FORBIDDEN)

        if request.user not in product.favorites.all():
            return Response({"message": "The product is not in favorites."}, status=status.HTTP_404_NOT_FOUND)

        product.is_favorite = False
        product.favorite_count -= 1
        product.favorites.remove(request.user)
        product.save()
        return Response({"message": "The product removed from favorites."}, status=status.HTTP_200_OK)