from django.shortcuts import render
from rest_framework.permissions import IsAuthenticated
from .serializer import RegisterSerializer,LoginSerializer,ResetPasswordSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken


#View for Testing
class sayHello(APIView):
    def get(self,request):
        return Response({"message":"Hello, Buddy!!!"},status = status.HTTP_200_OK)
 
        
#Register into the app
class RegisterView(APIView):
    def post(self,request):
        data = request.data 
        serializer = RegisterSerializer(data = data)
        if serializer.is_valid():
            user = serializer.save()
            return Response(status=status.HTTP_201_CREATED)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)


#Login in to the app  
class LoginView(APIView):
    def post(self,request):
        data = request.data
        serializer = LoginSerializer(data = data)
        if serializer.is_valid():
            username = serializer.validated_data["username"]
            password = serializer.validated_data["password"]
            
            user = authenticate(username = username,password = password)
            if user is not None:
    
                refresh = RefreshToken.for_user(user)
                return Response({
                    "access_token":str(refresh.access_token),                                 
                    },status=status.HTTP_200_OK)
            return Response({
                "error":"Invalid Credentials."
            },status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)    


# profile            
class ProfileView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self,request):
        user = request.user
        return Response({
            "name":user.username,
            "email":user.email
            },status=status.HTTP_200_OK)
    
    
# Logout from application       
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]  
    
    def post(self,request):
        try:
            refresh_token = request.data['refresh_token']   
            token = RefreshToken(refresh_token)  
            token.blacklist() 
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        
        
#Change Password 
class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]     
    
    def post(sefl,request):
        serializer = ChangePasswordView(data = request.data)
        if serializer.is_valid():
            user = request.user
            if not user.check_password(serializer.validated_data['old_password']):
                return Response({
                    'old_password':'Wrong password'
                },status=status.HTTP_400_BAD_REQUEST)
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            return Response({
                'status':'Password updated successfully'
                
            },status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)
            