from rest_framework import serializers
from django.contrib.auth.models import User


class RegisterSerializer(serializers.ModelSerializer):
    password1 = serializers.CharField(write_only = True)
    class Meta:
        model = User 
        fields = ["username","email","password","password1"]
        
    def validate(self, attrs):
        if attrs["password"] != attrs["password1"]:
            raise serializers.ValidationError("Passwords must match.")
        return attrs
    
    def create(self, validated_data):
        user = User.objects.create_user(
            
            username= validated_data["username"],
            email   =  validated_data["email"],
            password= validated_data['password']
            
        )
        return user

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only = True)
    

class ResetPasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required = True ,write_only = True)
    new_password = serializers.CharField(required = True,write_only = True)
    