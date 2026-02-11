from django.contrib.auth import authenticate
from .models import Account
from rest_framework.views import APIView
from rest_framework import status, generics
from .serializers import AccountSerializer, ChangePasswordSerializer
import re
from django.contrib.auth.hashers import make_password
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_bytes, smart_str, force_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.core.mail import send_mail
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token


def generate_unique_username(first_name, last_name):
    User = get_user_model()

    # Create base username variations
    username_variants = [
        f"{first_name}{last_name}",
        f"{first_name}.{last_name}",
        f"{first_name}_{last_name}",
        f"{first_name[0]}{last_name}",
    ]

    # Try each variant
    for username in username_variants:
        if not User.objects.filter(username=username).exists():
            return username
        
    # If all variants are taken, append numbers to the first variant
    base_username = username_variants[0]
    counter = 1

    while True:
        new_username = f"{base_username}{counter}"
        if not User.objects.filter(username=new_username).exists():
            return new_username
        counter += 1


class signup(APIView):
    def post(self, request, *args, **kwargs):
        serializer = AccountSerializer(data=request.data)
        if serializer.is_valid():
            first_name = request.data.get("first_name").lower().strip()
            last_name = request.data.get("last_name").lower().strip()

            if not first_name and not last_name:
                return Response({
                    'first_name': "This field is required", 
                    'last_name': "This field is required", 
                    })
            else:
                username = generate_unique_username(first_name=first_name, last_name=last_name)

                serializer.validated_data["password"] = make_password(serializer.validated_data.get("password"))

                account = serializer.save(
                    username=username,
                    first_name=first_name,
                    last_name=last_name
                )

                return Response({'status': "complete", "name": username})
        return Response(serializer.errors)


class loginView(APIView):
    def post(self, request, *args, **kwargs):
        password = request.data.get("password")
        user_id = request.data.get("user_id")

        if not password and not user_id:
            return Response({
                "user_id": "Please enter your User ID",
                "password": "Please enter password"
            })
        elif not password:
            return Response({"password": "Please enter password"})
        elif not user_id:
            return Response({"user_id": "Please enter user ID"})
        else:
            # Email regex
            email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
            
            # Phone number regex (supports international and local formats)
            phone_regex = r"^(?:\+\d{1,3})?\d{10,15}$"

            if re.match(email_regex, user_id):
                if Account.objects.filter(email=user_id.lower().strip()).count() == 0:
                    return Response({'email': 'No such email account'})
                else:
                    user = authenticate(email=user_id.lower(), password=password)

                    if not user:
                        return Response({'password': 'Password is incorrect'})
                    else:
                        return Response({'status': 'complete', "username": user.username})
            elif re.match(phone_regex, user_id):
                if Account.objects.filter(phone_number=user_id.lower().strip()).count() == 0:
                    return Response({'phone_number': 'No such phone number'})
                else:
                    user = authenticate(phone_number=user_id.lower(), password=password)
                    if not user:
                        return Response({'password': 'Password is incorrect'})
                    else:
                        return Response({'status': 'complete', "username": user.username})
            else:
                if Account.objects.filter(username=user_id.lower().strip()).count() == 0:
                    return Response({'username': 'No such username'})
                else:
                    user = authenticate(username=user_id.lower(), password=password)
                    if not user:
                        return Response({'password': 'Password is incorrect'})
                    else:
                        return Response({'status': 'complete', "username": user.username})
                    

class loginTokenView(APIView):
    def get(self, request, *args, **kwargs):
        User = get_user_model()

        username = request.GET.get("username").lower().strip()

        if User.objects.filter(username=username).exists():
            user_account = User.objects.get(username=username)
            token, _ = Token.objects.get_or_create(user=user_account)
            return Response({'token': token.key})
        else:
            return Response({"error": "No such user found"})


class logoutView(APIView):
    def post(self, request, *args, **kwargs):
        try:
            request.user.auth_token.delete()
            return Response({'status': 'logged out'})
        except:
            return Response({'status': 'user not logged in'})


class updateUserDetails(APIView):
    def put(self, request, *args, **kwargs):
        account = Account.objects.get(id=request.user.id)

        if not request.data.get('email') and not request.data.get('username'):
            return Response({'status': "nothing to update"})

        email = request.data.get('email')

        username = request.data.get('username')

        profile_image = request.FILES.get("profile_image")

        error_responses = []

        if email:
            if Account.objects.filter(email=email.lower().strip()).count() != 0 and Account.objects.get(email=email.lower().strip()).email != account.email:
                error_responses.append({'email': 'Email account in use'})

        if username:
            if Account.objects.filter(username=username.lower().strip()).count() != 0 and Account.objects.get(username=username.lower().strip()).username != account.username:
                error_responses.append({'username': 'Username in use'})
            
        if profile_image:
            account.profile_image.delete()
            account.profile_image = profile_image

        if len(error_responses) != 0:
            return Response({'errors': error_responses})
        else:
            account.email = email
            account.username = username
            account.save()
            return Response({'status': 'Updated'})


class deleteAccount(APIView):
    def delete(self, request):
        account = Account.objects.get(id=request.user.id)

        account.profile_image.delete()

        account.delete()

        return Response({'status': 'deleted'})
    

class RequestPasswordResetEmail(APIView):
    def post(self, request):
        email = request.data.get("email").lower().strip()

        User = get_user_model()

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))

            token = PasswordResetTokenGenerator().make_token(user)

            send_mail(
                "Reset email",
                f"http://127.0.0.1:8000/account/password-reset/{uidb64}/{token}/",
                "",
                [email],
                fail_silently=False,
            )

            return Response({'status': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'No email associated with any account'})
        

class PasswordTokenCheckAPI(APIView):
    def get(self, request, uidb64, token):
        try:
            User = get_user_model()
            
            id = urlsafe_base64_decode(uidb64)

            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token not valid'})

            return Response({'status': 'valid', "uid": uidb64, "token": token})
        
        except:
            return Response({'error': 'UID not valid'})
        
    
    def put(self, request, uidb64, token):
        try:
            User = get_user_model()

            password = request.data.get("password")

            id = force_str(urlsafe_base64_decode(uidb64))

            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error': 'Token no longer valid'})
                
            user.set_password(password)

            user.save()

            return Response({'status': "Password has successfully been reset"})
        
        except:
            return Response({'error': 'Token not valid'})


class changePasswordView(generics.UpdateAPIView):
    serializer_class = ChangePasswordSerializer

    model = Account

    permission_classes = (IsAuthenticated,)

    def get_object(self):
        obj = self.request.user
        return obj

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()

        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"error": "Wrong password"}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()

            return Response({'status': 'Password successfully reset'})

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)