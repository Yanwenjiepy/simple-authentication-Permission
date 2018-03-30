from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_post_parameters
from django.contrib.auth import login, logout
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist

from my_auth.serializers import (
    TokenSerializer, RegisterSerializer, VerifyEmailSerializer,
    LoginSerializer, UserSerializer, PasswordResetSerializer,
    PasswordResetConfirmSerializer, PasswordChangeSerializer
)
from my_auth.utils import create_token

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.generics import CreateAPIView, GenericAPIView, RetrieveUpdateAPIView
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response

from allauth.account.app_settings import app_settings
from allauth.account.utils import complete_signup
from allauth.account.views import ConfirmEmailView

# Create your views here.

TokenModel = Token

# 标注敏感POST参数

# 在注册时，账号的密码属于敏感的POST参数,需要'sensitive_post_parameters'标记
sensitive_post_parameters_method_register = method_decorator(
    sensitive_post_parameters('password1', 'password2')
)

# 在登录时输入的密码，重置账号的密码时需要输入的旧密码与新密码都属于敏感的POST参数
sensitive_post_parameters_method_reset = method_decorator(
    sensitive_post_parameters(
        'password', 'old_password', 'new_password1', 'new_password2'
    )
)


class RegisterView(CreateAPIView):
    """
    验证用户输入的数据，创建新用户
    """
    serializer_class = RegisterSerializer
    permission_classes = (AllowAny,)
    token_model = TokenModel

    @sensitive_post_parameters_method_register
    def dispatch(self, *args, **kwargs):
        return super(RegisterView, self).dispatch(*args, **kwargs)

    def response_data(self, user):

        if app_settings.EMAIL_VERIFICATION == \
                app_settings.EmailVerificationMethod.MANDATORY:
            return {"msg": "Verification email sent."}

        return TokenSerializer(user.auth_token).data

    def create(self, request, *args, **kwargs):

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)

        return Response(
            data=self.response_data(user=user),
            status=status.HTTP_201_CREATED,
            headers=headers
        )

    def perform_create(self, serializer):

        user = serializer.save(self.request)
        create_token(self.token_model, user, serializer)
        complete_signup(self.request._request, user, app_settings.EMAIL_VERIFICATION, None)

        return user


class VerifyEmailView(APIView, ConfirmEmailView):
    """
    邮箱的验证为自动验证

    在用户完成注册操作后，服务端将会给用户发送一封激活邮件，
    该激活邮件中包含一个'key'，
    用户点击激活链接发起激活邮箱的请求中包含该'key'，
    依据该'key'找到对应的尚未激活的邮箱，进行激活

    """
    permission_classes = (AllowAny,)

    def get_serializer(self, *args, **kwargs):
        return VerifyEmailSerializer(*args, **kwargs)

    def post(self, request, *args, **kwargs):

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.kwargs['key'] = serializer.validated_data['key']
        confirmation = self.get_object()
        confirmation.confirm(self.request)

        return Response(data={"msg": "Verify success."}, status=status.HTTP_200_OK)


class LoginView(GenericAPIView):
    """
    对用户传入的数据进行检查，
    如果该用户通过了身份认证并且传入的数据有效，
    则返回Token,
    并且调用Django的'login'方法，
    'login'方法会把 User ID 注册到Django的 session framework 中，
    为该用户与服务端建立 session

    """

    serializer_class = LoginSerializer
    permission_classes = (AllowAny,)
    token_model = TokenModel

    @sensitive_post_parameters_method_reset
    def dispatch(self, *args, **kwargs):
        return super(LoginView, self).dispatch(*args, **kwargs)

    # 会话登录，调用Django的'login'方法，用户每次请求不需要重新验证身份
    def session_login(self):
        login(self.request, self.user)

    def login(self):
        self.user = self.serializer.validated_data['user']
        self.token = create_token(self.token_model, self.user, self.serializer)
        if getattr(settings, 'SESSION_LOGIN', True):
            self.session_login()

    @staticmethod
    def get_response_serializer():
        response_serializer = TokenSerializer
        return response_serializer

    def get_response(self):
        serializer_class = self.get_response_serializer()
        serializer = serializer_class(
            instance=self.token, context={"request": self.request}
        )
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        self.request = request
        self.serializer = self.get_serializer(
            data=request.data, context={"request": request}
        )
        self.serializer.is_valid(raise_exception=True)
        self.login()
        return self.get_response()


class LogoutView(APIView):
    """
    删除 User object 的 Token object，
    调用Django的'logout'方法，退出登录
    """

    permission_classes = (AllowAny,)

    def logout(self, request):
        try:
            request.user.auth_token.delete()
        except (AttributeError, ObjectDoesNotExist):
            pass
        logout(request)
        return Response(
            data={"msg": "Logout successfully"},
            status=status.HTTP_200_OK
        )

    def post(self, request, *arg, **kwargs):
        return self.logout(request)


class UserDetailView(RetrieveUpdateAPIView):
    """
    浏览和更新用户个人信息(即浏览和更新UserModel的字段)

    只读字段：pk, email
    可更新字段：username, first_name, last_name
    可浏览字段： pk, email, username, first_name, last_name

    请求方法：GET, PUT, PATCH
    """

    serializer_class = UserSerializer
    permission_classes = (IsAuthenticated,)

    def get_object(self):
        return self.request.user


class PasswordResetView(GenericAPIView):
    """
    用户请求密码重置邮件，验证email后，
    调用django/contrib/auth/forms.py中PasswordResetForm的.save()方法，
    完成密码重置邮件的发送
    """

    serializer_class = PasswordResetSerializer
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            data={"msg": "Password reset email has been sent."},
            status=status.HTTP_200_OK
        )


class PasswordResetConfirmView(GenericAPIView):

    serializer_class = PasswordResetConfirmSerializer
    permission_classes = (AllowAny,)

    @sensitive_post_parameters_method_reset
    def dispatch(self, *args, **kwargs):
        return super(PasswordResetConfirmView, self).dispatch(*args, **kwargs)

    def post(self, request, *args, **kwargs):

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({"msg": "Password reset successfully."})


class PasswordChangeView(GenericAPIView):
    
    serializer_class = PasswordChangeSerializer
    permission_classes = (AllowAny,)

    @sensitive_post_parameters_method_reset
    def dispatch(self, *args, **kwargs):
        return super(PasswordChangeView, self).dispatch(*args, **kwargs)

    def post(self, request, *args, **kwargs):

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({"msg": "Password reset successfully."})
























