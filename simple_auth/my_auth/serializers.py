# Author: BigRabbit
#  下午3:10
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from django.contrib.auth.tokens import default_token_generator
from django.conf import settings
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_text

from rest_framework.authtoken.models import Token
from rest_framework import serializers, exceptions

from allauth.account.app_settings import app_settings
from allauth.utils import get_username_max_length, email_address_exists
from allauth.account.adapter import get_adapter
from allauth.account.utils import setup_user_email


UserModel = get_user_model()
TokenModel = Token


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = UserModel
        fields = ('pk', 'username', 'email', 'first_name', 'last_name')
        read_only_fields = ('email',)


class TokenSerializer(serializers.ModelSerializer):

    class Meta:
        model = TokenModel
        fields = ('key',)


class RegisterSerializer(serializers.Serializer):
    """
    验证用户输入的数据，创建新用户
    """

    username = serializers.CharField(
        max_length=get_username_max_length(),
        min_length=app_settings.USERNAME_MIN_LENGTH,
        required=app_settings.USERNAME_REQUIRED
    )
    email = serializers.EmailField(required=app_settings.EMAIL_REQUIRED)
    password1 = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)
    cleaned_data = {}

    def validate_username(self, username):
        username = get_adapter().clean_username(username)
        return username

    def validate_email(self, email):
        email = get_adapter().clean_email(email)

        if app_settings.UNIQUE_EMAIL:
            if email and email_address_exists(email):
                msg = {"email_error": "This email address has been registered!"}
                raise serializers.ValidationError(msg)

        return email

    def validate_password1(self, password):
        password = get_adapter().clean_password(password)
        return password

    def validate_password_equal(self, data):

        if data['password1'] != data['password2']:
            msg = {"password_error": "The password entered twice is inconsistent!"}
            raise serializers.ValidationError(msg)

        return data

    def get_cleaned_data(self):
        result = {
            'username': self.validated_data.get('username', ''),
            'email': self.validated_data.get('email', ''),
            'password1': self.validated_data.get('password1', '')
        }
        return result

    def save(self, request):

        adapter = get_adapter()
        user = adapter.new_user(request)
        self.cleaned_data = self.get_cleaned_data()
        adapter.save_user(request, user, self)
        setup_user_email(request, user, [])

        return user


class VerifyEmailSerializer(serializers.Serializer):

        key = serializers.CharField()


class LoginSerializer(serializers.Serializer):

    username = serializers.CharField(required=True, allow_blank=False)
    email = serializers.EmailField(required=True, allow_blank=False)
    password = serializers.CharField(style={'input_type': 'password'})

    def _validate_username(self, username, password):
        """
        通过username与password进行身份认证
        :param username: 账号名称
        :param password: 账号密码
        :return: User object
        """

        if username and password:
            user = authenticate(username=username, password=password)
        else:
            msg = {"identity_error": "Must have 'username' and 'password'."}
            raise exceptions.ValidationError(msg)
        return user

    def _validate_email(self, email, password):
        """
        通过email与password进行身份认证
        :param email: 账号邮箱
        :param password: 账号密码
        :return: User object
        """

        if email and password:
            user = authenticate(email=email, password=password)
        else:
            msg = {"identity_error": "Must have 'email' and 'password'."}
            raise exceptions.ValidationError(msg)
        return user

    def _validate_email_username(self, username, email, password):
        """
        通过以上两种认证方式中的任意一种进行身份认证
        :param username: 账号名称
        :param email: 账号邮箱
        :param password: 账号密码
        :return: User object
        """

        if username and password:
            user = authenticate(username=username, password=password)
        elif email and password:
            user = authenticate(email=email, password=password)
        else:
            msg = {"identity_error": "Must have 'username' and 'password' or 'email' and 'password'."}
            raise exceptions.ValidationError(msg)
        return user

    def validate(self, attrs):
        username = attrs.get('username')
        email = attrs.get('email')
        password = attrs.get('password')

        # 通过username与password进行身份认证
        if app_settings.AUTHENTICATION_METHOD == \
                app_settings.AuthenticationMethod.USERNAME:
            user = self._validate_username(username=username, password=password)

        # 通过email与password进行身份认证
        elif app_settings.AUTHENTICATION_METHOD == \
                app_settings.AuthenticationMethod.EMAIL:
            user = self._validate_email(email=email, password=password)

        # 通过以上两种认证方式中的任意一种进行身份认证
        else:
            user = self._validate_email_username(username=username, email=email, password=password)

        # 判断用户是否已经激活
        if user:
            if not user.is_active:
                msg = {"account_error": "This account is not available."}
                raise exceptions.ValidationError(msg)

        else:
            msg = {"identity_error": "This identity information cannot be logged in."}
            raise exceptions.ValidationError(msg)

        # 判断邮箱是否已经验证
        if app_settings.EMAIL_VERIFICATION == app_settings.EmailVerificationMethod.MANDATORY:
            email_address = user.emailaddress_set.get(email=user.email)
            if not email_address.verified:
                msg = {"email_error": "This email address is not verified."}
                raise serializers.ValidationError(msg)
        attrs['user'] = user
        return attrs


class PasswordResetSerializer(serializers.Serializer):
    """
    邮件重置密码
    用户请求密码重置邮件，验证数据后发送重置邮件
    """

    email = serializers.EmailField()
    password_reset_form_class = PasswordResetForm

    def set_email_options(self):
        """
        密码重置邮件的配置(可选)
        如果不配置，则使用 PasswordResetForm 的默认配置,
        具体配置请参阅django/contrib/auth/forms.py中的PasswordResetForm的.save()方法
        """
        options = {}
        return options

    def validate_email(self, value):
        """
        创建密码重置的form
        """
        self.reset_form = self.password_reset_form_class(data=self.initial_data)
        if not self.reset_form.is_valid():
            raise serializers.ValidationError(self.reset_form.errors)

        return value

    def save(self):
        """
        配置email,发送密码重置邮件
        """
        request = self.context.get('request')
        options = {
            'use_https': request.is_secure(),
            'from_email': getattr(settings, 'DEFAULT_EMAIL_FROM'),
            'request': request
        }
        options.update(self.set_email_options())
        self.reset_form.save(**options)


class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    邮件重置密码
    验证用户信息，保存新密码
    """
    new_password1 = serializers.CharField(max_length=128)
    new_password2 = serializers.CharField(max_length=128)
    uid = serializers.CharField()
    token = serializers.CharField()

    set_password_form_class = SetPasswordForm
    _errors = {}

    def validate(self, attrs):

        try:
            uid = force_text(urlsafe_base64_decode(attrs['uid']))
            self.user = UserModel._default_manager.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserModel.DoesNotExist):
            raise exceptions.ValidationError({"value_error": "Uid is invalid"})

        self.set_password_form = SetPasswordForm(user=self.user, data=attrs)

        if not self.set_password_form.is_valid():
            raise serializers.ValidationError(self.set_password_form.errors)

        if not default_token_generator.check_token(self.user, attrs['token']):
            raise exceptions.ValidationError({"value_error": "Token is invalid"})

        return attrs

    def save(self):
        return self.set_password_form.save()


class PasswordChangeSerializer(serializers.Serializer):
    """
    页面重置密码
    验证旧密码，确定身份合法性，保存新密码
    """

    old_password = serializers.CharField(max_length=128)
    new_password1 = serializers.CharField(max_length=128)
    new_password2 = serializers.CharField(max_length=128)

    set_password_form_class = SetPasswordForm

    def __init__(self, *args, **kwargs):
        self.logout_on_password_change = getattr(settings, 'LOGOUT_ON_PASSWORD_CHANGE', False)
        super(PasswordChangeSerializer, self).__init__(*args, **kwargs)

        self.fields.pop('old_password')
        self.request = self.context.get('request')
        self.user = getattr(self.request, 'user', None)

    def validate_old_password(self, value):
        """
        验证旧密码，确定用户身份合法性
        """
        if not self.user.check_possword(value):
            raise serializers.ValidationError(
                {"password_error": "Your old password was entered incorrectly"}
            )
        return value

    def validate(self, attrs):
        self.set_password_form = self.set_password_form_class(user=self.user, data=attrs)

        if not self.set_password_form.is_valid():
            raise serializers.ValidationError(self.set_password_form.errors)

        return attrs

    def save(self):
        self.set_password_form.save()
        # 修改密码后是否需要用户重新登录
        # 如果需要则设为'True',不需要则设为'False'
        if not self.logout_on_password_change:
            # 更新会话
            from django.contrib.auth import update_session_auth_hash
            update_session_auth_hash(self.request, self.user)

















