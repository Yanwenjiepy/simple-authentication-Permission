# Author: BigRabbit
#  下午9:12
from django.conf.urls import url
from my_auth.views import (
    RegisterView, VerifyEmailView, LoginView, LogoutView, UserDetailView,
    PasswordResetView, PasswordResetConfirmView, PasswordChangeView
)
from django.views.generic import TemplateView

urlpatterns = [
    url(r'^register/$', RegisterView.as_view(), name='register'),
    url(r'^register/verify-email/$', VerifyEmailView.as_view(), name='verify_email'),
    url(r'^account-confirm-email/(?P<key>[-:\w]+)/$', TemplateView.as_view(),
        name='account_confirm_email'),
    url(r'^login/$', LoginView.as_view(), name='login'),
    url(r'^logout/$', LogoutView.as_view(), name='logout'),
    url(r'^user/$', UserDetailView.as_view(), name='user_details'),
    url(r'^password/reset/$', PasswordResetView.as_view(), name='password_reset'),
    url(r'^password/reset/confirm/$', PasswordResetConfirmView.as_view(),
        name='password_reset_confirm'),
    url(r'^password/change$', PasswordChangeView.as_view(), name='password_change'),

]
