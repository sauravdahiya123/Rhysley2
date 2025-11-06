from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    
    path('signature_satus/', views.signature_status_get, name='signature_satus'),
    path('document_list/', views.document_list, name='document_list'),
    path('comming_soon_get/', views.comming_soon_get, name='comming_soon_get'),
    path('upload/', views.upload_document, name='upload_document'),
    path('document/<int:pk>/', views.document_detail, name='document_detail'),
    path('documents/<int:pk>/delete/', views.delete_document, name='delete_document'),  # ✅ Add this
    path('send_link/<int:pk>/', views.send_signing_link, name='send_signing_link'),
    path('send_signing_link_bulk/<int:pk>/', views.send_signing_link_bulk, name='send_signing_link_bulk'),
    path('open_signing_link/<int:pk>/', views.open_signing_link, name='open_signing_link'),
    path('sign/<str:token>/<str:encoded_email>', views.sign_document, name='sign_document'),
    path('apply_signatures/', views.apply_signatures, name='apply_signatures'),
    path('cancel-signing/<str:token>/', views.cancel_signing, name='cancel_signing'),
    path('upload_signature/', views.upload_signature, name='upload_signature'),
    path('delete-signature/', views.delete_signature, name='delete_signature'),
    path('document/assign/<str:token>/', views.assign_document, name='assign_document'),
    path('documents/<int:pk>/download/', views.download_document_files, name='download_document_files'),
    path('verify-otp/<int:user_id>/', views.verify_otp, name='verify_otp'),
    path('marketing/', views.marketing_view, name='marketing'),
    path("resend-otp/", views.resend_otp, name="resend_otp"),
    path('login/', views.user_login, name='user_login'),
    path('logout/', views.user_logout, name='user_logout'),
    path('signup/', views.user_signup, name='user_signup'),
    path('desgin/', views.desgin, name='desgin'),
    path('privacy_policy/', views.privacy_policy, name='privacy_policy'),
    path('terms_of_service/', views.terms_of_service, name='terms_of_service'),
    path('cookie_settings/', views.cookie_settings, name='cookie_settings'),
    path('thank_you/', views.thankyou, name='thank_you'),
    path('contact_us/', views.contact_us, name='contact_us'),
    path('contact/', views.contact_view, name='contact'),
    path('buy_plain/', views.buy_plain, name='buy_plain'),


]
