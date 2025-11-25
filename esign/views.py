from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Document, Signature, SignaturePlacement,Subscription  , SigningToken,SignatureBox,SignaturePage,DocumentSignFlow,Profile,MarketingSource
from .forms import DocumentUploadForm, SignatureUploadForm,MarketingForm,ContactInquiryForm
from django.utils import timezone
from django.core.mail import send_mail
from django.urls import reverse
import secrets
from datetime import timedelta
from django.http import JsonResponse
import json
import base64
from django.core.files.base import ContentFile
from io import BytesIO
import fitz
from django.contrib import messages
from django.core.mail import EmailMessage
from django.views.decorators.csrf import csrf_exempt
from django.template.loader import render_to_string
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from django.contrib.auth import get_user_model
from django.utils.crypto import get_random_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str
from django.conf import settings
import zipfile
from django.core.paginator import Paginator
from django.db.models import Q ,Count
import random
from django.contrib import auth
from esign.utils.email_utils import send_email_safe

def check(request):
    return redirect('')

def handle_not_found(request, exception):
    # Option 1: redirect to home page
    return redirect('/')

def desgin(request):
    return render(request, 'esign/token_invalid.html')

def privacy_policy(request):
    return render(request, 'esign/privacy_policy.html') 

def terms_of_service(request):
    return render(request, 'esign/terms_of_service.html') 
       
def cookie_settings(request):
    return render(request, 'esign/cookie_settings.html')    

def signup_steps(request):
    return render(request, 'esign/signup_steps.html')  
  
import random, datetime

def forgot_password(request):
    if request.method == "GET":
        email_param = request.GET.get('email')

        if email_param:
            email = email_param  # real email from URL

            # ✅ Send OTP automatically
            try:
                user = User.objects.get(email=email)
                otp = random.randint(100000, 999999)
                request.session['reset_email'] = email
                request.session['reset_otp'] = otp
                request.session['otp_expires'] = str(timezone.now() + datetime.timedelta(minutes=10))

                # Send OTP email
              
                name = user.first_name+" "+user.last_name
                html_content = render_to_string('mails/otp_email.html', {
                    
                    'EXPIRY_MINUTES': "10",
                    "name":name,
                    'otp': otp,  # if you want to include OTP
                    })

           
                display_name = "Eazeesign Via Eazeesign"

                email_sent = send_email_safe(
                    request,
                    subject="Verify your identity to log in to Eazeesign",
                    body=html_content,
                    recipient_list=[email],
                    from_email=f"{display_name} <{settings.DEFAULT_FROM_EMAIL}>"
                )
                if not email_sent:
                    return redirect(request.path)  
            


            

                if request.headers.get('x-requested-with') == 'XMLHttpRequest':
                    return JsonResponse({'success': True, 'message': 'OTP resent successfully!'})

                messages.success(request, "OTP sent successfully! Please check your email.")
                return render(request, "esign/forgot_password.html", {"masked_email": email_param})
            
                # messages.success(request, f"OTP sent successfully! Please check your email. {otp} ")
                # return redirect('forgot_password')
            except User.DoesNotExist:
                messages.error(request, "No account found with this email.")

        return render(request, "esign/forgot_password.html", {"masked_email": email_param})

    elif request.method == "POST":
        email = request.POST.get("email")
        entered_otp = request.POST.get("otp")

        # Check OTP for this email
        session_email = request.session.get('reset_email')
        session_otp = request.session.get('reset_otp')
        otp_expires = request.session.get('otp_expires')
        if otp_expires is None:
            # OTP expiry time set hi nahi hua
            # handle as expired
            messages.error(request, "OTP expired. Please request a new one.")
            return render(request, "esign/forgot_password.html", {"email": email,"masked_email":email})

        # expiry_dt = datetime.fromisoformat(otp_expires)
        # if timezone.now() > otp_expires:
        if timezone.now() > timezone.datetime.fromisoformat(otp_expires):
            messages.error(request, "OTP expired. Please request a new one.")
        elif str(session_otp) != str(entered_otp):
            messages.error(request, "Incorrect OTP. Please try again.")
        else:
            messages.success(request, "OTP verified successfully! You can reset your password now.")
            return redirect('change_password')  # redirect to password reset page

        return render(request, "esign/forgot_password.html", {"email": email,"masked_email":email})









def change_password(request):
    session_email = request.session.get('reset_email')

    if not session_email:
        messages.warning(request, "No email found in session. Please request OTP again.")
        return redirect('forgot_password')

    if request.method == "POST":
        new_password = request.POST.get('new_password')

        try:
            user = User.objects.get(email=session_email)

            # Check if new password is same as old password
            if check_password(new_password, user.password):
                messages.error(request, "New password cannot be the same as the old password.")
            else:
                # Update password (hashed)
                user.password = make_password(new_password)
                user.save()

                # Clear session
              
                # Automatically log in the user
                authenticated_user = authenticate(username=user.username, password=new_password)
                if authenticated_user is not None:
                    login(request, authenticated_user)
                    display_name = "Eazeesign Via Eazeesign"
                    html_content = render_to_string('mails/password_changed_successfully.html', {
                        "recipient_name":user.first_name+" "+user.last_name,
                        "email":user.email,
                        'document_link': "https://app.eazeesign.com/",  # if you want to include OTP
                        })
                    email_sent = send_email_safe(
                    request,
                    subject="Your Eazeesign Password has been changed",
                    body=html_content,
                    recipient_list=[user.email],
                    from_email=f"{display_name} <{settings.DEFAULT_FROM_EMAIL}>"
                    )
                    if not email_sent:
                        return redirect(request.path)  
                    request.session.pop('reset_email', None)
                    request.session.pop('reset_otp', None)
                    request.session.pop('otp_expires', None)


                    messages.success(request, "Password updated successfully! You are now logged in.")

              

                    return redirect('index')  # Redirect to dashboard

                else:
                    messages.success(request, "Password updated! Please log in.")
                    return redirect('user_login')

        except User.DoesNotExist:
            messages.error(request, "User not found in database.")

    return render(request, 'esign/change_password.html', {'email': session_email})
def otp_email(request):
    return render(request, 'esign/otp_email.html')    

def password_email(request):
    return render(request, 'esign/password_email.html')    


@login_required
def generate_pdf_with_boxes(document):
    reader = PdfReader(document.file.path)
    writer = PdfWriter()

    # Get all signature boxes for this document
    boxes = SignatureBox.objects.filter(document=document)

    for i, page in enumerate(reader.pages, start=1):
        packet = BytesIO()
        c = canvas.Canvas(packet, pagesize=letter)

        for box in boxes.filter(page=i):
            # Draw placeholder rectangle
            c.setStrokeColorRGB(0,0,0)
            c.setLineWidth(1)
            c.rect(box.x, box.y, box.width, box.height)
            c.drawString(box.x+5, box.y+box.height/2, box.type.upper())

        c.save()
        packet.seek(0)
        overlay_pdf = PdfReader(packet)
        page.merge_page(overlay_pdf.pages[0])
        writer.add_page(page)

    output_path = f"media/temp/{document.pk}_with_boxes.pdf"
    with open(output_path, "wb") as f:
        writer.write(f)

    return output_path


def resend_otp(request):
    if request.method == "POST":
        email = request.POST.get("email")

        if not email:
            return JsonResponse({"success": False, "message": "Email is required."})

        try:

            profile = User.objects.get(email=email)
            otp = random.randint(100000, 999999)
            request.session["email_otp"] = otp


            # send_mail(
            #     subject="Your new OTP",
            #     message=f"Your OTP is {otp}",
            #     from_email=settings.DEFAULT_FROM_EMAIL,
            #     recipient_list=[email],
            #     fail_silently=False,
            # )
            # name = email.split('@')[0]

            # html_content = render_to_string('mails/resend_otp.html', {
                
            #     'EXPIRY_MINUTES': "10",
            #     "name":name,
            #     'otp': otp,  # if you want to include OTP
            # })

            # # Create EmailMessage
            # email1 = EmailMessage(
            #     subject="Your Resend OTP Code",
            #     body=html_content,
            #     from_email=settings.DEFAULT_FROM_EMAIL,
            #     to=[email]         # recipient email
            # )
            # email1.content_subtype = "html"

            # # Send email
            # email1.send(fail_silently=False)

            html_content = render_to_string('mails/resend_otp.html', {
                
                'EXPIRY_MINUTES': "10",
                "name":profile.first_name+" "+profile.last_name,
                'otp': otp,  # if you want to include OTP
                })
            display_name = "Eazeesign Via Eazeesign"
            email_sent = send_email_safe(
                    request,
                    subject="Your Resend OTP Code",
                    body=html_content,
                    recipient_list=[email],
                    from_email=f"{display_name} <{settings.DEFAULT_FROM_EMAIL}>"

                )
            if not email_sent:
                return redirect(request.path)  # Wapas same page
            

            return JsonResponse({"success": True, "message": "OTP resent successfully!"})
        except Profile.DoesNotExist:
            return JsonResponse({"success": False, "message": "User not found."})

    return JsonResponse({"success": False, "message": "Invalid request."})


def user_login(request):
    if request.method == "POST":
        email = request.POST.get('email')
        password = request.POST.get('password')
        otp = request.POST.get('otp')
        messages.get_messages(request)  # Clear old ones

        
        # === SEND OTP BUTTON PRESSED ===
        if 'send_otp' in request.POST:
            try:
                user = User.objects.get(email=email)
                otp_code = str(random.randint(100000, 999999))

                # Save OTP in profile
                profile, created = Profile.objects.get_or_create(user=user)
                profile.email_otp = otp_code
                profile.save()

                # Send email OTP
                send_mail(
                    subject="Your Login OTP",
                    message=f"Your OTP for login is: {otp_code}",
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[email],
                    fail_silently=False,
                )

                messages.success(request, f"OTP sent to {email}{otp_code}. Please check your inbox.")
                return render(request, 'esign/login.html', {'email': email})

            except User.DoesNotExist:
                messages.success(request, "No user found with this email.")
                return redirect('user_login')

         # === LOGIN WITH OTP ===
        elif 'login' in request.POST and otp:
            try:
                user = User.objects.get(email=email)
                profile = Profile.objects.get(user=user)
                print("profile",profile.email_otp)
                if otp == profile.email_otp:
                    auth.login(request, user)
                    profile.email_otp = None
                    profile.save()
                    messages.get_messages(request)  # Clear old ones
                    messages.success(request, "Logged in successfully using OTP!")
                    
                    try:
                        marketing = MarketingSource.objects.get(user=user)
                    except MarketingSource.DoesNotExist:
                        marketing = None

                    if marketing and marketing.status:
                        return redirect('/')  # ya jahan redirect karna ho
                    else:
                        return redirect('marketing')
                else:
                    print("errror")
                    messages.error(request, "Invalid OTP. Please try again.")
            except (User.DoesNotExist, Profile.DoesNotExist):
                messages.error(request, "Please enter correct otp.")
                return redirect('user_login')

        # === LOGIN WITH PASSWORD ===
        elif 'login' in request.POST and password:
            user = auth.authenticate(username=email, password=password)
            if user:
                auth.login(request, user)
                messages.get_messages(request)  # Clear old ones
                messages.success(request, "Login successful!")
                try:
                    marketing = MarketingSource.objects.get(user=user)
                except MarketingSource.DoesNotExist:
                    marketing = None
                # return redirect('marketing')  # change this to your homepage
                if marketing and marketing.status:
                    return redirect('/')  # ya jahan redirect karna ho
                else:
                    return redirect('marketing')
            else:
                messages.get_messages(request)  # Clear old ones
                messages.success(request, "Invalid email or password.")
                return redirect('user_login')

       

    return render(request, 'esign/login.html')

def contact_us(request):
    if request.method == "POST":
        name = request.POST.get("inputContactName")
        email = request.POST.get("inputContactEmail")
        phone = request.POST.get("inputContactPhone")
        company = request.POST.get("inputContactCompanyName")

        # Email body
        body = f"""
        <h3>New Contact Form Submission</h3>
        <p><strong>Name:</strong> {name}</p>
        <p><strong>Email:</strong> {email}</p>
        <p><strong>Phone:</strong> {phone}</p>
        <p><strong>Company Name:</strong> {company}</p>
        """

        # Send to your email
        to_email = ["sauravdaiya870@gmail.com"]

        email_msg = EmailMessage(
            subject="New Contact Form Submission",
            body=body,
            from_email=settings.EMAIL_HOST_USER,     # Sender = your configured email
            to=to_email
        )
        email_msg.content_subtype = "html"

        try:
            email_msg.send()
            messages.success(request, "Your message has been sent successfully!")
        except Exception as e:
            print("EMAIL ERROR:", e)
            messages.error(request, "Failed to send message. Try again later.")

        return redirect("contact_us")

    return render(request, "esign/contact_us.html")

def contact_view(request):
    # Clear old messages
    list(get_messages(request))  # iterating clears the old messages

    if request.method == 'POST':
        name = request.POST.get('inputContactName')
        email = request.POST.get('inputContactEmail')
        phone = request.POST.get('inputContactPhone')
        company = request.POST.get('inputContactCompanyName')

        if name and email and phone and company:
            inquiry = ContactInquiry(
                name=name,
                email=email,
                phone=phone,
                company_name=company
            )
            if request.user.is_authenticated:
                inquiry.user = request.user
            inquiry.save()
            messages.success(request, "Your inquiry has been submitted successfully!")
            return redirect('contact')  # refresh page to show new message
        else:
            messages.error(request, "Please fill all required fields.")

    return render(request, 'esign/contact.html')



    
def user_logout(request):
    logout(request)
    list(messages.get_messages(request))
    messages.success(request, "You have been logged out successfully.")
    return redirect('user_login')

def comming_soon_get(request):
    return render(request,'esign/comming_soon.html')

def verify_otp(request, user_id):
    user = User.objects.get(id=user_id)
    profile = Profile.objects.get(user=user)
    messages.get_messages(request)  # Clear old ones
    if request.method == "POST":
        entered_otp = request.POST.get('otp')

        if entered_otp == profile.email_otp:
            user.is_active = True
            user.save()
            profile.is_verified = True
            profile.save()
            messages.success(request, "Email verified successfully! You can now log in.")
            return redirect('user_login')
        else:
            messages.error(request, "Invalid OTP. Please try again.")

    return render(request, 'esign/verify_otp.html', {'email': user.email})

def user_signup(request):
    pass

# def user_signup(request):
#     if request.method == "POST":
#         first_name = request.POST.get('username')
#         last_name = request.POST.get('userLastName')
#         email = request.POST.get('userEmail')
#         phone = request.POST.get('userPhone')
#         password = request.POST.get('userPassword')
#         confirm_password = request.POST.get('confirmPasswordHelp')
#         print("User create2")
#         messages.get_messages(request)  # Clear old ones
#         if password != confirm_password:
#             messages.error(request, "Passwords do not match.")
#             # return redirect('user_signup',{"post_data": request.POST})
#             return render(request, "esign/signup.html", {"post_data": request.POST})

#         print("User create1")

#         if User.objects.filter(email=email).exists():
#             messages.success(request, "User with this email already exists.")
#             return redirect('user_login')
#         print("User create")
#         # Create user (inactive until OTP verified)
#         user = User.objects.create_user(
#             username=email,
#             email=email,
#             password=password,
#             first_name=first_name,
#             last_name=last_name,
#             is_active=False
#         )
#         user.save()

#         # Generate OTP
#         otp = str(random.randint(100000, 999999))

#         # Create Profile
#         profile = Profile.objects.create(user=user, phone=phone, email_otp=otp)

#         # Send OTP to email
#         send_mail(
#             subject='Your Email Verification OTP',
#             message=f'Your OTP for account verification is {otp}',
#             from_email=settings.DEFAULT_FROM_EMAIL,
#             recipient_list=[email],
#             fail_silently=False,
#         )
#         messages.get_messages(request)  # Clear old ones
#         messages.success(request, f"OTP sent to {email} {otp}. Please verify your email.")
#         return redirect('verify_otp', user_id=user.id)

#     return render(request, 'esign/signup.html')




@login_required
def marketing_view(request):
    if request.method == "POST":
        form = MarketingForm(request.POST)
        if form.is_valid():
            source = form.cleaned_data['marketing_source']
            MarketingSource.objects.create(user=request.user, source=source,status=True)
            return redirect('/')  # ya jahan redirect karna ho
    else:
        form = MarketingForm()
    return render(request, 'esign/marketing_form.html', {'form': form})



@login_required
def signature_status_get(request):
    user = request.user
    search_query = request.GET.get('search', '').strip()

    # -------- DRAFTS --------
    drafts_doc_id = request.GET.get('drafts_doc_id')
    drafts_file_name = request.GET.get('drafts_file_name')
    drafts_category = request.GET.get('drafts_category')
    drafts_status = request.GET.get('drafts_status')

    drafts = Document.objects.filter(owner=user, status='pending').annotate(signer_count=Count('sign_flow')).filter(signer_count=0)
    if drafts_doc_id:
        drafts = drafts.filter(id=drafts_doc_id)
    if drafts_file_name:
        drafts = drafts.filter(title__icontains=drafts_file_name)
    if drafts_category:
        drafts = drafts.filter(category__icontains=drafts_category)
    if drafts_status:
        drafts = drafts.filter(status__icontains=drafts_status)
    drafts = drafts.order_by('-created_at')
    drafts_paginator = Paginator(drafts, 10)
    drafts_page_number = request.GET.get('drafts_page')
    drafts_page = drafts_paginator.get_page(drafts_page_number)

    # -------- ACTION REQUIRED --------
    action_doc_id = request.GET.get('action_doc_id')
    action_file_name = request.GET.get('action_file_name')
    action_category = request.GET.get('action_category')
    action_status = request.GET.get('action_status')

    action_required = DocumentSignFlow.objects.filter(
        recipient_email=user.email, is_signed=False, is_canceled=False, role='signer'
    ).select_related('document', 'document__owner')

    if action_doc_id:
        action_required = action_required.filter(document__id=action_doc_id)
    if action_file_name:
        action_required = action_required.filter(document__title__icontains=action_file_name)
    if action_category:
        action_required = action_required.filter(document__category__icontains=action_category)
    if action_status:
        action_required = action_required.filter(document__status__icontains=action_status)
    if search_query:
        action_required = action_required.filter(
            Q(document__title__icontains=search_query) | Q(document__category__icontains=search_query)
        )

    action_required = action_required.order_by('-document__created_at')
    action_paginator = Paginator(action_required, 10)
    action_page_number = request.GET.get('action_page')
    action_page = action_paginator.get_page(action_page_number)

    # -------- WAITING FOR OTHERS --------
    waiting_doc_id = request.GET.get('waiting_doc_id')
    waiting_file_name = request.GET.get('waiting_file_name')
    waiting_category = request.GET.get('waiting_category')
    waiting_status = request.GET.get('waiting_status')

    waiting_for_others = Document.objects.filter(owner=user, status='pending', sign_flow__is_signed=False).distinct().prefetch_related('sign_flow', 'sign_flow__document')
    if waiting_doc_id:
        waiting_for_others = waiting_for_others.filter(id=waiting_doc_id)
    if waiting_file_name:
        waiting_for_others = waiting_for_others.filter(title__icontains=waiting_file_name)
    if waiting_category:
        waiting_for_others = waiting_for_others.filter(category__icontains=waiting_category)
    if waiting_status:
        waiting_for_others = waiting_for_others.filter(status__icontains=waiting_status)
    if search_query:
        waiting_for_others = waiting_for_others.filter(Q(title__icontains=search_query) | Q(category__icontains=search_query))
    waiting_for_others = waiting_for_others.order_by('-created_at')
    waiting_paginator = Paginator(waiting_for_others, 10)
    waiting_page_number = request.GET.get('waiting_page')
    waiting_page = waiting_paginator.get_page(waiting_page_number)

    # -------- FINALIZED --------
    finalized_doc_id = request.GET.get('finalized_doc_id')
    finalized_file_name = request.GET.get('finalized_file_name')
    finalized_category = request.GET.get('finalized_category')
    finalized_status = request.GET.get('finalized_status')

    finalized = Document.objects.filter(owner=user, status__in=['signed', 'approved']).prefetch_related('sign_flow')
    if finalized_doc_id:
        finalized = finalized.filter(id=finalized_doc_id)
    if finalized_file_name:
        finalized = finalized.filter(title__icontains=finalized_file_name)
    if finalized_category:
        finalized = finalized.filter(category__icontains=finalized_category)
    if finalized_status:
        finalized = finalized.filter(status__icontains=finalized_status)
    if search_query:
        finalized = finalized.filter(Q(title__icontains=search_query) | Q(category__icontains=search_query))
    finalized = finalized.order_by('-created_at')
    finalized_paginator = Paginator(finalized, 10)
    finalized_page_number = request.GET.get('finalized_page')
    finalized_page = finalized_paginator.get_page(finalized_page_number)

    # -------- CONTEXT --------
    context = {
        'drafts': drafts_page,
        'action_required': action_page,
        'waiting_for_others': waiting_page,
        'finalized': finalized_page,
        'drafts_filters': {
            'doc_id': drafts_doc_id or '',
            'file_name': drafts_file_name or '',
            'category': drafts_category or '',
            'status': drafts_status or '',
        },
        'action_filters': {
            'doc_id': action_doc_id or '',
            'file_name': action_file_name or '',
            'category': action_category or '',
            'status': action_status or '',
        },
        'waiting_filters': {
            'doc_id': waiting_doc_id or '',
            'file_name': waiting_file_name or '',
            'category': waiting_category or '',
            'status': waiting_status or '',
        },
        'finalized_filters': {
            'doc_id': finalized_doc_id or '',
            'file_name': finalized_file_name or '',
            'category': finalized_category or '',
            'status': finalized_status or '',
        },
    }

    return render(request, 'esign/signature_status.html', context)





@login_required
def document_list(request):
    storage = messages.get_messages(request)
    list(storage)  # clear old messages

    # Get filter values from GET request
    doc_id = request.GET.get('doc_id', '').strip()
    document_title = request.GET.get('document_title', '').strip()
    category = request.GET.get('category', '').strip()
    status = request.GET.get('status', '').strip()  # e.g., 'Complete' or 'Pending'

    # Base queryset: only documents owned by user AND having at least one signer
    docs = Document.objects.filter(owner=request.user, is_template=False).annotate(
        signer_count=Count('sign_flow')
    ).filter(signer_count__gt=0)

    # Apply search-like filters
    if doc_id:
        docs = docs.filter(id__icontains=doc_id)  # partial match for ID
    if document_title:
        docs = docs.filter(title__icontains=document_title)  # partial match for title
    if category:
        docs = docs.filter(category__icontains=category)
    if status:
        filtered_docs = []
        for d in docs:
            flows = d.sign_flow.all()
            has_pending = any(not f.is_signed for f in flows)
            if status.lower() == "pending" and has_pending:
                filtered_docs.append(d)
            elif status.lower() == "complete" and not has_pending:
                filtered_docs.append(d)
        docs = filtered_docs

    # Order by newest first
    if hasattr(docs, 'order_by'):
        docs = docs.order_by('-created_at')

    # Pagination
    paginator = Paginator(docs, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'documents': page_obj,
        'doc_id': doc_id,
        'document_title': document_title,
        'category': category,
        'status': status,
    }
    return render(request, 'esign/document-list.html', context)

import pytz
@login_required
def upload_document(request):
    if request.method == 'POST':
        form = DocumentUploadForm(request.POST, request.FILES)
        if form.is_valid():
            doc = form.save(commit=False)
            doc.owner = request.user

            # Handle valid_until properly
            if timezone.is_naive(doc.valid_until):
                ist = pytz.timezone('Asia/Kolkata')
                doc.valid_until = ist.localize(doc.valid_until).astimezone(pytz.UTC)
            else:
                doc.valid_until = doc.valid_until.astimezone(pytz.UTC)

            print("timezone.now()",timezone.now())
            doc.save()
            return redirect('document_detail', pk=doc.pk)
    else:
        form = DocumentUploadForm()

    return render(request, 'esign/upload-document.html', {'form': form})

@login_required
def document_detail(request, pk):
  
    doc = get_object_or_404(Document, pk=pk)


    # Normal document detail if document exists
    # placements = SignaturePlacement.objects.filter(document=doc)
    reminder_range = range(1, 31)
    users = get_user_model().objects.all().order_by('id')

    return render(request, 'esign/document_detail.html', {
        'document': doc,
        'signatures': [],
        'placements': [],
        'users': users,
        'reminder_range': reminder_range,
    })

@login_required
def open_signing_link(request, pk):
    doc = get_object_or_404(Document, pk=pk)

    # सिर्फ owner या admin ही भेज सके
    if request.user != doc.owner and not request.user.is_staff:
        return redirect('index')

    token = secrets.token_urlsafe(32)
    expires = timezone.now() + timedelta(days=2)

    SigningToken.objects.create(document=doc, token=token, expires_at=expires)

    # instead of email → direct redirect
    return redirect('sign_document', token=token)



def rgb_to_hex(rgb_str):
    if rgb_str.startswith('rgb'):
        nums = rgb_str.strip('rgb()').split(',')
        return '#{:02x}{:02x}{:02x}'.format(int(nums[0]), int(nums[1]), int(nums[2]))
    return rgb_str  # already hex


import io
@login_required
def send_signing_link(request, pk):
    doc = get_object_or_404(Document, pk=pk)
    print("Start",request.POST)
    recipient_list = []
    recipient_emails = request.POST.getlist('email[]', '')
    cc_emails = request.POST.get('cc_email', '')
    subjectget = request.POST.get('subject', '')
    security_token = request.POST.get('security_token', '')
    reminder_days = request.POST.get('reminder_days', '')
    # reminder_days = int(reminder_days)  # convert string to integer
    reminder_days = 2  # convert string to integer
    role = "viewer" if request.POST.get("role") == "viewer" else "signer"

    
    print(recipient_emails,"recipient_emails first")
    recipient_list = [e.strip() for e in recipient_emails if e.strip()]
    cc_list = [e.strip() for e in cc_emails.split(',') if e.strip()]
    print(f"[INFO] Recipients: {recipient_list}, CC: {cc_list}")

    print("recipient_list start",recipient_list)
    print(request.POST)

    payload = json.loads(request.POST.get('boxes', '{}'))
    selected_pages = payload.get('allowed_pages', [])
    order_postion_bulk1 = payload.get('order_postion_bulk', [])

    print("order_postion_bulk1",order_postion_bulk1)
    
    # selected_pages = json.loads(request.POST.get('selected_pages', '[]'))
    print(f"[INFO] Selected pages received: {selected_pages}")
    # Clear previous boxes & pages for this document
    SignatureBox.objects.filter(document=doc).delete()
    SignaturePage.objects.filter(document=doc).delete()

    selected_user_ids = payload.get('users', [])

    print(f"[INFO] Selected user IDs: {selected_user_ids}")

    # Delete existing sign flow for this document
    # deleted_count, _ = DocumentSignFlow.objects.filter(document=doc).delete()
    # print(f"[INFO] Deleted {deleted_count} existing sign flow entries for document {doc.id}")
    
    for order, recipient in enumerate(order_postion_bulk1, start=1):
        name = recipient.get("name")
        email = recipient.get("email")
        position = recipient.get("position", order)
        token1 = get_random_string(32)
        
        flow = DocumentSignFlow.objects.create(
                document=doc,
                token=token1,
                recipient_name=name,
                recipient_email=email,
                order=position,
                role=role,
                reminder_days=reminder_days,
                  last_reminder_sent=timezone.now(),
                    next_reminder_sent = timezone.now() + timedelta(days=reminder_days),
                    security_token=security_token
            )
        # expires= timezone.now() + timedelta(days=2)
        if doc.valid_until:
            expires = doc.valid_until
        else:
            # agar valid_until blank ho to default 2 din ka expiry
            expires = timezone.now() + timedelta(days=2)
        SigningToken.objects.create(document=doc, token=token1, expires_at=expires)
        print("position",position)
        if position == 1:
            recipient_list.append(email)
            token = token1
            email_first_name = name
        
        

    print(f"[INFO] DocumentSignFlow creation completed for document {doc.id}")


    pages_str = ",".join(str(p) for p in selected_pages)

    # अब सिर्फ एक बार create करो
    SignaturePage.objects.create(
        document=doc,
        page=pages_str,
        allowed=True
    )



    if not recipient_list:
        messages.error(request, "Provide at least one valid recipient email.")
        print("[ERROR] No recipient emails provided.")
        return redirect(f'/document/{doc.id}/')

    # Get boxes data from POST and save to DB
    try:

        # boxes_data = json.loads(request.POST.get('boxes', '[]'))
        payload = json.loads(request.POST.get('boxes', '{}'))

        boxes_data = payload.get('boxes', [])

        print(f"[INFO] Boxes data received from POST: {boxes_data}")

        # Clear previous boxes for this document
        SignatureBox.objects.filter(document=doc).delete()
        
        # Save boxes to DB
        for box in boxes_data:
            SignatureBox.objects.create(
                document=doc,
                page=box['page'],
                x=box['x'],
                y=box['y'],
                width=box['width'],
                height=box['height'],
                type=box.get('type', 'signature'),
                rotation=box.get('rotation', 0),
                font_family=box.get('fontFamily', 'Arial'),
                font_size=box.get('fontSize', 10),
                color = rgb_to_hex(box.get('color', '#000000')),
                font_weight=box.get('fontWeight', 'normal'),
                font_style=box.get('fontStyle', 'normal'),
                text_decoration=box.get('textDecoration', 'none'),
            )
        print(f"[INFO] {len(boxes_data)} signature boxes saved to DB for document {doc.pk}")
    except Exception as e:
        messages.error(request, "Invalid boxes data.")
        print(f"[ERROR] Failed to parse or save boxes data: {e}")
        return redirect('document_detail', pk=pk)

    # Fetch boxes from DB for PDF generation
    boxes_data = list(SignatureBox.objects.filter(document=doc).values(
        'page', 'x', 'y', 'width', 'height', 'type', 'rotation'
    ))
    print(f"[INFO] Boxes fetched from DB for PDF: {boxes_data}")

    # Generate new PDF with boxes
    output = PdfWriter()
    reader = PdfReader(doc.file.path)
    for i, page in enumerate(reader.pages, start=1):
        packet = io.BytesIO()
        can = canvas.Canvas(packet, pagesize=letter)

        # Draw boxes for this page
        for box in boxes_data:
            if box['page'] == i:
                print(f"[DEBUG] Drawing box on page {i}: {box}")
                can.setStrokeColorRGB(0,0,0)
                can.setLineWidth(2)
                can.rect(box['x'], box['y'], box['width'], box['height'])
                can.drawString(box['x']+5, box['y']+box['height']/2, box['type'].capitalize())
        
        can.save()
        packet.seek(0)

        # Merge overlay safely
        overlay = PdfReader(packet)
        if len(overlay.pages) > 0:
            page.merge_page(overlay.pages[0])
            print(f"[INFO] Merged overlay into page {i}")
        else:
            print(f"[INFO] No boxes to merge on page {i}")

        output.add_page(page)

    # Save merged PDF to memory
    output_pdf_io = io.BytesIO()
    output.write(output_pdf_io)
    output_pdf_io.seek(0)

    merged_filename = f'merged_{doc.pk}.pdf'
    merged_path = f'media/{merged_filename}'
    with open(merged_path, 'wb') as f:
        f.write(output_pdf_io.read())
    print(f"[INFO] Merged PDF saved to {merged_path}")

    # Create signing token
    # token = secrets.token_urlsafe(32)
    # expires = timezone.now() + timedelta(days=2)
    # SigningToken.objects.create(document=doc, token=token, expires_at=expires)
    if order_postion_bulk1:
        encoded_email = urlsafe_base64_encode(force_bytes(recipient_list))
        sign_url = request.build_absolute_uri(reverse('sign_document', args=[token,encoded_email]))
        name = email_first_name if email_first_name else recipient_list[0].split("@")[0]
        # name = name_part.replace(".", " ").title()   # Saurav Dahiya
        print("name",name)

        html_content = render_to_string('mails/email_template_sign_request.html', {
            'doc_title': doc.title,
            'sign_url': sign_url,
            'name': name
            })
        print(recipient_list,"recipient_list")
    
    
        auth_user = request.user.get_full_name() or request.user.first_name
        display_name = f"{auth_user} Via Eazeesign"
        email_sent = send_email_safe(
                    request,
                    subject=f"Complete with Eazeesign: {doc.title}",
                    body=html_content,
                    recipient_list=recipient_list,
                    from_email=f"{display_name} <{settings.DEFAULT_FROM_EMAIL}>"
                )
        if not email_sent:
            return redirect(f'/document/{doc.id}/')

            
        # name = recipient_list.split("@")[0]              # saurav.dahiya

    else:
        for i in recipient_list:
            encoded_email = urlsafe_base64_encode(force_bytes(i))
            token = get_random_string(32)
            flow = DocumentSignFlow.objects.create(
                    document=doc,
                    token=token,
                    recipient_name="",
                    recipient_email=i,
                    order=0,
                    role=role,
                    reminder_days=reminder_days,
                    last_reminder_sent=timezone.now(),
                    next_reminder_sent = timezone.now() + timedelta(days=reminder_days),
                    security_token=security_token
                )
            if doc.valid_until:
                expires = doc.valid_until
            else:
                expires = timezone.now() + timedelta(days=2)
            # expires = timezone.now() + timedelta(days=2)
            SigningToken.objects.create(document=doc, token=token, expires_at=expires)
            sign_url = request.build_absolute_uri(reverse('sign_document', args=[token,encoded_email]))
            html_content = render_to_string('mails/email_template_sign_request.html', {
            'doc_title': doc.title,
            'sign_url': sign_url,
            'name': i.split("@")[0]
            })
            # print(recipient_list,"recipient_list")
            # display_name = "Eazeesign Via Eazeesign"
            auth_user = request.user.get_full_name() or request.user.first_name
            display_name = f"{auth_user} Via Eazeesign"

            email_sent = send_email_safe(
                    request,
                    subject=f"Complete with Eazeesign: {subjectget}",
                    body=html_content,
                    recipient_list=[i],
                    from_email=f"{display_name} <{settings.DEFAULT_FROM_EMAIL}>"
                )
            if not email_sent:
                return redirect(f'/document/{doc.id}/')

            



    # print(f"[INFO] Signing URL: {sign_url} (token expires at {expires})")

    # Send email
    try:
       
        print(f"[INFO] Email sent successfully to: {recipient_list}, CC: {cc_list}")

        messages.success(request, f"Signing link sent to: {', '.join(recipient_list)}")
        messages.error(request, f"Signing link sent to: {', '.join(recipient_list)}")
        if cc_list:
            messages.success(request, f"CC: {', '.join(cc_list)}")
    except Exception as e:
        messages.error(request, f"Failed to send email: {e}")
        print(f"[ERROR] Failed to send email: {e}")
    messages.success(request, "Link sent successfully!")  # ✅ set success message
    return redirect('document_list')





def accept_terms(request):
    request.session['accepted_terms'] = True
    return JsonResponse({'status': 'ok'})
def check_terms(request):
    accepted = request.session.get('accepted_terms', False)
    return JsonResponse({'accepted': accepted})

def disclosure_view(request):
    return render(request, "esign/disclosure.html")

def sign_document(request, token, encoded_email=None):
    st = get_object_or_404(DocumentSignFlow, token=token)
    doc = st.document
    try:
        signing_token = SigningToken.objects.get(document=doc, token=token)
        print("signing_token",signing_token)
        # Compare both in UTC (Django handles timezone-aware datetimes internally)
        print('signing_token.expires_at',signing_token.expires_at,timezone.now(),'timezone.now()')
        expires_date = signing_token.expires_at.date()  # this is a datetime.date
        new_date = expires_date + timedelta(days=1)
        if new_date < timezone.now().date():
            # token expired
            return render(request, 'esign/token_invalid.html', {
                "message": "This signing link has expired."
            })

    except SigningToken.DoesNotExist:
        return render(request, 'esign/token_invalid.html', {
            "message": "Invalid signing token."
        })
    # Current flow
    try:
        flow = DocumentSignFlow.objects.get(document=doc, token=token)
    except DocumentSignFlow.DoesNotExist:
        return render(request, 'esign/token_invalid.html', {
            "message": "You are not authorized to sign this document."
        })

    # # Already signed check
    invalid_states = {
        flow.is_signed: "You have already signed this document.",
        flow.is_canceled: "You have canceled signing for this document.",
        flow.assigned_by is not None: "This document has already been assigned to someone else."
    }

    for condition, message in invalid_states.items():
        if condition:
            return render(request, 'esign/token_invalid.html', {"message": message})


    if st.security_token:  # sirf tab check kare jab token set hai
        if request.method == "POST":
            entered_token = request.POST.get("security_token")
            if entered_token != st.security_token:
                return render(request, "esign/security_check.html", {
                    "error": "Invalid Security Token. Please try again.",
                    "token": token,
                })
        else:
            # Pehle baar jab link open hota hai → token maange
            return render(request, "esign/security_check.html", {
                "token": token,
            })



    if flow.role == "viewer":
        return render(request, "esign/only_show_doc.html", {
            "document": flow.document,
            "flow": flow,
            "message": "You can only view this document. Signing is not allowed."
        })
    # ---- File source decide ----
    if flow.order in [0,1] :
        # First signer → use original uploaded file
        file_to_sign = doc.file.url
        print("file_to_sign",file_to_sign)
        # file_to_sign =  f"/media/{file_to_sign}"

       

    else:
        # Not first → pick previous order’s merged file
        prev_flow = DocumentSignFlow.objects.filter(
            document=doc, order=flow.order - 1, is_signed=True 
        ).first()


        if prev_flow and prev_flow.merged_file:
            file_to_sign = prev_flow.merged_file
            file_to_sign =  f"/media/{file_to_sign}"
        else:
            return render(request, 'esign/token_invalid.html', {
                "message": "Previous signer has not completed signing yet."
            })

    print("File picked for signing:", file_to_sign)

    # Saved signatures for this user
    email = urlsafe_base64_decode(encoded_email).decode()
    if request.user.is_authenticated:
        saved_signatures = Signature.objects.filter(email=email).values('id', 'name', 'image','initials_image')
    else:
        saved_signatures = Signature.objects.filter(email=email).values('id', 'name', 'image','initials_image')

    print("saved_signatures",saved_signatures,email)
    # Allowed pages
    allowed_pages = SignaturePage.objects.filter(document=doc).first()
    if allowed_pages and allowed_pages.page:
        allowed_pages_list = [int(p) for p in allowed_pages.page.split(",")]
    else:
        allowed_pages_list = []

    # Signature boxes
    signature_boxes = list(
    SignatureBox.objects.filter(document=doc).values(
        'id',
        'page',
        'x',
        'y',
        'width',
        'height',
        'type',
        'rotation',
        'font_family',
        'font_size',
        'color',
        'font_weight',
        'font_style',
        'text_decoration'
    )
    )

    # Signing order checks
    previous_users = DocumentSignFlow.objects.filter(
        document=doc,
        order__lt=flow.order
    )
    all_previous_signed = all(u.is_signed for u in previous_users)
    if not all_previous_signed:
        return render(request, 'esign/token_invalid.html', {
            "message": "You cannot sign yet. Previous users in the signing order have not signed."
        })

    return render(request, 'esign/sign_page.html', {
        'document': doc,
        'token': token,
        'saved_signatures': list(saved_signatures),
        'allowed_pages_list': allowed_pages_list,
        'signature_boxes': signature_boxes,
        'can_sign': True,
        'signing_order': flow.order,
        'message': None,
        'file_to_sign': file_to_sign,  # ✅ yeh path aapko sign karne me use karna hoga
    })



def apply_signatures(request):
    if request.method != 'POST':
        return JsonResponse({'ok': False, 'error': 'POST only'}, status=405)

    try:
        data = json.loads(request.body.decode('utf-8'))
        token_str = data.get('token')
        placements = data.get('placements', [])

        # Get current signing flow
        flow = get_object_or_404(DocumentSignFlow, token=token_str)
        doc = flow.document

        # Determine PDF to use
        if flow.order in [0, 1]:
            pdf_path = doc.file.path
        else:
            prev_flow = DocumentSignFlow.objects.filter(document=doc, order=flow.order - 1).first()
            pdf_path = prev_flow.merged_file.path if prev_flow and prev_flow.merged_file else doc.file.path

        pdf = fitz.open(pdf_path)

        # Insert signatures
        # for p in placements:
        #     page_num = int(p['page'])
        #     page = pdf[page_num - 1]
        #     rect = page.rect
        #     x_pct = float(p['x_pct'])
        #     y_pct = float(p['y_pct'])
        #     w_pct = float(p.get('width_pct', 0.25))
        #     h_pct = float(p.get('height_pct', 0.1))
        #     target_w = rect.width * w_pct
        #     target_h = rect.height * h_pct
        #     x_pt = rect.x0 + rect.width * x_pct - target_w / 2
        #     y_pt = rect.y0 + rect.height * y_pct - target_h / 2

        #     if p.get('signature_id'):
        #         sig = Signature.objects.get(pk=int(p['signature_id']))
        #         page.insert_image(fitz.Rect(x_pt, y_pt, x_pt + target_w, y_pt + target_h), filename=sig.image.path)
        #     elif p.get('base64'):
        #         header, b64 = p['base64'].split(',', 1)
        #         imgdata = base64.b64decode(b64)
        #         imgstream = BytesIO(imgdata)
        #         page.insert_image(fitz.Rect(x_pt, y_pt, x_pt + target_w, y_pt + target_h), stream=imgstream)
        first_signature = None  # store first signature object

        for p in placements:
            page_num = int(p['page'])
            page = pdf[page_num - 1]
            rect = page.rect
            x_pct = float(p['x_pct'])
            y_pct = float(p['y_pct'])
            w_pct = float(p.get('width_pct', 0.25))
            h_pct = float(p.get('height_pct', 0.1))
            target_w = rect.width * w_pct
            target_h = rect.height * h_pct
            x_pt = rect.x0 + rect.width * x_pct - target_w / 2
            y_pt = rect.y0 + rect.height * y_pct - target_h / 2

            box_type = p.get('type')
            item_id = p.get('id')
            value = p.get('value')

            print(f"Processing placement: page={page_num}, type={box_type}, id={item_id}, value={value}")
            print(f"Coords: x={x_pt}, y={y_pt}, w={target_w}, h={target_h}")

            if box_type == "signature":
                if item_id:  # the first signature added
                    sig = Signature.objects.get(pk=int(item_id))
                    first_signature = sig  # store it for other boxes
                elif first_signature:  # use the first signature for other boxes
                    sig = first_signature
                else:
                    continue  # skip if no signature yet

                print(f"Inserting signature ID {sig.id} at page {page_num}")
                page.insert_image(
                    fitz.Rect(x_pt, y_pt, x_pt + target_w, y_pt + target_h),
                    filename=sig.image.path
                )
            elif box_type == "initial":
                if item_id:  # the first signature added
                    sig = Signature.objects.get(pk=int(item_id))
                    first_signature = sig  # store it for other boxes
                elif first_signature:  # use the first signature for other boxes
                    initial = first_signature
                else:
                    continue  # skip if no signature yet
            
                # initial = Signature.objects.get(pk=int(item_id))
                print(f"Inserting initial ID {item_id} at page {page_num}")
                page.insert_image(fitz.Rect(x_pt, y_pt, x_pt + target_w, y_pt + target_h), filename=initial.initials_image.path)

            elif box_type == "stamp" and item_id:
                stamp = Signature.objects.get(pk=int(item_id))
                print(f"Inserting stamp ID {item_id} at page {page_num}")
                page.insert_image(fitz.Rect(x_pt, y_pt, x_pt + target_w, y_pt + target_h), filename=stamp.image.path)

            elif box_type == "date" and value:
                print(f"Inserting date '{value}' at page {page_num}")
                page.insert_textbox(
                    fitz.Rect(x_pt, y_pt, x_pt + target_w, y_pt + target_h),
                    str(value),
                    fontsize=12,
                    fontname="helv",
                    color=(0, 0, 0)
                )


        # Save merged PDF to memory
        out = BytesIO()
        pdf.save(out)
        pdf.close()
        out.seek(0)

        # Save merged PDF to memory
        # out = BytesIO()
        # pdf.save(out)
        # pdf.close()
        # out.seek(0)

        # Save merged PDF to current flow
        merged_fname = f'merged-{doc.pk}-{secrets.token_hex(6)}.pdf'
        flow.merged_file.save(merged_fname, ContentFile(out.read()))
        flow.is_signed = True
        flow.signed_at = timezone.now()
        flow.save()

        # Update document status
        doc.status = 'signed'
        doc.save()

        # Prepare email for next signer (if any)
        next_flow = DocumentSignFlow.objects.filter(
            document=doc,
            order__gt=flow.order,
            is_signed=False
        ).order_by('order').first()

        if next_flow:
            encoded_email = urlsafe_base64_encode(force_bytes(next_flow.recipient_email))
            sign_url = request.build_absolute_uri(reverse('sign_document', args=[next_flow.token, encoded_email]))
            
            html_content = render_to_string('mails/email_template_sign_request.html', {
                'doc_title': doc.title,
                'sign_url': sign_url,
                'user': next_flow.recipient_name,
                'merged_url': request.build_absolute_uri(flow.merged_file.url),
                'message': 'Your document has been signed and merged PDF is attached.'
            })

            display_name = "Eazeesign Via Eazeesign"

            email_sent = send_email_safe(
                    request,
                    subject=f"Complete with Eazeesign: {doc.title}",
                    body=html_content,
                    recipient_list=[next_flow.recipient_email],
                    from_email=f"{display_name} <{settings.DEFAULT_FROM_EMAIL}>"
                )
            if not email_sent:
                return redirect(request.path)  # Wapas same page
            
        recipient_name = flow.recipient_name
        if not recipient_name:
            recipient_name = flow.recipient_email.split("@")[0]
        html_content = render_to_string('mails/document_signed_successfully.html', {
                'doc_title': doc.title,
                'sign_url': "",
                'recipient_name': recipient_name,
                'user': recipient_name,
                'document_link':request.build_absolute_uri(flow.merged_file.url)
            })
        display_name = "Eazeesign Via Eazeesign"

        email_self = EmailMessage(
            subject=f"Completed: Complete with Eazeesign: {doc.title}",
            body=html_content,
            from_email=f"{display_name} <{settings.DEFAULT_FROM_EMAIL}>",
            to=[flow.recipient_email]
        )
        email_self.content_subtype = "html"

        # email_self.content_subtype = "html"

        flow.merged_file.open()
        email_self.attach(
            flow.merged_file.name.split('/')[-1],
            flow.merged_file.read(),
            'application/pdf'
        )
        email_self.send(fail_silently=False)

        if 'accepted_terms' in request.session:
            del request.session['accepted_terms']


        return JsonResponse({'ok': True, 'merged_url': flow.merged_file.url})

    except Exception as e:
        return JsonResponse({'ok': False, 'error': str(e)}, status=500)

def thankyou(request):
    return render(request,'esign/thank_you.html')

def get_initial_image(request, sig_id):
    try:
        # sig = Signature.objects.get(id=sig_id)
        sig = Signature.objects.get(id=sig_id)
        print(sig.__dict__)  # prints all fields and values
        if sig.initials_image:  # make sure you have a field for initial image
            return JsonResponse({'ok': True, 'initialImageUrl': sig.initials_image.url})
        else:
            return JsonResponse({'ok': False, 'error': sig})
    except Signature.DoesNotExist:
        return JsonResponse({'ok': False, 'error': 'Signature not found'})
    

    
def upload_signature(request):
    if request.method == 'POST':
        data = json.loads(request.body.decode('utf-8'))
        img = data.get('image')
        initials_img = data.get('initials_image')  # new initials image
        name = data.get('name','')
        email = data.get('email')  # required

        if not img:
            return JsonResponse({'ok': False, 'error': 'No signature image provided'}, status=400)

        sig = Signature(email=email, name=name)

        # Save signature image
        header, b64 = img.split(',', 1)
        imgdata = base64.b64decode(b64)
        sig.image.save(f'sig-{secrets.token_hex(6)}.png', ContentFile(imgdata))

        # Save initials image if provided
        if initials_img:
            header_init, b64_init = initials_img.split(',', 1)
            init_data = base64.b64decode(b64_init)
            sig.initials_image.save(f'init-{secrets.token_hex(6)}.png', ContentFile(init_data))

        sig.save()

        return JsonResponse({
            'ok': True,
            'id': sig.id,
            'url': sig.image.url,
            'initials_url': sig.initials_image.url if sig.initials_image else None
        })

    return JsonResponse({'ok': False, 'error': 'POST only'}, status=405)

@login_required
def delete_document(request, pk):
    doc = get_object_or_404(Document, pk=pk)
    
    if request.method == "POST":
        doc_title = doc.title  # delete से पहले title store कर लो
        doc.delete()

        # success message
        messages.success(request, f"Document '{doc_title}' deleted successfully.")

        # वापस उसी page पर redirect
        referer = request.META.get("HTTP_REFERER")
        if referer:
            return redirect(referer)
        else:
            return redirect('document_list')

    return redirect('document_list')



@csrf_exempt  # if you are using fetch with CSRF manually
def delete_signature(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            sig_id = data.get("id")
            sig = Signature.objects.get(id=sig_id)
            sig.delete()
            return JsonResponse({"ok": True})
        except Signature.DoesNotExist:
            return JsonResponse({"ok": False, "error": "Signature not found"})
        except Exception as e:
            return JsonResponse({"ok": False, "error": str(e)})
    return JsonResponse({"ok": False, "error": "Invalid method"})






def send_signing_link_bulk(request, pk):
    doc = get_object_or_404(Document, pk=pk)
    # auth_user_email = request.user.email  # ✅ Authenticated user's email
    print(f"[INFO] send_signing_link_bulk called for document {doc.pk} by user {request.user}")

    # Get CSV emails
    print(request.POST)
    csv_emails_json = request.POST.get('csv_emails', '[]')
    print(f"[DEBUG] Raw csv_emails_json: {csv_emails_json}")
    try:
        emails_from_csv = json.loads(csv_emails_json)
    except json.JSONDecodeError:
        messages.error(request, "Invalid CSV emails data.")
        print("[ERROR] JSON decode failed for csv_emails")
        return redirect('document_detail', pk=pk)

    print(f"[DEBUG] Parsed emails_from_csv: {emails_from_csv}")
    if not emails_from_csv:
        messages.error(request, "No recipient emails found.")
        print("[WARN] No recipient emails found")
        return redirect('document_detail', pk=pk)

    # Optional CC and subject
    cc_emails = request.POST.get('cc_email', '')
    cc_list = [e.strip() for e in cc_emails.split(',') if e.strip()]
    print(f"[DEBUG] CC List: {cc_list}")
    subjectget = request.POST.get('subject', 'Please sign the document')
    print(f"[DEBUG] Email subject: {subjectget}")

    # Boxes & pages
    raw_boxes = request.POST.get('boxes', '')

    print("raw_boxes",raw_boxes)
    print("raw_boxes",request.POST)
    try:
        if not raw_boxes.strip():       # empty string
            payload = {}                # fallback empty dict
        else:
            payload = json.loads(raw_boxes)
    except json.JSONDecodeError:
        payload = {}                    # fallback safe
        print("[ERROR] JSON decode failed for boxes")
        
    boxes_data = payload.get('boxes', [])
    selected_pages = payload.get('allowed_pages', [])
    order_postion_bulk1 = payload.get('order_postion_bulk', [])
    print(f"[DEBUG] Boxes Data: {boxes_data}")
    print(f"[DEBUG] Selected Pages: {selected_pages}")
    print(f"[DEBUG] Order Position Bulk: {order_postion_bulk1}")

    # Clear previous data
    SignatureBox.objects.filter(document=doc).delete()
    SignaturePage.objects.filter(document=doc).delete()
    DocumentSignFlow.objects.filter(document=doc).delete()
    print("[INFO] Cleared previous SignatureBox, SignaturePage, DocumentSignFlow")

    # Save new SignaturePage
    pages_str = ",".join(str(p) for p in selected_pages)
    SignaturePage.objects.create(document=doc, page=pages_str, allowed=True)
    print(f"[INFO] Created SignaturePage for pages: {pages_str}")

    # Save new SignatureBoxes
    for box in boxes_data:
        SignatureBox.objects.create(
            document=doc,
            page=box['page'],
            x=box['x'],
            y=box['y'],
            width=box['width'],
            height=box['height'],
            type=box.get('type', 'signature'),
            rotation=box.get('rotation', 0)
        )
    print(f"[INFO] Created {len(boxes_data)} SignatureBoxes")

    # Create DocumentSignFlow entries
    recipient_list_first = []
    first_token = None
    # for order, recipient in enumerate(order_postion_bulk1 or emails_from_csv, start=1):
    #     if isinstance(recipient, dict):
    #         email = recipient.get("email")
    #         name = recipient.get("name", "")
    #         position = recipient.get("position", order)
    #     else:
    #         email = recipient
    #         name = ""
    #         position = order

    #     token1 = get_random_string(32)
    #     flow = DocumentSignFlow.objects.create(
    #         document=doc,
    #         token=token1,
    #         recipient_email=email,
    #         recipient_name=name,
    #         order=position
    #     )
    #     print(f"[INFO] Created DocumentSignFlow: {email} at position {position} with token {token1}")

    #     if position == 1:
    #         recipient_list_first.append(email)
    #         first_token = token1

    # Generate merged PDF


    recipient_tokens = {}  # email: token

    # 1️⃣ Handle order-position dicts
    for recipient in order_postion_bulk1:
        email = recipient.get("email")
        name = recipient.get("name", "")
        position = recipient.get("position", 1)

        token1 = get_random_string(32)
        flow = DocumentSignFlow.objects.create(
            document=doc,
            token=token1,
            recipient_email=email,
            recipient_name=name,
            order=position
        )
        recipient_tokens[email] = token1  # store token

        if position == 1:
            recipient_list_first.append(email)
            first_token = token1

    # 2️⃣ Handle CSV-only emails
    for email in emails_from_csv:
        token1 = get_random_string(32)
        flow = DocumentSignFlow.objects.create(
            document=doc,
            token=token1,
            recipient_email=email,
            recipient_name="",
            order=0
        )
        recipient_tokens[email] = token1  # store token

        # Optional: include CSV emails in first recipient email
        # recipient_list_first.append(email)

    print("[DEBUG] All recipient tokens:", recipient_tokens)


    output = PdfWriter()
    reader = PdfReader(doc.file.path)
    boxes_db = list(SignatureBox.objects.filter(document=doc).values(
        'page', 'x', 'y', 'width', 'height', 'type', 'rotation'
    ))
    print(f"[DEBUG] Fetched {len(boxes_db)} boxes from DB for PDF overlay")

    for i, page in enumerate(reader.pages, start=1):
        packet = io.BytesIO()
        can = canvas.Canvas(packet, pagesize=letter)
        for box in boxes_db:
            if box['page'] == i:
                can.setStrokeColorRGB(0,0,0)
                can.setLineWidth(2)
                can.rect(box['x'], box['y'], box['width'], box['height'])
                can.drawString(box['x']+5, box['y']+box['height']/2, box['type'].capitalize())
        can.save()
        packet.seek(0)
        overlay = PdfReader(packet)
        if len(overlay.pages) > 0:
            page.merge_page(overlay.pages[0])
        output.add_page(page)
    print("[INFO] Merged PDF pages with signature boxes")

    merged_filename = f'merged_{doc.pk}.pdf'
    merged_path = f'media/{merged_filename}'
    with open(merged_path, 'wb') as f:
        output.write(f)
    print(f"[INFO] Merged PDF saved at: {merged_path}")



    # Send email to all recipients using their token
    for email in recipient_tokens:
        token = recipient_tokens[email]
        
        # Encode email for URL
        encoded_email = urlsafe_base64_encode(force_bytes([email]))
        sign_url = request.build_absolute_uri(reverse('sign_document', args=[token, encoded_email]))
        print(f"[INFO] Sending email to {email} with link {sign_url}")
        
        html_content = render_to_string('mails/email_template_sign_request.html', {
            'doc_title': doc.title,
            'sign_url': sign_url,
            'user': "Saurav"
        })

        msg = EmailMessage(
            subject=f"Please sign document: {subjectget}",
            body=html_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[email],
            cc=cc_list
        )
        msg.content_subtype = "html"
        msg.attach(merged_filename, open(merged_path, 'rb').read(), 'application/pdf')
        msg.send(fail_silently=False)
        print(f"[INFO] Email sent successfully to {email}")


    # Send email to first signer(s)
    # if recipient_list_first:
    #     encoded_email = urlsafe_base64_encode(force_bytes(recipient_list_first))
    #     sign_url = request.build_absolute_uri(reverse('sign_document', args=[first_token, encoded_email]))
    #     print(f"[INFO] Sending email to first signer(s): {recipient_list_first} with link {sign_url}")

    #     html_content = render_to_string('esign/email_template_sign_request.html', {
    #         'doc_title': doc.title,
    #         'sign_url': sign_url,
    #         'user': "Saurav"
    #     })

    #     email = EmailMessage(
    #         subject=f"Please sign document: {subjectget}",
    #         body=html_content,
    #         from_email='sauravdahiya870@gmail.com',
    #         to=recipient_list_first,
    #         cc=cc_list
    #     )
    #     email.content_subtype = "html"
    #     email.attach(merged_filename, open(merged_path, 'rb').read(), 'application/pdf')
    #     email.send(fail_silently=False)
    #     print("[INFO] Email sent successfully to first signer(s)")

    messages.success(request, f"Bulk signing links sent for document {doc.pk}")
    print(f"[SUCCESS] Bulk signing links processed for document {doc.pk}")
    return redirect('document_detail', pk=pk)





def cancel_signing(request, token):
    if request.method == "POST":
        try:
            flow = DocumentSignFlow.objects.get(token=token)
        except DocumentSignFlow.DoesNotExist:
            return JsonResponse({"success": False, "message": "Invalid token."})

        # Optional reason from request
        import json
        data = json.loads(request.body.decode('utf-8'))
        reason = data.get("reason", "")

        # Check order
        if flow.order in [0, None]:
            flow.is_canceled = 1  # canceled
            flow.save()

            # Send email to document owner
            try:
                document = flow.document  # Assuming DocumentSignFlow has FK to Document as 'document'
                owner = document.owner

                subject = f"Document Cancelled:: {document.title}"

                # if you have a custom HTML email template, use it
                html_content = render_to_string('mails/document_cancelled_to_sign_email.html', {
                    'recipient_name': owner.get_full_name() or owner.username,
                    'assigner_name': "",
                    'document_title': document.title,
                    'site_url': settings.SITE_URL
                })

                # send email using EmailMessage
                # email_msg = EmailMessage(
                #     subject=subject,
                #     body=html_content,
                #     from_email=settings.DEFAULT_FROM_EMAIL,  # sender is the one assigning
                #     to=[owner.email],
                # )

                display_name = "Eazeesign Via Eazeesign"

                email_sent = send_email_safe(
                        request,
                        subject=subject,
                        body=html_content,
                        recipient_list=[owner.email],
                        from_email=f"{display_name} <{settings.DEFAULT_FROM_EMAIL}>"
                    )
                if not email_sent:
                    return redirect(request.path)  # Wapas same page


                # email_msg.content_subtype = "html"
                # email_msg.send(fail_silently=False)

            except Exception as e:
                # Log error but continue
                print(f"Email sending failed: {e}")

            return JsonResponse({"success": True})
        else:
            return JsonResponse({"success": False, "message": "You must sign in order. Cannot cancel yet."})
    return JsonResponse({"success": False, "message": "Invalid request."})

def assign_document(request, token):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)  # parse JSON
            email = data.get("assign_email")
            name = data.get("assign_name")
        except json.JSONDecodeError:
            return JsonResponse({"status": "error", "message": "Invalid JSON"}, status=400)

        if not email or not name:
            return JsonResponse({'status': 'error', 'message': 'Name and Email are required'}, status=400)

        # get original document flow by token
        st = get_object_or_404(DocumentSignFlow, token=token)

        # generate new token for assigned signer
        # new_token = secrets.token_urlsafe(16)
        new_token = get_random_string(32)
        # create a new flow record
        new_flow = DocumentSignFlow.objects.create(
            document=st.document,
            token=new_token,
            recipient_name=name,
            recipient_email=email,
            order=0,
            role='Signer'
        )
        st.assigned_by = new_flow.id
        st.save()

        signing_token = SigningToken.objects.get(document=st.document, token=token)
        SigningToken.objects.create(document=st.document, token=new_token, expires_at=signing_token.expires_at)
        # build document link
        # encoded_email = urlsafe_base64_encode(force_bytes(email))
        # document_link = f"{settings.SITE_URL}/document/sign/{new_token}/{encoded_email}"

        encoded_email = urlsafe_base64_encode(force_bytes(email))
        document_link = request.build_absolute_uri(reverse('sign_document', args=[new_token,encoded_email]))
        # prepare email content
        subject = f"You've been assigned a document to sign: {st.document.title if hasattr(st.document, 'title') else 'Document'}"

        # if you have a custom HTML email template, use it
        # html_content = render_to_string('mails/email_template_sign_request.html', {
        #     'recipient_name': name,
        #     'assigner_name': st.recipient_name,
        #     'document_title': getattr(st.document, 'title', 'Document'),
        #     'document_link': document_link,
        #     'site_url': settings.SITE_URL
        # })
        recipient_email = st.recipient_email  # e.g. "saurav.dahiya@gmail.com"
        user_name = recipient_email.split("@")[0]

        html_content = render_to_string('mails/email_template_sign_request.html', {
                    'doc_title': getattr(st.document, 'title', 'Document'),
                    'sign_url': document_link,
                    'name':  user_name
                    })
        # send email using EmailMessage
        # email_msg = EmailMessage(
        #     subject=subject,
        #     body=html_content,
        #     from_email=st.recipient_email,  # sender is the one assigning
        #     to=[email],
        # )
        # email_msg.content_subtype = "html"
        # email_msg.send(fail_silently=False)

        display_name = "Eazeesign Via Eazeesign"

        email_sent = send_email_safe(
                        request,
                        subject=subject,
                        body=html_content,
                        recipient_list=[st.recipient_email],
                        from_email=f"{display_name} <{settings.DEFAULT_FROM_EMAIL}>"
                    )
        if not email_sent:
            return redirect(request.path)  # Wapas same page


        return JsonResponse({'status': 'success', 'message': 'Document assigned and email sent successfully!'})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)



from django.http import HttpResponse, FileResponse
import os

@login_required
def download_document_files(request, pk):
    document = get_object_or_404(Document, pk=pk)
    download_option = request.POST.get('download_options')
    recipient_ids = request.POST.getlist('recipient_ids')

    files_to_download = []

    # Original document download
    if download_option == "original" and document.file:
        files_to_download.append(document.file.path)

    # All signed files
    elif download_option == "all_signed":
        flows = document.sign_flow.filter(is_signed=True)
        for f in flows:
            if f.merged_file:
                files_to_download.append(f.merged_file.path)

    # Individual recipient selection
    elif recipient_ids:
        flows = document.sign_flow.filter(pk__in=recipient_ids, is_signed=True)
        for f in flows:
            if f.merged_file:
                files_to_download.append(f.merged_file.path)

    if not files_to_download:
        return HttpResponse("No files selected or available.", status=400)

    import os, io, zipfile

    # Single file → direct PDF
    if len(files_to_download) == 1:
        file_path = files_to_download[0]
        filename = os.path.basename(file_path)
        return FileResponse(open(file_path, 'rb'), as_attachment=True, filename=filename)

    # Multiple files → ZIP
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zip_file:
        for file_path in files_to_download:
            filename = os.path.basename(file_path)
            zip_file.write(file_path, arcname=filename)
    zip_buffer.seek(0)

    return FileResponse(zip_buffer, as_attachment=True, filename=f"{document.title}_files.zip")



@login_required
def index(request):
    filter_period = request.GET.get('filter', 'today')
    now = timezone.now()

    # Determine date range
    filter_map = {
        'today': now.replace(hour=0, minute=0, second=0, microsecond=0),
        'last_week': now - timedelta(days=7),
        'last_month': now - timedelta(days=30),
        'this_year': now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0),
    }
    start_date = filter_map.get(filter_period)

    # Query documents
    docs_qs = Document.objects.filter(
        owner=request.user,
        is_template=False
    ).annotate(
        signer_count=Count('sign_flow')
    ).filter(
        signer_count__gt=0
    ).order_by('-created_at')

    if start_date:
        docs_qs = docs_qs.filter(created_at__gte=start_date)
    yesterday = (timezone.now() - timedelta(days=1)).date()

    total_docs = docs_qs.count()
    status_counts = {
        'signed': docs_qs.filter(status='signed').count(),
        'pending': docs_qs.filter(status='pending').count(),
        'expiring_soon': docs_qs.filter(valid_until__lte=now).count(),  # ← updated
    'expired': docs_qs.filter(valid_until__date=yesterday).count(),  # ← only yesterday's expired
        'declined': docs_qs.filter(status='cancelled').count(),
    }

    signatures_collected = status_counts['signed']
    expiring_soon = (
        docs_qs.filter(status='pending', expiry_date__lte=now + timedelta(days=7)).count()
        if hasattr(Document, 'expiry_date') else 0
    )
    templates_count = Document.objects.filter(owner=request.user, is_template=True).count()

    def pct(x): 
        return round((x / total_docs * 100), 1) if total_docs else 0
    from datetime import date

    subscription = Subscription.objects.filter(user=request.user, status='active').first()
    if subscription:
        days_left = (subscription.end_date.date() - date.today()).days
    else:
        days_left = 0

   

    data = {
        'filter_period': filter_period,
        'total_docs': total_docs,
        'signed_docs': status_counts['signed'],
        'pending_docs': status_counts['pending'],
        'expired_docs': status_counts['expired'],
        'declined_docs': status_counts['declined'],
        'signatures_collected': signatures_collected,
        'expiring_soon': status_counts['expiring_soon'],
        'templates_count': templates_count,
        # percentages
        'signed_percent': pct(status_counts['signed']),
        'pending_percent': pct(status_counts['pending']),
        'expired_percent': pct(status_counts['expired']),
        'signatures_percent': pct(signatures_collected),
        'expiring_percent': pct(status_counts['expiring_soon']),
        'completion_rate': pct(status_counts['signed']),
        'declined_percent': pct(status_counts['declined']),
        'subscription': subscription,
        'days_left': days_left,
    }

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return JsonResponse(data)

    return render(request, 'esign/index-dinesh.html', data)


import stripe
stripe.api_key = settings.STRIPE_SECRET_KEY

def checkout_view(request):
    return render(request, "payments/checkout.html", {
        "stripe_public_key": settings.STRIPE_PUBLIC_KEY
    })




from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.urls import reverse
import stripe, json
import razorpay

# @csrf_exempt
# def create_checkout_session(request):
#     try:
#         data = json.loads(request.body.decode('utf-8'))
#         name = data.get('name', 'Premium Plan')
#         currency = data.get('currency', 'usd')
#         plan = data.get('plan', 'premium')
#         amount = int(data.get('amount', 2000))  # in cents
#         interval = data.get('interval', 'month')  # "month" or "year"
#         mode = data.get('mode', 'subscription')  # can be "payment" or "subscription"

#         # ✅ Create price with recurring interval if subscription
#         if mode == 'subscription':
#             price = stripe.Price.create(
#                 unit_amount=amount,
#                 currency=currency,
#                 recurring={'interval': interval},
#                 product_data={'name': name},
#             )
#         else:
#             price = stripe.Price.create(
#                 unit_amount=amount,
#                 currency=currency,
#                 product_data={'name': name},
#             )

#         # ✅ Create checkout session
#         checkout_session = stripe.checkout.Session.create(
#             payment_method_types=['card'],
#             line_items=[{
#                 'price': price.id,
#                 'quantity': 1,
#             }],
#             mode=mode,
#             success_url=request.build_absolute_uri(reverse('stripe_success')) + '?session_id={CHECKOUT_SESSION_ID}',
#             cancel_url=request.build_absolute_uri(reverse('stripe_cancel')),
#             metadata={
#                 'plan': plan,
#                 'interval': interval,
#                 'user_email': request.user.email if request.user.is_authenticated else 'guest@example.com',
#             },
#         )

#         # Return direct checkout URL
#         return JsonResponse({'checkout_url': checkout_session.url})

#     except Exception as e:
#         return JsonResponse({'error': str(e)}, status=400)


@csrf_exempt
def create_checkout_session(request):
    try:
        data = json.loads(request.body.decode('utf-8'))

        # Plan / Payment Info
        plan_name = data.get('plan_name', 'Premium')
        plan = data.get('plan', 'premium')
        amount = int(float(data.get('amount', 2000))) * 100  # paise
        currency = data.get('currency', 'INR').upper()
        interval = data.get('interval', 'month')

        # Customer details
        first_name = data.get('f_name', '')
        last_name = data.get('l_name', '')
        email = data.get('email', '')

        phone = data.get('phone_number', '')
        if phone.startswith("0"):
            phone = phone[1:]    # remove leading zero



        # Razorpay client
        client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

        # Build only non-empty notes
        notes_data = {
            "plan_name": plan_name,
            "plan": plan,
            "interval": interval,
        }
        if first_name: notes_data["first_name"] = first_name
        if last_name: notes_data["last_name"] = last_name
        if email: notes_data["email"] = email
        if phone: notes_data["phone"] = phone

        # Create Razorpay Order
        order = client.order.create({
            "amount": amount,
            "currency": currency,
            "payment_capture": 1,
            "notes": notes_data
        })

        # Response to frontend
        return JsonResponse({
            "order_id": order["id"],
            "amount": amount,
            "currency": currency,
            "key_id": settings.RAZORPAY_KEY_ID,
            "customer": {
                "first_name": first_name,
                "last_name": last_name,
                "email": email,
                "phone": phone
            },
            "metadata": {
                "plan": plan,
                "interval": interval
            },
            "success_url": request.build_absolute_uri(reverse("razorpay_success")),
            "cancel_url": request.build_absolute_uri(reverse("razorpay_cancel")),
        })

    except Exception as e:
        print("RAZORPAY ERROR:", e)
        return JsonResponse({"error": str(e)}, status=400)

@csrf_exempt
def razorpay_success(request):
    try:
        # Razorpay returns POST values
        payment_id = request.POST.get("razorpay_payment_id")
        order_id = request.POST.get("razorpay_order_id")
        signature = request.POST.get("razorpay_signature")

        if not payment_id or not order_id or not signature:
            messages.error(request, "Invalid Razorpay response.")
            return redirect("register")

        # Razorpay verify signature
        client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
        params = {
            "razorpay_order_id": order_id,
            "razorpay_payment_id": payment_id,
            "razorpay_signature": signature
        }
        client.utility.verify_payment_signature(params)

        # -----------------------------------------------
        # 1️⃣ Fetch Order Notes (Customer + Plan info)
        # -----------------------------------------------
        order_data = client.order.fetch(order_id)
        notes = order_data.get("notes", {})

        # Fallback from POST (if needed)
        plan = notes.get("plan") or request.POST.get("plan", "premium")
        interval = notes.get("interval") or request.POST.get("interval", "month")

        # Customer details
        first_name = notes.get("first_name") or request.POST.get("first_name", "")
        last_name = notes.get("last_name") or request.POST.get("last_name", "")
        user_email = notes.get("email") or request.POST.get("email")
        phone = notes.get("phone") or request.POST.get("phone", "")

        if not user_email:
            user_email = "guest@example.com"

        # -----------------------------------------------
        # 2️⃣ Create User (Auto Password)
        # -----------------------------------------------
        import string
        email_prefix = user_email.split("@")[0]

        uppercase_letter = random.choice(string.ascii_uppercase)
        digit = random.choice(string.digits)
        special_char = "@"
        random_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
        password = f"{email_prefix[:3]}{uppercase_letter}{digit}{special_char}{random_part}"

        user, created = User.objects.get_or_create(
            email=user_email,
            defaults={
                "username": user_email,
                "first_name": first_name if first_name else email_prefix,
                "last_name": last_name,
                "is_active": True
            }
        )

        if created:
            user.set_password(password)
            user.save()

        # -----------------------------------------------
        # 3️⃣ Create Subscription Entry
        # -----------------------------------------------
        subscription, created_sub = Subscription.objects.get_or_create(
            razorpay_payment_id=payment_id,
            defaults={
                "user": user,
                "plan": plan,
                "stripe_payment_status": "succeeded",
                "amount_cents": order_data.get("amount_paid", 0),
                "currency": order_data.get("currency", "INR"),
                "status": Subscription.STATUS_ACTIVE
            }
        )

        subscription.set_active_dates()
        subscription.save()

        # -----------------------------------------------
        # 4️⃣ Send Email (Login Details)
        # -----------------------------------------------
        login_url = request.build_absolute_uri(f"/login/?email={user_email}")

        subject = "Your Subscription is Active!"
        html_content = render_to_string("mails/subscription_active_email.html", {
            "customer_email": user_email,
            "customer_first_name": first_name,
            "customer_last_name": last_name,
            "customer_phone": phone,
            "password": password,
            "plan": plan,
            "interval": interval,
            "login_url": login_url,
        })

        email = EmailMessage(
            subject=subject,
            body=html_content,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[user_email],
        )
        email.content_subtype = "html"
        email.send()

        # -----------------------------------------------
        # 5️⃣ Auto Login User
        # -----------------------------------------------
        login(request, user, backend='django.contrib.auth.backends.ModelBackend')

        return render(request, "payments/success.html")

    except razorpay.errors.SignatureVerificationError:
        messages.error(request, "Payment signature invalid.")
        return redirect("register")

    except Exception as e:
        messages.error(request, str(e))
        return redirect("register")

def razorpay_cancel(request):
    return render(request, "payments/cancel.html")


# @csrf_exempt
# def success_view(request):
#     """
#     Called after Stripe redirects to success_url.
#     Expects ?session_id=... in URL.
#     Retrieves Stripe session, then creates user & subscription record.
#     """
#     session_id = request.GET.get('session_id')
#     if not session_id:
#         messages.error(request, "Missing session id.")
#         return redirect('register')

#     try:
#         session = stripe.checkout.Session.retrieve(session_id, expand=['payment_intent', 'customer_details'])
#     except stripe.error.StripeError as e:
#         messages.error(request, f"Stripe error: {str(e)}")
#         return redirect('register')

#     # Get customer email
#     customer_email = (session.customer_details.email 
#                       if hasattr(session, 'customer_details') and session.customer_details 
#                       else session.customer_email or session.metadata.get('user_email'))
#     if not customer_email:
#         messages.error(request, "Could not determine customer email from Stripe session.")
#         return redirect('register')

#     # Get plan & amount from metadata
#     plan = session.metadata.get('plan', 'monthly')
#     interval = session.metadata.get('interval', 'month')
#     amount_cents = getattr(session, 'amount_total', None)
#     currency = getattr(session, 'currency', 'usd')
#     import string

#     # Create or get user
#     user, created = User.objects.get_or_create(
#         email=customer_email,
#         defaults={
#             'username': customer_email,
#             'first_name': session.metadata.get('user_name', customer_email.split('@')[0]),
#              'is_active': True,   # <- yahan set karo instead
#         }
#     )
#     email_prefix = customer_email.split('@')[0]
    
#     # Generate random components
#     uppercase_letter = random.choice(string.ascii_uppercase)
#     digit = random.choice(string.digits)
#     special_char = "@"
#     random_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
    
#     # Combine parts to form password
#     password = f"{email_prefix[:3]}{uppercase_letter}{digit}{special_char}{random_part}"

#     if created:
#         user.set_password(password)
#         user.save()

#     # Get PaymentIntent to check payment status
#     payment_intent_id = getattr(session, 'payment_intent', None)
#     payment_intent = stripe.PaymentIntent.retrieve(payment_intent_id) if payment_intent_id else None
#     payment_status = getattr(payment_intent, 'status', 'pending')

#     # Create or update subscription record
#     subscription, sub_created = Subscription.objects.get_or_create(
#         stripe_checkout_session_id=session_id,
#         defaults={
#             'user': user,
#             'plan': plan,
#             'status': Subscription.STATUS_ACTIVE if payment_status in ('succeeded', 'paid', 'complete') else Subscription.STATUS_PENDING,
#             'stripe_payment_intent_id': payment_intent_id,
#             'stripe_payment_status': payment_status,
#             'amount_cents': amount_cents,
#             'currency': currency,
#         }
#     )

#     if not sub_created:
#         subscription.user = user
#         subscription.plan = plan
#         subscription.stripe_payment_intent_id = payment_intent_id
#         subscription.stripe_payment_status = payment_status
#         subscription.amount_cents = amount_cents or subscription.amount_cents
#         subscription.currency = currency or subscription.currency
#         if payment_status in ('succeeded', 'paid', 'complete'):
#             subscription.status = Subscription.STATUS_ACTIVE
#             subscription.set_active_dates()
#         else:
#             subscription.status = Subscription.STATUS_PENDING
#         subscription.save()
#     else:
#         if subscription.status == Subscription.STATUS_ACTIVE:
#             subscription.set_active_dates()

#     # Send login email
#     # login_url = request.build_absolute_uri(f"/login/?email={customer_email}")
#     # subject = "Your Subscription is Active!"
#     # message = f"""
#     # Hi {customer_email},

#     # Your subscription ({plan}) is now active.

#     # Login Details:
#     # Email: {customer_email}
#     # Password: 12345

#     # Click the link below to login:
#     # {login_url}

#     # Thank you!
#     # """
#     # send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [customer_email], fail_silently=False)
#     login_url = request.build_absolute_uri(f"/login/?email={customer_email}")

#     # Send HTML email using EmailMessage
#     subject = "Your Subscription is Active!"
#     html_content = render_to_string("mails/subscription_active_email.html", {
#         "customer_email": customer_email,
#         "password":password,
#         "plan": plan,
#         "login_url": login_url,
#     })

#     email = EmailMessage(
#         subject=subject,
#         body=html_content,  # HTML content
#         from_email=settings.DEFAULT_FROM_EMAIL,
#         to=[customer_email],
#     )
#     email.content_subtype = "html"  # Important!
#     email.send(fail_silently=False)
    
#     # Log user in automatically
#     try:
#         login(request, user, backend='django.contrib.auth.backends.ModelBackend')
#     except Exception:
#         pass

#     messages.success(request, "Payment successful. Your account was created.")
#     return render(request, "payments/success.html")


def cancel_view(request):
    return render(request, "payments/cancel.html")

def testing(request):
    return render(request,'')
@csrf_exempt
def stripe_webhook(request):
    payload = request.body
    sig_header = request.META['HTTP_STRIPE_SIGNATURE']
    endpoint_secret = "your_webhook_secret"

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
    except (ValueError, stripe.error.SignatureVerificationError):
        return HttpResponse(status=400)

    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        print("Payment successful for:", session['customer_email'])

    return HttpResponse(status=200)
    
def buy_plain(request):
    if request.method == "GET":
        return render(request,'esign/plans_pricing.html')


def admin_view(request):
    if request.method == "GET":
        return render(request,'admin/admin_view.html')

        
def signup_basic(request):
    if request.method == "POST":
        email = request.POST.get("userEmail")

        if email:
            # user = User.objects.filter(email=email, is_active=True).first()

            user = User.objects.filter(email=email).first()

            if user and user.is_active:
                # User already active → cannot signup again
                messages.success(request, "Email already registered. Please log in instead.")
                request.session["signup_user_id"] = user.id  # optional
                return redirect('signup_basic')

            # If user doesn't exist → create new one
            otp = get_random_string(6, allowed_chars="0123456789")
            # username = email.split('@')[0] + get_random_string(4)  # e.g. 'john1234'

            # user = User.objects.create(
            #     username=username,
            #     email=email
            # )
            if not user:
                user = User.objects.create(
                    username=email,
                    email=email,
                    is_active=False
                )
            # Store info in session
            request.session["signup_email"] = email
            request.session["email_otp"] = otp
            request.session["signup_user_id"] = user.id
          
            name = email.split('@')[0]

            # html_content = render_to_string('mails/signup_otp_email.html', {
                
            #     'EXPIRY_MINUTES': "10",
            #     "name":name,
            #     'otp': otp,  # if you want to include OTP
            # })

            # Create EmailMessage
            # email1 = EmailMessage(
            #     subject="Your OTP Code",
            #     body=html_content,
            #     from_email=settings.DEFAULT_FROM_EMAIL,
            #     to=[email]         # recipient email
            # )
            # email1.content_subtype = "html"

            # # Send email
            # email1.send(fail_silently=False)
            # email_sent = send_email_safe(
            #         request,
            #         subject="Your OTP Code",
            #         body=html_content,
            #         recipient_list=[email],
            #         from_email=settings.DEFAULT_FROM_EMAIL
            #     )
            # if not email_sent:
            #     return redirect(request.path)  # Wapas same page
            


            return redirect(f"{reverse('signup_multi_step')}?email={email}")


        else:
            messages.error(request, "Please enter a valid email.")

    return render(request, "esign/signup.html")



def send_sms_otp(phone, otp):
    # Replace with real SMS sending logic
    print(f"Send SMS OTP {otp} to {phone}")
from django.contrib.auth.hashers import make_password , check_password

def signup_multi_step(request):
    step = int(request.POST.get('step', 0)) if request.method == 'POST' else 0
    email = request.GET.get('email') or request.session.get('signup_email', '')
    context = {'step': step,'email_prefill':email}
    if request.method == 'POST':
        if step == 1:
            print("Proper working")
            # Step 0: Collect basic info
            # email = request.POST.get('userEmail')
            phone_list = request.POST.getlist('userPhone')
            phone = phone_list[0] if phone_list else None
            print("phone",request.POST)
            context['mobile'] = phone
            request.session["signup_phone"] = phone
            # phone = request.POST.get('userPhone')

            first_name = request.POST.get('username')
            last_name = request.POST.get('userLastName')
            print("email",first_name,last_name,phone)
            try:
                user = User.objects.get(email=email)  # email ke base pe user fetch karna
                print("user",user)
                user.first_name = first_name
                user.last_name = last_name
               

                user.save()
                profile, created = Profile.objects.get_or_create(user=user)
                # agar phone field User model me nahi hai to ye optional hai:
                # if hasattr(user, 'phone'):
                profile.phone = phone
                profile.save()
                otp = get_random_string(6, allowed_chars="0123456789")
                html_content = render_to_string('mails/signup_otp_email.html', {
                
                'EXPIRY_MINUTES': "10",
                "name":first_name+" "+last_name,
                'otp': otp,  # if you want to include OTP
                })
                display_name = "Eazeesign Via Eazeesign"

                email_sent = send_email_safe(
                    request,
                    subject="Your OTP Code",
                    body=html_content,
                    recipient_list=[email],
                    from_email=f"{display_name} <{settings.DEFAULT_FROM_EMAIL}>"

                )
                if not email_sent:
                    return redirect(request.path)  # Wapas same page
                
                messages.success(request, f"An OTP has been sent to {email}. Please check your email.")

                
                # messages.success(request, "User details updated successfully!")

                # user mil gaya to hi session me id save karo
                request.session['signup_user_id'] = user.id

            except User.DoesNotExist:
                print("catch")
                messages.error(request, "User not found with this email.")
            context['step'] = 1
            return render(request, 'esign/signup_steps.html', context)
        
        elif step == 2:
            # Step 1: Verify Email OTP
            print("ojhbvbhjklkjn")
            otp = request.POST.get('emailVerificationCode')
            user_id = request.session.get('signup_user_id')
            user_otp = request.session.get('email_otp')
            print("user_id",user_id)
            user = User.objects.get(id=user_id)
            
            if str(user_otp) == str(otp):
                user.is_email_verified = True
                user.save()
                context['step'] = 3
            else:
                context['step'] = 1
                messages.error(request, f"Invalid email OTP. You entered: {user_otp} {otp}")
            
            return render(request, 'esign/signup_steps.html', context)
        
        elif step == 4:
            # Step 2: Verify Phone OTP
            otp = request.POST.get('phoneVerificationCode')
            user_id = request.session.get('signup_user_id')
            phone_otp = request.session.get('phone_otp')
            user = User.objects.get(id=user_id)
            
            if "123456" == otp:
                user.is_phone_verified = True
                user.save()
                context['step'] = 4
            else:
                messages.error(request, "Invalid phone OTP.")
                context['step'] = 3

            
            return render(request, 'esign/signup_steps.html', context)
        
        elif step == 5:
            # Step 3: Set Password
            password = request.POST.get('userPassword')
            user_id = request.session.get('signup_user_id')
            user = User.objects.get(id=user_id)
            
            # Set hashed password
            user.password = make_password(password)
            user.is_active = True  # ✅ Make user active
            user.save()
            
            # Create free trial subscription
            trial_days = 30  # free trial duration
            Subscription.objects.create(
                user=user,
                plan=Subscription.PLAN_FREE_TRIAL,
                status=Subscription.STATUS_ACTIVE,
                start_date=timezone.now(),
                end_date=timezone.now() + timedelta(days=trial_days),
                amount_cents=0,
                currency='usd',
            )

            # Auto-login user
            login(request, user)
            
            # Clean session
            if 'signup_user_id' in request.session:
                del request.session['signup_user_id']
                        
            messages.success(request, "Signup completed successfully!")
            
            # Redirect to index/dashboard
            return redirect('index')

    return render(request, 'esign/signup_steps.html', context)

import requests

@csrf_exempt
def send_mobile_otp(request):
    if request.method != "POST":
        return JsonResponse({"success": False, "message": "Invalid request. POST required."})

    phone = request.POST.get("phone")
    if not phone:
        return JsonResponse({"success": False, "message": "Phone number is required."})

    # Generate 6-digit OTP
    otp = random.randint(100000, 999999)

    # Store OTP in session
    request.session['mobile_otp'] = otp
    request.session['mobile_number'] = phone

    # Message to send
    message = f"Your OTP code is {otp}"

    # Sinch SMS GET API
    sms_sender_id = settings.SMS_SENDER_ID
    send_sms_url = (
        "https://push3.aclgateway.com/servlet/"
        "com.aclwireless.pushconnectivity.listeners.TextListener?"
        f"appid={settings.SINCH_APPID}"
        f"&userId={settings.SINCH_USERID}"
        f"&pass={settings.SINCH_PASSWORD}"
        "&contenttype=1"
        f"&from={sms_sender_id}"
        f"&to={phone}"
        f"&text={message}"
        "&alert=1&selfid=true"
    )

    try:
        response = requests.get(send_sms_url, timeout=10)
        # You can log response if needed
        return JsonResponse({"success": True, "message": "OTP sent successfully!", "response": response.text})
    except requests.exceptions.RequestException as e:
        return JsonResponse({"success": False, "message": f"Failed to send OTP: {str(e)}"})

def user_login1(request):
    step = int(request.POST.get('step', 0)) if request.method == 'POST' else 0
    email = request.POST.get('email') or request.session.get('login_email', '')
    context = {'stepInput': step, 'email_prefill': email}
    print(context)
    if request.method == 'POST':
        # 🧩 Step 0 → User entered email
        if step == 0:
            email = request.POST.get('email')
            try:
                user = User.objects.get(email=email)
                if user and user.is_active:
                    context['stepInput'] = 2  # Move to OTP verification step
                    return render(request, 'esign/login.html', context)
                else:
                    messages.error(request, "No user found with this email.")
                    context['stepInput'] = 0
                    return render(request, 'esign/login.html', context)
            except User.DoesNotExist:
                messages.error(request, "No user found with this email.")
                context['stepInput'] = 0
                return render(request, 'esign/login.html', context)

        
            context['stepInput'] = 2  # Move to OTP verification step
            return render(request, 'esign/login.html', context)

        # 🧩 Step 1 → Verify OTP
        elif step == 1:
            # email = request.session.get('login_email')
            password = request.POST.get('password')
            print("password",password,"email",email)
            # print("password",password)
            if not email or not password:
                messages.error(request, "Session expired or password missing.")
                context['stepInput'] = 0
                return render(request, 'esign/login.html', context)

            user = authenticate(request, username=email, password=password)
            if user:
                
                try:
                    phone = user.profile.phone
                except Profile.DoesNotExist:
                    phone = None  # or your default number
                print("📞 Phone:", phone)

                if phone:
                    # Password correct, user has phone number → continue verification
                    context['stepInput'] = 3
                    context['phone_prefill'] = phone[-4:]  # last 4 digits
                    messages.success(request, "Password verified! Please select verification method.")
                    return render(request, 'esign/login.html', context)
                else:
                    # User has no phone number → login and redirect to index
                    messages.success(request, "Password verified! Redirecting to dashboard.")
                    login(request, user)  # Django login
                    return redirect('index')  # redirect to index page
            else:
                # Password incorrect
                messages.error(request, "Incorrect password. Try again.")
                context['stepInput'] = 2
                return render(request, 'esign/login.html', context)

        # 🧩 Step 3 → Optional: Phone/email verification choice, etc.
        elif step == 2:
            # Example for choosing delivery method or extra verification
            method = request.POST.get('otpMethod')
            print("method",method)
            if method not in ['sms', 'call', 'email']:
                messages.success(request, "Please select a verification method.")
                context['stepInput'] = 3
            else:
                messages.success(request, f"You chose {method.upper()} for verification.")
                context['stepInput'] = 4  # For example, back to OTP step
                otp = random.randint(100000, 999999)
                request.session["login_otp"] = otp
                try:
                    user = User.objects.get(email=email)
                    phone = user.profile.phone
                except Profile.DoesNotExist:
                    phone = None  # or your default number
                print("📞 Phone:", phone)
                context['phone_prefill'] = phone[-4:] if phone else ''
                # if request.user.is_authenticated:
                    
                # else:
                #     context['phone_prefill'] = ''


            return render(request, 'esign/login.html', context)
        elif step == 3:
            # Step 4 → Verify OTP from SMS/Email
            login_otp = request.POST.get('loginOtp')
            session_login_otp = request.session.get('login_otp')  # OTP stored in session from step 0 or step 3
            # session_email = request.session.get('login_email')

            if not email or not session_login_otp:
                messages.error(request, "Session expired. Please start again.")
                context['stepInput'] = 0
                return redirect('user_login')

            if str(login_otp) == str(session_login_otp):
                try:
                    user = User.objects.get(email=email)
                except User.DoesNotExist:
                    context['stepInput'] = 0
                    messages.error(request, "User not found.")
                    return redirect('user_login')
                

                # Login the user
                login(request, user)
                messages.success(request, "Login successful via OTP!")
    
                # Clear session OTP
                request.session.pop('login_email', None)
                request.session.pop('login_otp', None)

                return redirect('index')
            else:
                messages.error(request, "Invalid OTP. Please try again. "+str(session_login_otp))
                context['stepInput'] = 4
                # context['step'] = 4  # Stay on the same step
                return render(request, 'esign/login.html', context)


    # GET request → default page
    return render(request, 'esign/login.html', context)
