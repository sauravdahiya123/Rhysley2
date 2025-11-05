from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Document, Signature, SignaturePlacement, SigningToken,SignatureBox,SignaturePage,DocumentSignFlow,Profile,MarketingSource
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
from esign.utils.email_utils import get_from_email



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
            profile = Profile.objects.get(user__email=email)
            otp = random.randint(100000, 999999)
            profile.email_otp = otp
            profile.save()
            # Profile.objects.filter(user__email=email).update(otp=otp)

            print("profile",profile)

            send_mail(
                subject="Your new OTP",
                message=f"Your OTP is {otp}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )

            return JsonResponse({"success": True, "message": "OTP resent successfully!","otp":otp})
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
    return render(request,'esign/contact_us.html')


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
    if request.method == "POST":
        first_name = request.POST.get('username')
        last_name = request.POST.get('userLastName')
        email = request.POST.get('userEmail')
        phone = request.POST.get('userPhone')
        password = request.POST.get('userPassword')
        confirm_password = request.POST.get('confirmPasswordHelp')
        print("User create2")
        messages.get_messages(request)  # Clear old ones
        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            # return redirect('user_signup',{"post_data": request.POST})
            return render(request, "esign/signup.html", {"post_data": request.POST})

        print("User create1")

        if User.objects.filter(email=email).exists():
            messages.success(request, "User with this email already exists.")
            return redirect('user_login')
        print("User create")
        # Create user (inactive until OTP verified)
        user = User.objects.create_user(
            username=email,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            is_active=False
        )
        user.save()

        # Generate OTP
        otp = str(random.randint(100000, 999999))

        # Create Profile
        profile = Profile.objects.create(user=user, phone=phone, email_otp=otp)

        # Send OTP to email
        send_mail(
            subject='Your Email Verification OTP',
            message=f'Your OTP for account verification is {otp}',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )
        messages.get_messages(request)  # Clear old ones
        messages.success(request, f"OTP sent to {email} {otp}. Please verify your email.")
        return redirect('verify_otp', user_id=user.id)

    return render(request, 'esign/signup.html')




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
        if position == 1:
            recipient_list.append(email)
            token = token1
        
        

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
        return redirect('document_list')

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
        html_content = render_to_string('esign/email_template_sign_request.html', {
            'doc_title': doc.title,
            'sign_url': sign_url,
            'user': "Saurav"
            })
        print(recipient_list,"recipient_list")
        email = EmailMessage(
                subject=f"Please sign document: {subjectget}",
                body=html_content,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=recipient_list,
                cc=cc_list
            )
        email.content_subtype = "html"
        email.attach(merged_filename, open(merged_path, 'rb').read(), 'application/pdf')
        email.send(fail_silently=False)
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
            html_content = render_to_string('esign/email_template_sign_request.html', {
            'doc_title': doc.title,
            'sign_url': sign_url,
            'user': "Saurav"
            })
            print(recipient_list,"recipient_list")
            email = EmailMessage(
                subject=f"Please sign document: {subjectget}",
                body=html_content,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[i],
                cc=cc_list
            )
            email.content_subtype = "html"
            email.attach(merged_filename, open(merged_path, 'rb').read(), 'application/pdf')
            email.send(fail_silently=False)



    # print(f"[INFO] Signing URL: {sign_url} (token expires at {expires})")

    # Send email
    try:
       
        print(f"[INFO] Email sent successfully to: {recipient_list}, CC: {cc_list}")

        messages.success(request, f"Signing link sent to: {', '.join(recipient_list)}")
        if cc_list:
            messages.success(request, f"CC: {', '.join(cc_list)}")
    except Exception as e:
        messages.error(request, f"Failed to send email: {e}")
        print(f"[ERROR] Failed to send email: {e}")
    messages.success(request, "Link sent successfully!")  # ✅ set success message
    return redirect('document_list')









def sign_document(request, token, encoded_email=None):
    st = get_object_or_404(DocumentSignFlow, token=token)
    doc = st.document
    try:
        signing_token = SigningToken.objects.get(document=doc, token=token)

        # Compare both in UTC (Django handles timezone-aware datetimes internally)
        print('signing_token.expires_at',signing_token.expires_at,timezone.now(),'timezone.now()')
        if signing_token.expires_at.date() < timezone.now().date():
            # token expired
            return render(request, 'esign/token_invalid.html', {
                "message": "This signing link has expired."
            })

    except SigningToken.DoesNotExist:
        return render(request, 'esign/token_invalid.html', {
            "message": "Invalid signing token."
        })
    print("st",st)
    # Current flow
    try:
        flow = DocumentSignFlow.objects.get(document=doc, token=token)
    except DocumentSignFlow.DoesNotExist:
        return render(request, 'esign/token_invalid.html', {
            "message": "You are not authorized to sign this document."
        })

    # Already signed check
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
        saved_signatures = Signature.objects.filter(email=email)
    else:
        saved_signatures = Signature.objects.filter(email=email)

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
        'saved_signatures': saved_signatures,
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

            if p.get('signature_id'):
                sig = Signature.objects.get(pk=int(p['signature_id']))
                page.insert_image(fitz.Rect(x_pt, y_pt, x_pt + target_w, y_pt + target_h), filename=sig.image.path)
            elif p.get('base64'):
                header, b64 = p['base64'].split(',', 1)
                imgdata = base64.b64decode(b64)
                imgstream = BytesIO(imgdata)
                page.insert_image(fitz.Rect(x_pt, y_pt, x_pt + target_w, y_pt + target_h), stream=imgstream)

        # Save merged PDF to memory
        out = BytesIO()
        pdf.save(out)
        pdf.close()
        out.seek(0)

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
            
            html_content = render_to_string('esign/email_template_sign_request.html', {
                'doc_title': doc.title,
                'sign_url': sign_url,
                'user': next_flow.recipient_name,
                'merged_url': request.build_absolute_uri(flow.merged_file.url),
                'message': 'Your document has been signed and merged PDF is attached.'
            })
            # from_email = get_from_email(doc=doc)
            email = EmailMessage(
                subject=f"Document Signed: {doc.title}",
                body=html_content,
                # from_email='sauravdahiya870@gmail.com',
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=[next_flow.recipient_email]
            )
            email.content_subtype = "html"

            # Attach merged PDF
            flow.merged_file.open()
            email.attach(
                flow.merged_file.name.split('/')[-1],
                flow.merged_file.read(),
                'application/pdf'
            )

            email.send(fail_silently=False)

        # Optionally, send email to current signer as confirmation
        email_body_self = f"""
        Hello {flow.recipient_name},

        You have successfully signed the document: "{doc.title}".

        The merged PDF is attached for your reference.

        You can also access it here: {request.build_absolute_uri(flow.merged_file.url)}

        Thank you.
        """

        email_self = EmailMessage(
            subject=f"Document Signed: {doc.title}",
            body=email_body_self,
            from_email= settings.DEFAULT_FROM_EMAIL,
            to=[flow.recipient_email]
        )

        # email_self.content_subtype = "html"

        flow.merged_file.open()
        email_self.attach(
            flow.merged_file.name.split('/')[-1],
            flow.merged_file.read(),
            'application/pdf'
        )
        email_self.send(fail_silently=False)

        return JsonResponse({'ok': True, 'merged_url': flow.merged_file.url})

    except Exception as e:
        return JsonResponse({'ok': False, 'error': str(e)}, status=500)

def thankyou(request):
    return render(request,'esign/thank_you.html')


# @login_required
def upload_signature(request):
    if request.method == 'POST':
        data = json.loads(request.body.decode('utf-8'))
        img = data.get('image')
        name = data.get('name','')
        email = data.get('email')  # email is now required
        
        if not img:
            return JsonResponse({'ok': False, 'error': 'no image'}, status=400)
        header, b64 = img.split(',',1)
        imgdata = base64.b64decode(b64)
        user = request.user
        sig = Signature(email=email, name=name)
        sig.image.save(f'sig-{secrets.token_hex(6)}.png', ContentFile(imgdata))
        sig.save()
        return JsonResponse({'ok': True, 'id': sig.id, 'url': sig.image.url})
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
        
        html_content = render_to_string('esign/email_template_sign_request.html', {
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
                subject = f"Document Cancelled: {document.title}"
                message = f"Hello {owner.get_full_name() or owner.username},\n\n" \
                          f"The document titled '{document.title}' has been cancelled by the signer.\n"
                if reason:
                    message += f"Reason provided: {reason}\n"
                message += "\nPlease check the platform for more details.\n\nThanks,\nYour Company"
                
                send_mail(
                    subject,
                    message,
                    flow.recipient_email,  # from email
                    [owner.email],
                    fail_silently=False,
                )
            except Exception as e:
                # Log error but continue
                print(f"Email sending failed: {e}")

            return JsonResponse({"success": True})
        else:
            return JsonResponse({"success": False, "message": "You must sign in order. Cannot cancel yet."})
    return JsonResponse({"success": False, "message": "Invalid request."})


def assign_document(request, token):
    if request.method == "POST":
        # Get current flow
        st = get_object_or_404(DocumentSignFlow, token=token)
        if request.content_type == "application/json":
            try:
                data = json.loads(request.body)
                name = data.get('name')
                encoded_email = data.get('email')
                role=  ''
            except Exception:
                return JsonResponse({'success': False, 'message': 'Invalid JSON data.'})
        else:
            # Handle standard form POST
            name = request.POST.get('assigned_name')
            email_raw = request.POST.get('assigned_email')
            role = "viewer"
            if email_raw:
                encoded_email = urlsafe_base64_encode(force_bytes(email_raw))
            else:
                encoded_email = None

                
        try:
            email = urlsafe_base64_decode(encoded_email).decode()  # ✅ now plain email
        except Exception:
            return JsonResponse({'success': False, 'message': 'Invalid email encoding.'})

        print('encoded_email',encoded_email)
        if not name or not email:
            return JsonResponse({'success': False, 'message': 'Name and email are required.'})

        # Check signing order
        if st.order not in [0, 1]:
            return JsonResponse({
                'success': False,
                'message': 'You cannot assign this document. Signing order must be 0 or 1.'
            })

        # Prepare new token
        new_token = get_random_string(32)

        # Get last merged file from previous signed flow
        last_signed_flow = DocumentSignFlow.objects.filter(
            token=token
        ).first()

        print(last_signed_flow.recipient_email,"get email")
        print("last_signed_flow",last_signed_flow,email,token)
        merged_path = None
        merged_filename = None
        if last_signed_flow and last_signed_flow.merged_file:
            merged_path = last_signed_flow.merged_file.path
            merged_filename = last_signed_flow.merged_file.name.split('/')[-1]

        # Create new flow
        new_flow = DocumentSignFlow.objects.create(
            document=st.document,
            token=new_token,
            recipient_name=name,
            recipient_email=email,
            order=0,
            role=role
        )
        st.assigned_by = new_flow.id
        st.save()

        # Encode email for URL only
        encoded_email = urlsafe_base64_encode(force_bytes(email))
        sign_url = request.build_absolute_uri(
            reverse('sign_document', args=[new_token, encoded_email])
        )

        # Render email template
        html_content = render_to_string('esign/email_template_sign_request.html', {
            'doc_title': st.document.title if hasattr(st.document, 'title') else "Document",
            'sign_url': sign_url,
            'user': name
        })

        # Send email
        email_msg = EmailMessage(
            subject=f"Please sign document: {st.document.title if hasattr(st.document, 'title') else 'Document'}",
            body=html_content,
            from_email=last_signed_flow.recipient_email,
            to=[email],  # plain email, NOT encoded
        )
        email_msg.content_subtype = "html"

        # Attach merged file if exists
        if merged_path:
            with open(merged_path, 'rb') as f:
                email_msg.attach(merged_filename, f.read(), 'application/pdf')

        email_msg.send(fail_silently=False)

        return JsonResponse({'success': True})

    return JsonResponse({'success': False, 'message': 'Invalid request.'})


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
    }

    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return JsonResponse(data)

    return render(request, 'esign/index-dinesh.html', data)

    
     
@login_required
def ajax_filter_dashboard(request):
    filter_period = request.GET.get('filter', 'today')
    now = timezone.now()

    # Determine start date based on filter
    if filter_period == 'today':
        start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif filter_period == 'last_week':
        start_date = now - timedelta(days=7)
    elif filter_period == 'last_month':
        start_date = now - timedelta(days=30)
    elif filter_period == 'this_year':
        start_date = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
    else:
        start_date = None

    # Base queryset (same as index)
    docs_qs = Document.objects.filter(owner=request.user, is_template=False).order_by('-created_at')
    if start_date:
        docs_qs = docs_qs.filter(created_at__gte=start_date)

    # Compute all stats
    total_docs = docs_qs.count()
    signed_docs = docs_qs.filter(status='signed').count()
    pending_docs = docs_qs.filter(status='pending').count()
    expired_docs = docs_qs.filter(status='cancelled').count()
    signatures_collected = signed_docs

    expiring_soon = (
        docs_qs.filter(status='pending', expiry_date__lte=now + timedelta(days=7)).count()
        if hasattr(Document, 'expiry_date') else 0
    )

    templates_count = Document.objects.filter(owner=request.user, is_template=True).count()
    declined_docs = docs_qs.filter(status='cancelled').count()

    # Percentages
    signed_percent = (signed_docs / total_docs * 100) if total_docs else 0
    pending_percent = (pending_docs / total_docs * 100) if total_docs else 0
    expired_percent = (expired_docs / total_docs * 100) if total_docs else 0
    signatures_percent = (signatures_collected / total_docs * 100) if total_docs else 0
    expiring_percent = (expiring_soon / total_docs * 100) if total_docs else 0
    completion_rate = signed_percent
    declined_percent = (declined_docs / total_docs * 100) if total_docs else 0

    data = {
        'total_docs': total_docs,
        'signed_docs': signed_docs,
        'pending_docs': pending_docs,
        'expired_docs': expired_docs,
        'signatures_collected': signatures_collected,
        'expiring_soon': expiring_soon,
        'templates_count': templates_count,
        'declined_docs': declined_docs,
        'signed_percent': round(signed_percent, 1),
        'pending_percent': round(pending_percent, 1),
        'expired_percent': round(expired_percent, 1),
        'signatures_percent': round(signatures_percent, 1),
        'expiring_percent': round(expiring_percent, 1),
        'completion_rate': round(completion_rate, 1),
        'declined_percent': round(declined_percent, 1),
    }

    return JsonResponse(data)