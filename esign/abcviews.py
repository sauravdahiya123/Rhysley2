from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Document, Signature, SignaturePlacement, SigningToken,SignatureBox,SignaturePage,DocumentSignFlow
from .forms import DocumentUploadForm, SignatureUploadForm
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

def user_login(request):
    if request.user.is_authenticated:
        return redirect('index')

    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect('index')
        else:
            messages.error(request, "Invalid username or password")
    return render(request, 'esign/login.html')

def user_logout(request):
    logout(request)
    return redirect('user_login')

def user_signup(request):
    if request.method == "POST":
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists")
        else:
            user = User.objects.create_user(username=username, email=email, password=password)
            user.save()
            messages.success(request, "Account created! Please login.")
            return redirect('user_login')
    return render(request, 'esign/signup.html')



@login_required
def index(request):
    docs = Document.objects.filter(owner=request.user).order_by('-created_at')[:20]
    return render(request, 'esign/index.html', {'documents': docs})


@login_required
def upload_document(request):
    if request.method == 'POST':
        form = DocumentUploadForm(request.POST, request.FILES)
        if form.is_valid():
            doc = form.save(commit=False)
            doc.owner = request.user
            doc.save()
            return redirect('document_detail', pk=doc.pk)
    else:
        form = DocumentUploadForm()
    return render(request, 'esign/upload.html', {'form': form})


@login_required
def document_detail(request, pk):
    doc = get_object_or_404(Document, pk=pk)
    sigs = Signature.objects.filter(user=request.user)
    placements = SignaturePlacement.objects.filter(document=doc)
    users = get_user_model().objects.all().order_by('id')  # Or any ordering you want
    return render(request, 'esign/document_detail.html', {
        'document': doc,
        'signatures': sigs,
        'placements': placements,
        'users': users,
    })

# @login_required
def open_signing_link(request, pk):
    doc = get_object_or_404(Document, pk=pk)
    token = request.GET.get('token')

    return redirect('sign_document', token=token)


import io
@login_required
def send_signing_link(request, pk):
    print(f"[INFO] send_signing_link called for document pk={pk} by user={request.user}")
    payload = json.loads(request.POST.get('boxes', '{}'))

    print("Saurva get data",payload)
    doc = get_object_or_404(Document, pk=pk)

    # Recipients
    recipient_list = []
    print(request.POST)
    recipient_emails = request.POST.get('email[]', '')
    cc_emails = request.POST.get('cc_email', '')
    subjectget = request.POST.get('subject', '')
    print("Subject",subjectget)
    recipient_list = [e.strip() for e in recipient_emails.split(',') if e.strip()]
    cc_list = [e.strip() for e in cc_emails.split(',') if e.strip()]
    print(f"[INFO] Recipients: {recipient_list}, CC: {cc_list}")

    payload = json.loads(request.POST.get('boxes', '{}'))
    selected_pages = payload.get('allowed_pages', [])

    # selected_pages = json.loads(request.POST.get('selected_pages', '[]'))
    print(f"[INFO] Selected pages received: {selected_pages}")
    # Clear previous boxes & pages for this document
    SignatureBox.objects.filter(document=doc).delete()
    SignaturePage.objects.filter(document=doc).delete()

    order_postion_bulk1 = payload.get('order_postion_bulk', [])

    print(f"[INFO] Selected user IDs: {order_postion_bulk1}")

    # Delete existing sign flow for this document
    deleted_count, _ = DocumentSignFlow.objects.filter(document=doc).delete()
    print(f"[INFO] Deleted {deleted_count} existing sign flow entries for document {doc.id}")
    token  = None
    for order, recipient in enumerate(order_postion_bulk1, start=1):
        name = recipient.get("name")
        email = recipient.get("email")
        position = recipient.get("position", order)
        token = get_random_string(32)
        flow = DocumentSignFlow.objects.create(
                document=doc,
                token=token,
                recipient_name=name,
                recipient_email=email,
                order=position
            )
        if position == 1 and email:
            recipient_list.append(email)
    print("token start",token)
    print(f"[INFO] DocumentSignFlow creation completed for document {doc.id}")


    pages_str = ",".join(str(p) for p in selected_pages)

    # अब सिर्फ एक बार create करो
    SignaturePage.objects.create(
        document=doc,
        page=pages_str,
        allowed=True,
        user_id=request.user
    )



    if not recipient_list:
        messages.error(request, "Provide at least one valid recipient email.")
        print("[ERROR] No recipient emails provided.")
        return redirect('document_detail', pk=pk)

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
                rotation=box.get('rotation', 0)
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
    if token != None:
        sign_url = request.build_absolute_uri(reverse('sign_document', args=[token]))
    else:
        token = secrets.token_urlsafe(32)
        expires = timezone.now() + timedelta(days=2)
        SigningToken.objects.create(document=doc, token=token, expires_at=expires)
        sign_url = request.build_absolute_uri(reverse('sign_document', args=[token]))
        print(f"[INFO] Signing URL: {sign_url} (token expires at {expires})")

    print(sign_url,"sign_url")

    # Send email
    try:
        html_content = render_to_string('esign/email_template_sign_request.html', {
            'doc_title': doc.title,
            'sign_url': sign_url,
            'user': request.user
        })
        email = EmailMessage(
            # subject=f"Please sign document: {doc.title}",
            subject="Test",
            body=html_content,
            from_email='sauravdahiya870@gmail.com',
            to=recipient_list,
            cc=cc_list
        )
        email.content_subtype = "html"
        email.attach(merged_filename, open(merged_path, 'rb').read(), 'application/pdf')
        email.send(fail_silently=False)
        print(f"[INFO] Email sent successfully to: {recipient_list}, CC: {cc_list}")

        messages.success(request, f"Signing link sent to: {', '.join(recipient_list)}")
        if cc_list:
            messages.success(request, f"CC: {', '.join(cc_list)}")
    except Exception as e:
        messages.error(request, f"Failed to send email: {e}")
        print(f"[ERROR] Failed to send email: {e}")

    return redirect('document_detail', pk=pk)









# def sign_document(request, token):
#     st = get_object_or_404(SigningToken, token=token)
#     if not st.is_valid():
#         return render(request, 'esign/token_invalid.html')
#     doc = st.document
#     saved_signatures = Signature.objects.filter(user=doc.owner)
#     return render(request, 'esign/sign_page.html', {'document': doc, 'token': token, 'saved_signatures': saved_signatures})


from django.shortcuts import get_object_or_404, render
from django.contrib.auth.decorators import login_required
from esign.models import DocumentSignFlow, Signature, SignaturePage, SignatureBox



def sign_document(request, token):
    """
    Handles document signing. Checks DocumentSignFlow first (ordered signing),
    then SigningToken (direct access for owner/admin). Optimized version.
    """
    # 1️⃣ Check if token exists in signing flow
    flow_entry = DocumentSignFlow.objects.filter(token=token).first()
    if flow_entry:
        doc = flow_entry.document
        recipient_email = flow_entry.recipient_email
        signing_order = flow_entry.order

        # Check if previous users have signed
        previous_users = DocumentSignFlow.objects.filter(document=doc, order__lt=signing_order)
        can_sign = True
        message = None
        latest_pdf_url = flow_entry.document.merged_file.url if flow_entry.document.merged_file else flow_entry.document.file.url

        if previous_users.exists() and not all(u.is_signed for u in previous_users):
            can_sign = False
            message = "You cannot sign yet. Previous users in the signing order have not signed."

    # 2️⃣ If not in signing flow, check SigningToken
    else:
        st = get_object_or_404(SigningToken, token=token)
        latest_pdf_url = st.document
        doc = st.document
        recipient_email = None
        signing_order = None
        can_sign = True
        message = None

    
    # 3️⃣ Last merged PDF if available

    # 4️⃣ Saved signatures (if user logged in)
    saved_signatures = Signature.objects.filter(user=request.user) if request.user.is_authenticated else Signature.objects.none()

    # 5️⃣ Allowed pages
    allowed_pages_obj = SignaturePage.objects.filter(document=doc).first()
    allowed_pages_list = list(map(int, allowed_pages_obj.page.split(","))) if allowed_pages_obj and allowed_pages_obj.page else []

    # 6️⃣ Signature boxes
    signature_boxes = list(SignatureBox.objects.filter(document=doc)
                           .values('id', 'page', 'x', 'y', 'width', 'height', 'type', 'rotation'))

    context = {
        'document': doc,
        'token': token,
        'email': recipient_email,
        'saved_signatures': saved_signatures,
        'allowed_pages_list': allowed_pages_list,
        'signature_boxes': signature_boxes,
        'can_sign': can_sign,
        'signing_order': signing_order,
        'message': message,
        'latest_pdf_url': latest_pdf_url,
    }
 
    return render(request, 'esign/sign_page.html', context)


def apply_signatures(request):
    if request.method != 'POST':
        return JsonResponse({'ok': False, 'error': 'POST only'}, status=405)

    data = json.loads(request.body.decode('utf-8'))
    token_str = data.get('token')
    placements = data.get('placements', [])

    # Try SigningToken first (new flow), fallback to DocumentSignFlow (old flow)
    st = SigningToken.objects.filter(token=token_str).first()
    flow_entry = None
    doc = None

    if st:
        doc = st.document
        print("Sig")
    else:
        flow_entry = get_object_or_404(DocumentSignFlow, token=token_str)
        doc = flow_entry.document
        print("DIOCC")

    # Open PDF
    pdf_path = doc.merged_file.path if doc.merged_file else doc.file.path
    pdf = fitz.open(pdf_path)

    # Place signatures
    for p in placements:
        page_num = int(p['page'])
        page = pdf[page_num - 1]
        rect = page.rect

        x_pct = float(p.get('x_pct', 0))
        y_pct = float(p.get('y_pct', 0))
        w_pct = float(p.get('width_pct', 0.25))
        h_pct = float(p.get('height_pct', 0.1))

        target_w = rect.width * w_pct
        target_h = rect.height * h_pct
        x_pt = rect.x0 + rect.width * x_pct - target_w / 2
        y_pt = rect.y0 + rect.height * y_pct - target_h / 2

        if p.get('signature_id'):
            sig = get_object_or_404(Signature, pk=int(p['signature_id']))
            page.insert_image(fitz.Rect(x_pt, y_pt, x_pt + target_w, y_pt + target_h), filename=sig.image.path)
        elif p.get('base64'):
            header, b64data = p['base64'].split(',', 1)
            imgdata = base64.b64decode(b64data)
            page.insert_image(fitz.Rect(x_pt, y_pt, x_pt + target_w, y_pt + target_h), stream=BytesIO(imgdata))

    # Save merged PDF
    out = BytesIO()
    pdf.save(out)
    pdf.close()
    out.seek(0)
    merged_filename = f'merged-{doc.pk}-{secrets.token_hex(6)}.pdf'
    doc.merged_file.save(merged_filename, ContentFile(out.read()))
    out.close()

    # Mark token used
    if st:
        st.used = True
        st.save()

    # Mark document signed if all flows completed
    doc.status = 'signed'
    doc.save()
    print("flow_entry",flow_entry)
    # Update signing flow
    if flow_entry:
        flow_entry.is_signed = True
        flow_entry.signed_at = timezone.now()
        flow_entry.save()

        # Optional: send email to next signer in order
        next_flow = DocumentSignFlow.objects.filter(
            document=doc, order__gt=flow_entry.order, is_signed=False
        ).order_by('order').first()
        print(next_flow,"next_flow")
        if next_flow:
            print(next_flow,"next_flow enter")
            recipient_list = [next_flow.recipient_email]
            sign_url = request.build_absolute_uri(
                reverse('sign_document', args=[next_flow.user.pk])
            )
            html_content = render_to_string('esign/email_template_sign_request.html', {
                'doc_title': doc.title,
                'sign_url': sign_url,
                'user': DummyUser(next_flow.recipient_name)
            })
            with open(doc.merged_file.path, 'rb') as f:
                email = EmailMessage(
                    subject=f"Please sign document: {doc.title}",
                    body=html_content,
                    from_email='sauravdahiya870@gmail.com',
                    to=recipient_list,
                )
                email.content_subtype = "html"
                email.attach(merged_filename, f.read(), 'application/pdf')
                email.send(fail_silently=True)

    return JsonResponse({'ok': True, 'merged_url': doc.merged_file.url})

class DummyUser:
    def __init__(self, username):
        self.username = username


@login_required
def upload_signature(request):
    if request.method == 'POST':
        data = json.loads(request.body.decode('utf-8'))
        img = data.get('image')
        name = data.get('name','')
        if not img:
            return JsonResponse({'ok': False, 'error': 'no image'}, status=400)
        header, b64 = img.split(',',1)
        imgdata = base64.b64decode(b64)
        user = request.user
        sig = Signature(user=user, name=name)
        sig.image.save(f'sig-{secrets.token_hex(6)}.png', ContentFile(imgdata))
        sig.save()
        return JsonResponse({'ok': True, 'id': sig.id, 'url': sig.image.url})
    return JsonResponse({'ok': False, 'error': 'POST only'}, status=405)


@login_required
def delete_document(request, pk):
    doc = get_object_or_404(Document, pk=pk)
    if request.method == "POST":
        doc.delete()
        messages.success(request, f"Document '{doc.title}' deleted successfully.")
        return redirect('/')
    return redirect('/')



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