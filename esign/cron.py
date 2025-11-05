from django.utils import timezone
from datetime import timedelta
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from .models import DocumentSignFlow

def send_pending_reminders():
    now = timezone.now()
    pending_flows = DocumentSignFlow.objects.filter(
        is_signed=False,
        is_canceled=False,
        next_reminder_sent__lte=now
    )

    for flow in pending_flows:
        doc = flow.document
        user_email = flow.recipient_email
        if not user_email:
            continue

        # Generate signing URL
        sign_url = f"http://yourdomain.com/sign/{flow.token}/"  # Replace with real logic

        html_content = render_to_string('esign/email_template_sign_request.html', {
            'doc_title': doc.title,
            'sign_url': sign_url,
            'user': flow.recipient_name or "User"
        })

        try:
            email = EmailMessage(
                subject=f"Reminder: Please sign document {doc.title}",
                body=html_content,
                from_email='noreply@yourdomain.com',
                to=[user_email]
            )
            email.content_subtype = "html"
            email.send(fail_silently=False)

            # Update reminders
            flow.last_reminder_sent = timezone.now()
            if flow.reminder_days:
                flow.next_reminder_sent = timezone.now() + timedelta(days=flow.reminder_days)
            flow.save()

            print(f"[INFO] Reminder sent to {user_email}")
        except Exception as e:
            print(f"[ERROR] Failed to send reminder to {user_email}: {e}")
