# utils/email_helper.py
from django.core.mail import EmailMessage
from django.contrib import messages
from smtplib import SMTPRecipientsRefused, SMTPAuthenticationError

def send_email_safe(request, subject, body, recipient_list, from_email):
    email1 = EmailMessage(
        subject=subject,
        body=body,
        from_email=from_email,
        to=recipient_list
    )
    email1.content_subtype = "html"

    try:
        email1.send(fail_silently=False)
        return True
    except SMTPAuthenticationError:
        messages.success(request, "Email authentication failed. Check email credentials.")
    except SMTPRecipientsRefused:
        messages.success(request, "Recipient email address is invalid.")
    except Exception as e:
        messages.success(request, "Something went wrong while sending email.")
        print("EMAIL ERROR:", str(e))
    return False
