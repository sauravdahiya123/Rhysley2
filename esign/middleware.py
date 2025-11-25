from django.shortcuts import redirect
from django.http import Http404
from django.contrib import messages
from smtplib import SMTPRecipientsRefused, SMTPAuthenticationError

class Handle404RedirectMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            response = self.get_response(request)

            if hasattr(response, "status_code") and response.status_code == 404:
                return redirect('/')

            return response

        except Http404:
            return redirect('/')

        except SMTPRecipientsRefused:
            messages.error(request, "Invalid email address. Please try again.")
            return redirect(request.path)

        except SMTPAuthenticationError:
            messages.error(request, "Email authentication failed. Please check SMTP username/password.")
            return redirect(request.path)

        except Exception as e:
            print("GLOBAL ERROR:", str(e))
            messages.error(request, "Something went wrong. Please try again.")
            return redirect(request.path)
