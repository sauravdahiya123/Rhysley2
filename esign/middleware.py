from django.shortcuts import redirect
from django.http import HttpResponseNotFound
from django.http import Http404

class Handle404RedirectMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            response = self.get_response(request)
            # Agar normal 404 HTML response mila ho
            if response.status_code == 404:
                return redirect('/')  # redirect to dashboard
            return response
        except Http404:
            # Agar directly Http404 raise hua ho
            return redirect('/')
