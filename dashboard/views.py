# dashboard/views.py
from django.shortcuts import render,get_object_or_404,redirect
from django.contrib.auth.models import User
from esign.models import Subscription
from django.db.models import Q
from django.core.paginator import Paginator
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test

def superuser_required(user):
    return user.is_superuser

def dashboard_home(request):
    return render(request, 'dashboard/home.html')

@user_passes_test(superuser_required, login_url='/login/')
def user_list(request):
    # Get search/filter parameters
    search_field = request.GET.get('search_field', '').strip()
    category = request.GET.get('category', '').strip()  # Plan filter
    status = request.GET.get('status', '').strip()      # Status filter

    users = User.objects.prefetch_related('subscription_set').filter(
            is_active=True
        ).exclude(id=request.user.id)
    # Apply search filter
    if search_field:
        users = users.filter(
            Q(username__icontains=search_field) |
            Q(first_name__icontains=search_field) |
            Q(last_name__icontains=search_field) |
            Q(email__icontains=search_field)
        )

    # Apply plan filter
    if category:
        users = users.filter(subscription__plan__iexact=category.lower())

    # Apply status filter
    if status:
        users = users.filter(subscription__status__iexact=status.lower())

    # Pagination
    paginator = Paginator(users.distinct(), 10)  # 10 users per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'users': page_obj,
        'search_field': search_field,
        'category': category,
        'status': status,
        'page_obj': page_obj,
    }

    return render(request, 'dashboard/admin_view.html', context)

def subscription_list(request):
    subscriptions = Subscription.objects.all()
    return render(request, 'dashboard/subscriptions.html', {'subscriptions': subscriptions})


def delete_user(request, user_id):
    if request.method == "POST":
        user = get_object_or_404(User, id=user_id)
        # Delete all subscriptions first
        user.subscription_set.all().delete()
        user.delete()
        messages.success(request, f"User {user.username} and their subscriptions have been deleted.")
    return redirect('dashboard:user_list')


