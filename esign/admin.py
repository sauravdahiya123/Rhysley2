from django.contrib import admin
from .models import Document, Signature, SignaturePlacement, SigningToken,Company, CompanyMembership, SubscriptionPlan, CompanySubscription

# admin.site.register(Document)
# admin.site.register(Signature)
# admin.site.register(SignaturePlacement)
# admin.site.register(SigningToken)


from django.core.exceptions import ValidationError
from django.utils import timezone

from django.contrib.auth.models import Group
admin.site.site_header = "Esign Administration"      # Top-left header
admin.site.site_title = "Esign Admin Portal"         # Browser tab title
admin.site.index_title = "Welcome to Esign Admin"    # Index page title
admin.site.unregister(Group)

# --------------------- Inline Admins with Validation ---------------------
class CompanyMembershipInline(admin.TabularInline):
    model = CompanyMembership
    extra = 1
    readonly_fields = ('joined_at',)
    fields = ('user', 'role', 'joined_at')
    autocomplete_fields = ('user',)

    def clean(self):
        """
        Enforce subscription limits on max_users per company
        """
        super().clean()
        # Only enforce if parent object exists
        if hasattr(self, 'parent_object') and self.parent_object:
            company = self.parent_object
            # Get current active subscription
            active_sub = company.subscriptions.filter(is_active=True).first()
            if active_sub and active_sub.plan:
                max_users = active_sub.plan.max_users
                current_members = company.members.count()
                # Count the new members in this inline
                new_members = len([f for f in self.forms if f not in self.deleted_forms and f.cleaned_data])
                if current_members + new_members > max_users:
                    raise ValidationError(f"Cannot add more than {max_users} members as per the active subscription plan.")

class CompanySubscriptionInline(admin.TabularInline):
    model = CompanySubscription
    extra = 1
    readonly_fields = ('start_date', 'end_date')
    fields = ('plan', 'start_date', 'end_date', 'is_active')
    autocomplete_fields = ('plan',)

    def clean(self):
        """
        Ensure only one active subscription at a time
        """
        super().clean()
        if hasattr(self, 'parent_object') and self.parent_object:
            company = self.parent_object
            active_forms = [f for f in self.forms if f.cleaned_data.get('is_active') and f not in self.deleted_forms]
            if len(active_forms) + company.subscriptions.filter(is_active=True).count() > 1:
                raise ValidationError("A company can only have one active subscription at a time.")

# --------------------- Company Admin ---------------------
@admin.register(Company)
class CompanyAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'is_active', 'created_at', 'updated_at')
    list_filter = ('is_active', 'created_at')
    search_fields = ('name', 'user__email')
    ordering = ('-created_at',)
    readonly_fields = ('created_at', 'updated_at')
    inlines = [CompanyMembershipInline, CompanySubscriptionInline]


# --------------------- Subscription Plan Admin ---------------------
@admin.register(SubscriptionPlan)
class SubscriptionPlanAdmin(admin.ModelAdmin):
    list_display = ('name', 'price', 'duration_days', 'max_users', 'max_documents')
    list_filter = ('duration_days',)
    search_fields = ('name',)
    ordering = ('name',)

# --------------------- Company Membership Admin ---------------------
@admin.register(CompanyMembership)
class CompanyMembershipAdmin(admin.ModelAdmin):
    list_display = ('user', 'company', 'role', 'joined_at')
    list_filter = ('role', 'joined_at')
    search_fields = ('user__email', 'company__name')
    ordering = ('-joined_at',)
    readonly_fields = ('joined_at',)

# --------------------- Company Subscription Admin ---------------------
@admin.register(CompanySubscription)
class CompanySubscriptionAdmin(admin.ModelAdmin):
    list_display = ('company', 'plan', 'start_date', 'end_date', 'is_active')
    list_filter = ('is_active', 'start_date', 'end_date')
    search_fields = ('company__name', 'plan__name')
    ordering = ('-start_date',)
    readonly_fields = ('start_date',)
