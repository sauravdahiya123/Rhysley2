from django.conf import settings
from django.db import models
import uuid
from django.utils import timezone

class User(models.Model):
    email = models.EmailField(unique=True)
    
    
User = settings.AUTH_USER_MODEL

def upload_doc_path(instance, filename):
    return f'documents/{instance.owner.id}/{uuid.uuid4().hex}_{filename}'

def sig_image_path(instance, filename):
    # Replace "@" and "." in email to avoid filesystem issues
    safe_email = instance.email.replace('@', '_at_').replace('.', '_dot_')
    return f'signatures/{safe_email}/{uuid.uuid4().hex}.png'


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone = models.CharField(max_length=15, blank=True, null=True)
    email_otp = models.CharField(max_length=6, blank=True, null=True)
    mobile_otp = models.CharField(max_length=6, blank=True, null=True)
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return self.user.username


class Document(models.Model):
    STATUS_CHOICES = [
        ('pending','Pending'),
        ('signed','Signed'),
        ('approved','Approved'),
        ('cancelled','Cancelled'),
    ]
    TEMPLATE_CATEGORIES = [
        ('employment', 'Employment / HR'),
        ('legal', 'Legal / Compliance'),
        ('finance', 'Finance / Accounting'),
        ('sales', 'Sales / Marketing'),
        ('procurement', 'Procurement / Operations'),
        ('government', 'Government / Administrative'),
        ('education', 'Education / Training'),
        ('healthcare', 'Healthcare / Medical'),
        ('it', 'IT / Software'),
        ('misc', 'Miscellaneous / Personal'),
    ]
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='documents')
    title = models.CharField(max_length=250)
    file = models.FileField(upload_to=upload_doc_path)
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    merged_file = models.FileField(upload_to='merged/', null=True, blank=True)
    is_template = models.BooleanField(default=False)
    category = models.CharField(max_length=50, choices=TEMPLATE_CATEGORIES, default='misc')
    favorite_by = models.ManyToManyField(User, related_name='favorite_templates', blank=True)
    template_id = models.CharField(max_length=150, blank=True, null=True)
    valid_until = models.DateTimeField(
    null=True, 
    blank=True, 
    help_text="Document is valid until this date"
    )


    

    def __str__(self):
        return self.title

class Signature(models.Model):
    email = models.EmailField()  # now signature is linked to email
    image = models.ImageField(upload_to=sig_image_path)
    name = models.CharField(max_length=150, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    def __str__(self):
        return f'{self.email} signature {self.id}'

class SignaturePlacement(models.Model):
    document = models.ForeignKey(Document, related_name='placements', on_delete=models.CASCADE)
    signature = models.ForeignKey(Signature, on_delete=models.CASCADE, null=True, blank=True)
    page_number = models.PositiveIntegerField()
    x = models.FloatField()
    y = models.FloatField()
    width = models.FloatField()
    height = models.FloatField()
    placed_at = models.DateTimeField(auto_now_add=True)
    #  recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name="placements")
    # signed = models.BooleanField(default=False)
    # signature = models.ForeignKey(Signature, null=True, blank=True, on_delete=models.SET_NULL)


class SigningToken(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    token = models.CharField(max_length=128, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    def is_valid(self):
        return (not self.used) and timezone.now() < self.expires_at


class SignatureBox(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    page = models.IntegerField()
    x = models.FloatField()
    y = models.FloatField()
    width = models.FloatField()
    height = models.FloatField()
    type = models.CharField(max_length=20)  # 'signature' or 'stamp' or 'input'
    rotation = models.FloatField(default=0)
    color = models.CharField(max_length=20, default='#000000')  # store hex or rgb
    font_family = models.CharField(max_length=100, default='Arial')
    font_size = models.IntegerField(default=10)
    font_weight = models.CharField(max_length=20, default='normal')
    font_style = models.CharField(max_length=20, default='normal')
    text_decoration = models.CharField(max_length=20, default='none')
    # created_at = models.DateTimeField(auto_now_add=True)
    # updated_at = models.DateTimeField(auto_now=True)


class SignaturePage(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    page = models.CharField(max_length=20)  # 'signature' or 'stamp' or 'input'
    allowed = models.BooleanField(default=True)
    user_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='signaturespage',null=True, blank=True)
    token = models.CharField(max_length=64, db_index=True, null=True, blank=True)

class DocumentSignFlow(models.Model):
    ROLE_CHOICES = (
        ("signer", "Signer"),   # ✅ Can sign
        ("viewer", "Viewer"),   # ✅ Can only read
    )
    document = models.ForeignKey(Document, on_delete=models.CASCADE, related_name='sign_flow')
    token = models.CharField(max_length=64, unique=True)  # unique token per recipient
    recipient_name = models.CharField(max_length=255, blank=True, null=True)
    recipient_email = models.EmailField(blank=True, null=True)

    order = models.PositiveIntegerField()
    is_signed = models.BooleanField(default=False)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default="signer")  # ✅ NEW FIELD

    signed_at = models.DateTimeField(null=True, blank=True)
    merged_file = models.FileField(upload_to='signed_docs/', null=True, blank=True)  # new field
    is_canceled = models.BooleanField(default=False)  # ✅ new column for cancel/refuse
    assigned_at = models.DateTimeField(null=True, blank=True)
    assigned_by = models.CharField(max_length=255, blank=True, null=True)
    reminder_days = models.PositiveIntegerField(
        null=True,   # DB me NULL allow karega
        blank=True   # form/admin me blank allow karega
    )
    last_reminder_sent = models.DateTimeField(null=True, blank=True)
    next_reminder_sent = models.DateTimeField(null=True, blank=True)
    security_token = models.CharField(max_length=255, blank=True, null=True)


    class Meta:
        ordering = ['order']

class ContactInquiry(models.Model):
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, blank=True
    )
    name = models.CharField(max_length=255)
    email = models.EmailField()
    phone = models.CharField(max_length=50)
    company_name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.email}"
        

class MarketingSource(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    source = models.CharField(max_length=100)
    status = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.email} - {self.source}"







# Company Deatils 
# --------------------- Business / Subscription Models ---------------------

from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone

class Company(models.Model):
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL, 
        on_delete=models.CASCADE, 
        related_name='company_profile'
    )  # This user represents the company account
    name = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    class Meta:
        verbose_name = "Company"
        verbose_name_plural = "Companies"  # For sidebar
    def __str__(self):
        return self.name

class CompanyMembership(models.Model):
    ROLE_CHOICES = [('admin', 'Admin'), ('member', 'Member')]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='members')
    role = models.CharField(max_length=50, choices=ROLE_CHOICES, default='member')
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'company')
        verbose_name = "Company Membership"
        verbose_name_plural = "Company Memberships"


class SubscriptionPlan(models.Model):
    name = models.CharField(max_length=100, unique=True)
    price = models.DecimalField(max_digits=10, decimal_places=2, validators=[MinValueValidator(0)])
    duration_days = models.PositiveIntegerField(default=30)
    max_users = models.PositiveIntegerField(default=1)
    max_documents = models.PositiveIntegerField(default=100)

    class Meta:
        verbose_name = "Company Subscription"
        verbose_name_plural = "Company Subscriptions"

    def __str__(self):
        return self.name


class CompanySubscription(models.Model):
    company = models.ForeignKey(Company, on_delete=models.CASCADE, related_name='subscriptions')
    plan = models.ForeignKey(SubscriptionPlan, on_delete=models.SET_NULL, null=True)
    start_date = models.DateTimeField(null=True, blank=True)
    end_date = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Subscription Plan"
        verbose_name_plural = "Subscription Plans"

    def save(self, *args, **kwargs):
        # Set start_date if not set
        if not self.start_date:
            self.start_date = timezone.now()
        
        # Set end_date based on plan duration if not set
        if self.plan and not self.end_date:
            self.end_date = self.start_date + timezone.timedelta(days=self.plan.duration_days)
        
        super().save(*args, **kwargs)
