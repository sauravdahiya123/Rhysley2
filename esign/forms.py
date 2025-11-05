from django import forms
from .models import Document, Signature,ContactInquiry

class DocumentUploadForm(forms.ModelForm):
    valid_until = forms.DateTimeField(
        required=False,
        widget=forms.DateInput(
            attrs={
                'class': 'form-control',
                'type': 'datetime-local',  # HTML5 date-time picker
                'placeholder': 'Select valid until date'
            }
        ),
        help_text="Optional: Document is valid until this date"
    )

    class Meta:
        model = Document
        fields = ['title', 'file', 'category', 'valid_until']
        widgets = {
            'category': forms.Select(attrs={'class': 'form-select'})
        }
class SignatureUploadForm(forms.ModelForm):
    class Meta:
        model = Signature
        fields = ['image', 'name']



MARKETING_CHOICES = [
    ('Google Search', 'Google Search'),
    ('Business Event or Conference', 'Business Event or Conference'),
    ('Social Media', 'Social Media (Facebook, LinkedIn etc.)'),
    ('Blog or Article', 'Blog or Article'),
    ('Online Advertisement', 'Online Advertisement'),
    ('Email Campaign', 'Email Campaign'),
    ('Referral from a Friend or Colleague', 'Referral from a Friend or Colleague'),
    ('Others', 'Others'),
]

class MarketingForm(forms.Form):
    marketing_source = forms.ChoiceField(
        choices=MARKETING_CHOICES, 
        widget=forms.RadioSelect
    )


class ContactInquiryForm(forms.ModelForm):
    class Meta:
        model = ContactInquiry
        fields = ['name', 'email', 'phone', 'company_name']