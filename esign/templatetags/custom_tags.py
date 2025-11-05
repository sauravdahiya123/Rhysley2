# esign/templatetags/custom_tags.py
from django import template

register = template.Library()

@register.filter
def to_range(start, end):
    return range(start, end + 1)



@register.filter
def has_pending(flows):
    return any(not f.is_signed for f in flows)