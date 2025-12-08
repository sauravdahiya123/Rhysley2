# esign/templatetags/custom_tags.py
from django import template

register = template.Library()

@register.filter
def to_range(start, end):
    return range(start, end + 1)



# @register.filter
# def has_pending(flows):
#     return any(not f.is_signed for f in flows)


# @register.filter
# def has_pending(flows):
#     return any((not f.is_signed) and (not f.is_canceled) for f in flows)


@register.filter
def has_pending(flows):
    return any(
        (not f.is_signed)
        and (not f.is_canceled)
        and (not getattr(f, "is_viewed", True))
        and (not getattr(f, "assigned_by", True))
        for f in flows
    )
