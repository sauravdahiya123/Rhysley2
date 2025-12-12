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
    """
    Returns True if there is any pending flow:
    - For signers: not signed
    - For non-signers: considered only if is_viewed=False
    - Optionally: check assigned_by
    """
    return any(
        (f.role == "signer" and not f.is_signed)  # signer not signed → pending
        or (f.role != "signer" and not getattr(f, "is_viewed", True))  # non-signer not viewed → pending
        # Optional: add assigned_by check
        # and not getattr(f, "assigned_by", True)
        for f in flows
    )

@register.filter
def has_cancelled(flows):
    return any(f.is_canceled for f in flows)
