# yourapp/utils/email_utils.py

def get_from_email(request=None, doc=None):
    """
    Returns the best possible 'from_email' for sending emails.
    Priority:
    1. Logged-in user's email (if request.user is authenticated)
    2. Document owner's email (if provided)
    3. Default no-reply address
    """
    # Case 1: Logged-in user
    if request and hasattr(request, "user") and request.user.is_authenticated and request.user.email:
        return request.user.email

    # Case 2: Document owner
    if doc and hasattr(doc, "owner") and getattr(doc.owner, "email", None):
        return doc.owner.email

    # Case 3: Fallback
    return "no-reply@esign.com"
