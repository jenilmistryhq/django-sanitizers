import bleach
from django.conf import settings

def sanitize(value):
    """
    Cleans potentially unsafe input using bleach based on Django settings.
    """
    # Fetch the main config dictionary from settings
    config = getattr(settings, 'SANITIZER_CONFIG', {})

    # Extract necessary values, providing secure defaults
    allowed_tags = config.get('ALLOWED_TAGS', [])
    allowed_attributes = config.get('ALLOWED_ATTRIBUTES', {})
    strip_flag = config.get('STRIP', True)

    if not isinstance(value, str):
        return value

    # Use the fetched configuration
    return bleach.clean(
        value,
        tags=allowed_tags,
        attributes=allowed_attributes,
        strip=strip_flag
    )