import bleach

def sanitize(value):
    allowed_tags = ['b', 'i', 'u', 'strong', 'em']
    return bleach.clean(value, tags=allowed_tags, strip=True)
