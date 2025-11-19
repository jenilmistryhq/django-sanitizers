# core/middleware/sanitizer.py
import io
import json
from django.conf import settings
from django.http import QueryDict, HttpResponse
from django.utils.deprecation import MiddlewareMixin  # compatible helper import
import bleach

def _get_setting(name, default):
    return getattr(settings, name, default)

ALLOWED_TAGS = _get_setting("SANITIZER_ALLOWED_TAGS", ["b","i","u","em","strong","a","br","p","ul","ol","li"])
ALLOWED_ATTRS = _get_setting("SANITIZER_ALLOWED_ATTRIBUTES", {"a": ["href", "title", "rel"]})
STRIP = _get_setting("SANITIZER_STRIP", True)
SANITIZE_RESPONSE_HTML = _get_setting("SANITIZER_SANITIZE_RESPONSE_HTML", False)
DEBUG = _get_setting("SANITIZER_DEBUG", False)

def sanitize_value(value):
    """
    Recursively sanitize strings inside structures.
    - Leaves bytes and file-like objects untouched.
    """
    # strings
    if isinstance(value, str):
        cleaned = bleach.clean(value, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=STRIP)
        if DEBUG and cleaned != value:
            try:
                print(f"[sanitizer] changed: {value!r} -> {cleaned!r}")
            except Exception:
                pass
        return cleaned

    # dict-like
    if isinstance(value, dict):
        return {k: sanitize_value(v) for k, v in value.items()}

    # list/tuple
    if isinstance(value, (list, tuple)):
        t = [sanitize_value(v) for v in value]
        return type(value)(t)

    # other primitives (int/float/bool/None) -> leave as-is
    return value


class SanitizerMiddleware:
    """
    New-style middleware (callable). Sanitizes GET/POST and JSON request bodies.
    It also optionally sanitizes HTML HttpResponse.content.
    """
    def __init__(self, get_response):
        self.get_response = get_response
        self.enabled = getattr(settings, "SANITIZER_ENABLED", True)

    def __call__(self, request):
        if not self.enabled:
            return self.get_response(request)

        # 1) sanitize GET - QueryDict is immutable, so create a copy
        if request.GET:
            try:
                qd = request.GET.copy()
                for k in list(qd.keys()):
                    values = qd.getlist(k)
                    sanitized_values = [sanitize_value(v) for v in values]
                    qd.setlist(k, sanitized_values)
                request.GET = qd
            except Exception:
                # never break request processing; fail safe
                pass

        # 2) sanitize POST (form-encoded)
        # If content-type is form data, request.POST becomes a QueryDict populated from request._stream
        if request.method in ("POST", "PUT", "PATCH") and request.content_type:
            ct = request.content_type.split(";")[0]
            if ct in ("application/x-www-form-urlencoded", "multipart/form-data"):
                try:
                    if hasattr(request, "POST"):
                        pd = request.POST.copy()
                        # skip file inputs (they are in request.FILES)
                        for k in list(pd.keys()):
                            values = pd.getlist(k)
                            sanitized_values = [sanitize_value(v) for v in values]
                            pd.setlist(k, sanitized_values)
                        # assign modified QueryDict back
                        request.POST = pd
                except Exception:
                    pass

        # 3) sanitize JSON body (application/json)
        if request.method in ("POST", "PUT", "PATCH") and getattr(request, "body", None):
            try:
                ct = request.content_type.split(";")[0] if request.content_type else ""
                if ct == "application/json":
                    raw = request.body
                    # parse and sanitize
                    parsed = json.loads(raw.decode("utf-8") if isinstance(raw, (bytes, bytearray)) else raw)
                    sanitized = sanitize_value(parsed)
                    sanitized_bytes = json.dumps(sanitized).encode("utf-8")
                    # replace request._body and request._stream so downstream sees sanitized body
                    request._body = sanitized_bytes
                    request._stream = io.BytesIO(sanitized_bytes)
                    # also set a convenience attribute
                    request.sanitized_json = sanitized
            except Exception:
                # if parsing fails, do nothing
                pass

        # Keep going to view
        response = self.get_response(request)

        # 4) Optionally sanitize HTML response content
        if SANITIZE_RESPONSE_HTML and isinstance(response, HttpResponse):
            try:
                content_type = response.get("Content-Type", "").split(";")[0]
                if content_type == "text/html" and response.content:
                    original = response.content.decode(response.charset or "utf-8")
                    cleaned = bleach.clean(original, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRS, strip=STRIP)
                    if cleaned != original:
                        response.content = cleaned.encode(response.charset or "utf-8")
                        # adjust Content-Length if present
                        if response.has_header("Content-Length"):
                            response["Content-Length"] = str(len(response.content))
            except Exception:
                pass

        return response
