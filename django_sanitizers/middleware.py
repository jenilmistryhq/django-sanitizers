import json
from django.conf import settings
from .sanitizer import sanitize

class SanitizerMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.config = getattr(settings, 'SANITIZER_CONFIG', {})
        # Pre-calculate skip fields for O(1) lookup
        self.SKIP_FIELDS = set(self.config.get(
            'SKIP_FIELDS', 
            # Default includes the critical fields if config is missing
            {'password', 'password_confirmation', 'token', 'access_token', 'refresh_token'}
        ))

    def __call__(self, request):
        # We only care about methods that transmit data
        if request.method in ("POST", "PUT", "PATCH"):
            content_type = getattr(request, 'content_type', '') or request.META.get('CONTENT_TYPE', '')

            # Handle JSON Payloads
            if 'application/json' in content_type and request.body:
                try:
                    data = json.loads(request.body)
                    clean_data = self._walk_and_sanitize(data)
                    # Re-assign the cleaned data to request._body
                    # We must use _body because request.body is a property in newer Django
                    request._body = json.dumps(clean_data).encode('utf-8')
                except json.JSONDecodeError:
                    # If JSON is malformed, we let the view handle the error
                    pass

            # Handle Form Data (Standard POST)
            # We check request.POST specifically. Note: This reads the stream.
            elif request.POST:
                q_dict = request.POST.copy() 
                
                for key in q_dict:
                    if key in self.SKIP_FIELDS:
                        continue
                    
                    values = q_dict.getlist(key)
                    cleaned_values = [self._sanitize_value(v) for v in values]
                    q_dict.setlist(key, cleaned_values)

                q_dict._mutable = False
                request.POST = q_dict

        return self.get_response(request)

    def _walk_and_sanitize(self, data):
        """
        Recursively walks through dictionaries and lists to sanitize strings.
        """
        if isinstance(data, dict):
            return {
                # Uses the configurable self.SKIP_FIELDS here
                k: (v if k in self.SKIP_FIELDS else self._walk_and_sanitize(v)) 
                for k, v in data.items()
            }
        if isinstance(data, list):
            return [self._walk_and_sanitize(item) for item in data]
        if isinstance(data, str):
            return self._sanitize_value(data)
        return data

    def _sanitize_value(self, value):
        """
        Wrapper to ensure we only sanitize strings and handle potential errors.
        """
        if isinstance(value, str):
            return sanitize(value)
        return value