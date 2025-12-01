import json
from django.conf import settings
from django.http import QueryDict
from .sanitizer import sanitize

class SanitizerMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.config = getattr(settings, 'SANITIZER_CONFIG', {})
        self.SKIP_FIELDS = set(self.config.get('SKIP_FIELDS', set())) 

    def __call__(self, request):
        if request.method in ("POST", "PUT", "PATCH"):
            content_type = request.content_type or ""

            # Handle JSON Payloads (PUT/PATCH/POST with application/json)
            if 'application/json' in content_type and request.body:
                try:
                    data = json.loads(request.body)
                    clean_data = self._walk_and_sanitize(data)
                    # Re-assign the cleaned data to request.body as bytes
                    request._body = json.dumps(clean_data).encode('utf-8')
                except json.JSONDecodeError:
                    pass

            # Handle Form Data (Standard POST submissions)
            elif request.POST:
                # Create a mutable copy efficiently
                q_dict = request.POST.copy()
                
                # We need to handle lists in QueryDicts
                for key in q_dict:
                    if key in self.SKIP_FIELDS: # Uses the user-defined config setting
                        continue
                        
                    values = q_dict.getlist(key)
                    cleaned_values = [self._sanitize_value(v) for v in values]
                    q_dict.setlist(key, cleaned_values)

                # Replace the immutable request.POST with our cleaned mutable version
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