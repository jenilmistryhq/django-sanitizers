from .sanitizer import sanitize

class SanitizerMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method in ("POST", "PUT", "PATCH"):
            if request.body:
                for key, value in request.POST.items():
                    request.POST._mutable = True
                    request.POST[key] = sanitize(value)
                    request.POST._mutable = False

        return self.get_response(request)
