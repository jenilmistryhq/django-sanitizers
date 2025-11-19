from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse, HttpResponseBadRequest

@csrf_exempt
def echo_json(request):
    if request.content_type.split(";")[0] != "application/json":
        return HttpResponseBadRequest("Expecting JSON")
    # use sanitized_json set by middleware if available, else parse normally
    payload = getattr(request, "sanitized_json", None)
    if payload is None:
        import json
        payload = json.loads(request.body.decode())
    return JsonResponse({"received": payload})

@csrf_exempt
def form_view(request):
    if request.method == "POST":
        # request.POST is sanitized by middleware already
        name = request.POST.get("name")
        return JsonResponse({"name": name})
    return JsonResponse({"method": "send a POST"})
