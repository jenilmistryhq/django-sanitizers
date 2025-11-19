
# django-sanitizer

A lightweight, configurable Django middleware that **automatically sanitizes all incoming request data** (JSON, form-data, query params) to protect your application against **XSS, HTML injection, and unsafe attributes**.

Built with **Bleach**, easy to install, easy to extend, and safe by default.

---

## 🚀 Features

* 🔒 Sanitizes **JSON bodies**, **form-data**, and **query parameters**
* 🧼 Removes unsafe HTML tags, scripts, event handlers (e.g., `onerror`)
* 🎯 Fully configurable via Django settings
* 📝 Optional HTML response sanitization
* 🛠 Zero configuration required — works out of the box
* 🧪 Comes with testing utilities and easy middleware integration

---

## 📦 Installation

```bash
pip install django-sanitizer
```

Or install your local dev version:

```bash
pip install -e .
```

---

## ⚙️ Setup

Add the middleware to your Django settings:

```python
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django_sanitizer.middleware.SanitizerMiddleware",
    "django.middleware.common.CommonMiddleware",
    ...
]
```

---

## 🔧 Configuration Options (Optional)

Add to `settings.py` only if you want customization:

```python
SANITIZER_ENABLED = True

SANITIZER_ALLOWED_TAGS = [
    "b", "i", "u", "a", "em", "strong", "p",
    "ul", "ol", "li", "br", "img"
]

SANITIZER_ALLOWED_ATTRIBUTES = {
    "a": ["href", "title", "rel"],
    "img": ["src", "alt"],
}

SANITIZER_STRIP = True
SANITIZER_SANITIZE_RESPONSE_HTML = False
SANITIZER_DEBUG = False
```

---

## 🧪 Example

### Request Body:

```json
{
  "bio": "<script>alert(1)</script><b>Hello</b>"
}
```

### Sanitized Output:

```json
{
  "bio": "<b>Hello</b>"
}
```

---

## 🧪 Django Views Example

### JSON Example Endpoint

```python
# views.py
from django.http import JsonResponse

def echo_json(request):
    return JsonResponse(request.sanitized_data)
```

### Form Example Endpoint

```python
def form_view(request):
    return JsonResponse(request.sanitized_data)
```

---

## 🧪 Testing in Postman

### For JSON:

* Method: POST
* URL: `/echo-json/`
* Headers: `Content-Type: application/json`
* Body (raw JSON):

```json
{"bio":"<img src=x onerror=alert(1)>hello"}
```

You should receive:

```json
{"bio":"hello"}
```

---

## 🛡 How It Works

The middleware intercepts the request before it reaches your views:

1. Extracts request data (JSON, form-data, GET params)
2. Sanitizes all values using allowed tags + attributes
3. Places sanitized result in `request.sanitized_data`
4. Your view receives **only safe data**

This allows **cleaning without modifying Django internals**.

---

## 📁 Project Structure (Package Only)

```
django_sanitizer/
│
├── __init__.py
├── sanitizer.py
├── middleware.py
└── utils.py
```

---

## 🛠 Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

Run tests:

```bash
pytest
```

---

## 📦 Publishing to PyPI

```bash
python -m build
twine upload dist/*
```

---

## 📄 License

MIT License © 2025
Free to use, modify, and integrate into commercial apps.

---

## ⭐ Support the Project

If this package helps you, please ⭐ star the repository on GitHub once published!
