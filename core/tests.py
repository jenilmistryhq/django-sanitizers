from django.test import TestCase, Client
import json

class SanitizerTests(TestCase):
    def setUp(self):
        self.client = Client()

    def test_json_sanitized(self):
        payload = {"bio": "<script>alert(1)</script><b>bold</b>"}
        r = self.client.post("/echo-json/", data=json.dumps(payload), content_type="application/json")
        self.assertEqual(r.status_code, 200)
        got = r.json()["received"]["bio"]
        # <script> removed, <b> preserved if allowed
        self.assertNotIn("<script>", got)
        self.assertIn("<b>", got)

    def test_post_form(self):
        r = self.client.post("/form-url/", {"name": "<img src=x onerror=alert(1) />Jenil"})
        self.assertEqual(r.status_code, 200)
        name = r.json()["name"]
        self.assertNotIn("onerror", name)
