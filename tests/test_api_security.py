import requests

BASE_URL = "http://localhost:5000"

def test_xss_api_protected():
    response = requests.get(f"{BASE_URL}/api/user/1")

    assert "<script>" not in response.text, "XSS в API!"

    assert "application/json" in response.headers.get("Content-Type", ""), \
        "API повертає не JSON"
