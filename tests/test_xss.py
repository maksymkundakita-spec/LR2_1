import requests

BASE_URL = "http://localhost:5000"

def test_xss_search_protected(flask_app):
    xss_payload = "<script>alert('XSS')</script>"
    
    response = requests.get(f"{BASE_URL}/search", params={"q": xss_payload})
    assert xss_payload not in response.text, "XSS вразливість у search!"

    response2 = requests.get(f"{BASE_URL}", params={"name": xss_payload})
    assert xss_payload not in response2.text, "XSS на головній сторінці!"