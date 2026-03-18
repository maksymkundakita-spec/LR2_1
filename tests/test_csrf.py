import requests

BASE_URL = "http://localhost:5000"

def test_csrf_admin_protected(flask_app):
    payload = {"site_name": "Hacked Site"}

    response = requests.post(f"{BASE_URL}/admin/update", data=payload)

    assert "Site name updated" not in response.text, \
        "CSRF атака спрацювала!"