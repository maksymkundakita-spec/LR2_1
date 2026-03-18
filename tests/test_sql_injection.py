import requests

BASE_URL = "http://localhost:5000"

def test_sql_injection_login_protected(flask_app):
    payload = {"username": "admin' --", "password": "anything"}
    response = requests.post(f"{BASE_URL}/login", data=payload)

    assert not (
        response.url == f"{BASE_URL}/dashboard" or "Welcome" in response.text
    ), "SQL Injection працює! Система НЕ захищена"
