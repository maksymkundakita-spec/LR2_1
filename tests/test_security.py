import requests
import pytest
import time
import threading
from LR2_1 import app

BASE_URL = "http://localhost:5000"


@pytest.fixture(scope="session")
def flask_app():
    """Запускає Flask додаток для тестування"""
    thread = threading.Thread(
        target=app.run,
        kwargs={'debug': False, 'use_reloader': False}
    )
    thread.daemon = True
    thread.start()
    time.sleep(2)
    yield


# SQL Injection (має бути ЗАХИЩЕНО)
def test_sql_injection_login_protected(flask_app):
    payload = {"username": "admin' --", "password": "anything"}
    response = requests.post(f"{BASE_URL}/login", data=payload)

    assert not (
        response.url == f"{BASE_URL}/dashboard" or "Welcome" in response.text
    ), "SQL Injection працює! Система НЕ захищена"


# XSS (має бути екранування)
def test_xss_search_protected(flask_app):
    xss_payload = "<script>alert('XSS')</script>"
    response = requests.get(f"{BASE_URL}/search", params={"q": xss_payload})

    assert xss_payload not in response.text, \
        "XSS вразливість у search!"

    response2 = requests.get(f"{BASE_URL}", params={"name": xss_payload})

    assert xss_payload not in response2.text, \
        "XSS на головній сторінці!"


# API має повертати безпечні дані (не HTML)
def test_xss_api_protected(flask_app):
    response = requests.get(f"{BASE_URL}/api/user/1")

    assert "<script>" not in response.text, \
        "XSS в API!"

    # краще перевірити що це JSON
    assert "application/json" in response.headers.get("Content-Type", ""), \
        "API повертає не JSON"


# IDOR має бути заблокований
def test_idor_transfer_protected(flask_app):
    payload = {
        "from_account": "ACC1002",
        "to_account": "ACC9999",
        "amount": "1000"
    }

    session = requests.Session()
    session.post(f"{BASE_URL}/login", data={"username": "user", "password": "userpass"})

    response = session.post(f"{BASE_URL}/transfer", data=payload)

    assert "Transferred" not in response.text, \
        "IDOR: можна переказати з чужого рахунку!"


# CSRF має бути захищений
def test_csrf_admin_protected(flask_app):
    payload = {"site_name": "Hacked Site"}

    response = requests.post(f"{BASE_URL}/admin/update", data=payload)

    assert "Site name updated" not in response.text, \
        "CSRF атака спрацювала!"


# Комбінована атака (SQL Injection)
def test_combined_sql_and_xss_protected(flask_app):
    payload = {"username": "' OR 1=1 --", "password": "anything"}

    response = requests.post(
        f"{BASE_URL}/login",
        data=payload,
        allow_redirects=False
    )

    assert response.status_code != 302, \
        "SQL Injection дозволяє логін!"
