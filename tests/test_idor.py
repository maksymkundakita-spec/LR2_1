import requests

BASE_URL = "http://localhost:5000"

def test_idor_transfer_protected():
    payload = {
        "from_account": "ACC1002",
        "to_account": "ACC9999",
        "amount": "1000"
    }

    session = requests.Session()
    session.post(f"{BASE_URL}/login", data={
        "username": "user",
        "password": "userpass"
    })

    response = session.post(f"{BASE_URL}/transfer", data=payload)

    assert "Transferred" not in response.text, \
        "IDOR: можна переказати з чужого рахунку!"
