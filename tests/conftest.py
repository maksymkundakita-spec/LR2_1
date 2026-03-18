import pytest
import time
import threading
from LR2_v1 import app

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
