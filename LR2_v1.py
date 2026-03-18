from flask import Flask, request, render_template, redirect, url_for, session, abort
import sqlite3
import hashlib
import os
import secrets
from functools import wraps

app = Flask(__name__)
# Секретний ключ зберігаємо в змінних середовища
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Конфігурація для безпеки
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = True  # Для HTTPS

# Декоратор для перевірки автентифікації
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Декоратор для перевірки прав адміністратора
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session or session['user'] != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# Функція для безпечної роботи з БД (використання параметризованих запитів)
def execute_query(query, params=None):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    if params:
        cursor.execute(query, params)
    else:
        cursor.execute(query)
    data = cursor.fetchall()
    conn.commit()
    conn.close()
    return data

# Функція для хешування паролів
def hash_password(password):
    # Використовуємо сіль для захисту від атак
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    password_hash = password_hash.hex()
    return (salt + password_hash.encode('ascii')).decode('ascii')

def verify_password(stored_password, provided_password):
    salt = stored_password[:64].encode('ascii')
    stored_password_hash = stored_password[64:]
    password_hash = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
    password_hash = password_hash.hex()
    return password_hash == stored_password_hash

# Генерація CSRF токена
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

# Ініціалізація БД
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)")
    
    # Паролі хешуються
    admin_password = hash_password('admin123')
    user_password = hash_password('userpass')
    
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ('admin', admin_password))
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)", ('user', user_password))
    
    cursor.execute("CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY, user_id INTEGER, account_number TEXT UNIQUE, balance INTEGER)")
    cursor.execute("INSERT OR IGNORE INTO accounts (user_id, account_number, balance) VALUES (1, 'ACC1001', 10000), (2, 'ACC1002', 5000)")
    
    cursor.execute("CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY, from_account TEXT, to_account TEXT, amount INTEGER, user_id INTEGER)")
    conn.commit()
    conn.close()

# Головна сторінка
@app.route('/')
def index():
    name = request.args.get('name', 'Guest')
    # Екранування виводу для запобігання XSS
    safe_name = escape_html(name)
    return f"<h1>Welcome to Payment Hub, {safe_name}!</h1><p>This is a secure app for educational purposes.</p>"

# Сторінка логіну
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Використання параметризованого запиту для запобігання SQL Injection
        query = "SELECT * FROM users WHERE username = ?"
        users = execute_query(query, (username,))
        
        if users and verify_password(users[0][2], password):
            session['user'] = username
            # Генеруємо новий CSRF токен при вході
            session['_csrf_token'] = secrets.token_hex(32)
            return redirect(url_for('dashboard'))
        else:
            return "Login failed"
    return render_template('login.html')

# Панель користувача
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=session['user'])

# Сторінка переказу
@app.route('/transfer', methods=['GET', 'POST'])
@login_required
def transfer():
    if request.method == 'POST':
        # Перевірка CSRF токена
        token = request.form.get('_csrf_token')
        if not token or token != session.get('_csrf_token'):
            abort(403)
        
        to_account = request.form['to_account']
        amount = request.form['amount']
        
        # IDOR - отримуємо рахунок користувача з БД, а не з форми
        user_query = "SELECT id FROM users WHERE username = ?"
        user_result = execute_query(user_query, (session['user'],))
        user_id = user_result[0][0]
        
        account_query = "SELECT account_number FROM accounts WHERE user_id = ?"
        account_result = execute_query(account_query, (user_id,))
        
        if not account_result:
            return "Account not found"
        
        from_account = account_result[0][0]
        
        # Перевіряємо чи існує рахунок отримувача
        check_account = "SELECT * FROM accounts WHERE account_number = ?"
        if not execute_query(check_account, (to_account,)):
            return "Destination account not found"
        
        # Перевіряємо баланс
        balance_query = "SELECT balance FROM accounts WHERE account_number = ?"
        balance_result = execute_query(balance_query, (from_account,))
        current_balance = balance_result[0][0]
        
        if int(amount) > current_balance:
            return "Insufficient funds"
        
        # Параметризований запит для запобігання SQL Injection
        # Використовуємо транзакцію для атомарності операцій
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        try:
            cursor.execute("BEGIN TRANSACTION")
            
            # Зменшуємо баланс відправника
            cursor.execute("UPDATE accounts SET balance = balance - ? WHERE account_number = ?", (amount, from_account))
            
            # Збільшуємо баланс отримувача
            cursor.execute("UPDATE accounts SET balance = balance + ? WHERE account_number = ?", (amount, to_account))
            
            # Записуємо транзакцію
            cursor.execute("INSERT INTO transactions (from_account, to_account, amount, user_id) VALUES (?, ?, ?, ?)",
                          (from_account, to_account, amount, user_id))
            
            cursor.execute("COMMIT")
            return f"Transfer successful! From {from_account} to {to_account}"
        except Exception as e:
            cursor.execute("ROLLBACK")
            return f"Transfer failed: {str(e)}"
        finally:
            conn.close()
    
    # Для GET запиту показуємо форму
    return render_template('transfer1.html', csrf_token=generate_csrf_token())

# Адмін-панель
@app.route('/admin', methods=['GET'])
@admin_required
def admin():
    return render_template('admin.html', csrf_token=generate_csrf_token())

# Оновлення налаштувань
@app.route('/admin/update', methods=['POST'])
@admin_required
def admin_update():
    # Перевірка CSRF токена
    token = request.form.get('_csrf_token')
    if not token or token != session.get('_csrf_token'):
        abort(403)
    
    site_name = request.form['site_name']
    # Екранування виводу
    safe_site_name = escape_html(site_name)
    return f"Site name updated to {safe_site_name}"

# API ендпоінт
@app.route('/api/user/<int:user_id>')
def api_user(user_id):
    # Параметризований запит
    query = "SELECT username FROM users WHERE id = ?"
    user = execute_query(query, (user_id,))
    
    if user:
        # Повертаємо JSON замість HTML для API
        return {"username": user[0][0]}
    else:
        return {"error": "User not found"}, 404

# Сторінка пошуку
@app.route('/search')
def search():
    query = request.args.get('q', '')
    # Екранування виводу
    safe_query = escape_html(query)
    return f"You searched for: {safe_query}"

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Допоміжна функція для екранування HTML
def escape_html(text):
    """Просте екранування HTML спецсимволів"""
    html_escape_table = {
        "&": "&amp;",
        '"': "&quot;",
        "'": "&apos;",
        ">": "&gt;",
        "<": "&lt;",
    }
    return "".join(html_escape_table.get(c, c) for c in text)

if __name__ == '__main__':
    init_db()
    # Вимкнення debug режиму в продакшені
    app.run(debug=False, host='0.0.0.0', port=5000)
