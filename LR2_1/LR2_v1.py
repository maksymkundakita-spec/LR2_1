from flask import Flask, request, render_template, redirect, url_for, session
import sqlite3

app = Flask(__name__)
app.secret_key = 'very-secret-key'

# Функція для роботи з БД (з SQL ін'єкцією)
def execute_query(query):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute(query)
    data = cursor.fetchall()
    conn.commit()
    conn.close()
    return data

# Ініціалізація БД
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'admin123'), ('user', 'userpass')")
    
    cursor.execute("CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY, user_id INTEGER, account_number TEXT, balance INTEGER)")
    cursor.execute("INSERT OR IGNORE INTO accounts (user_id, account_number, balance) VALUES (1, 'ACC1001', 10000), (2, 'ACC1002', 5000)")
    
    cursor.execute("CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY, from_account TEXT, to_account TEXT, amount INTEGER)")
    conn.commit()
    conn.close()

# Головна сторінка (вразлива до XSS)
@app.route('/')
def index():

    name = request.args.get('name', 'Guest')
    return f"<h1>Welcome to Payment Hub, {name}!</h1><p>This is a vulnerable app for educational purposes.</p>"

# Сторінка логіну (вразлива до SQL Injection)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        user = execute_query(query)
        
        if user:
            session['user'] = username
            return redirect(url_for('dashboard'))
        else:
            return "Login failed"
    return render_template('login.html')

# Панель користувача
@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return f"<h1>Welcome, {session['user']}!</h1><a href='/transfer'>Transfer</a> | <a href='/logout'>Logout</a>"
    return redirect(url_for('login'))

# Сторінка переказу (вразлива до IDOR)
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if request.method == 'POST':
        to_account = request.form['to_account']
        amount = request.form['amount']
        from_account = request.form['from_account']
        
        query = f"INSERT INTO transactions (from_account, to_account, amount) VALUES ('{from_account}', '{to_account}', {amount})"
        execute_query(query)
        return f"Transferred {amount} from {from_account} to {to_account}"
    
    # Для GET запиту показуємо форму
    return render_template('transfer.html')

# Адмін-панель (вразлива до CSRF)
@app.route('/admin', methods=['GET'])
def admin():
    return render_template('admin.html')


# Оновлення налаштувань (вразливе до CSRF)
@app.route('/admin/update', methods=['POST'])
def admin_update():
    site_name = request.form['site_name']
    return f"Site name updated to {site_name}"

# API ендпоінт (вразливий до XSS)
@app.route('/api/user/<int:user_id>')
def api_user(user_id):
    query = f"SELECT username FROM users WHERE id = {user_id}"
    user = execute_query(query)
    response_html = f"<div>Username: {user[0][0]}</div>" if user else "<div>User not found</div>"
    return response_html

# Сторінка пошуку (вразлива до XSS)
@app.route('/search')
def search():
    query = request.args.get('q', '')
    return f"You searched for: {query}"

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)