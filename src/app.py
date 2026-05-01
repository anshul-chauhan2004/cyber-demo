from flask import Flask, render_template, request, session, redirect, url_for, g
import sqlite3
from markupsafe import Markup

app = Flask(__name__)
# Intentionally using a weak secret key for demonstration purposes
app.secret_key = 'super_secret_group_5_key' 

DATABASE = 'demo.db'

def get_db():
    """Connect to the SQLite database."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Close the database connection at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initialize the database with some dummy data for our hacks."""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # Create users table
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT, 
                            username TEXT, 
                            password TEXT, 
                            balance REAL)''')
        
        # Check if we need to seed the database
        cursor.execute("SELECT COUNT(*) FROM users")
        if cursor.fetchone()[0] == 0:
            # Seed our vulnerable database with Plaintext passwords (!)
            cursor.execute("INSERT INTO users (username, password, balance) VALUES ('admin', 'admin123', 1000000.00)")
            cursor.execute("INSERT INTO users (username, password, balance) VALUES ('bob', 'bobpass', 500.00)")
            cursor.execute("INSERT INTO users (username, password, balance) VALUES ('alice', 'alicepass', 750.00)")
            db.commit()
            print("Database initialized with seed data.")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/sqli', methods=['GET', 'POST'])
def sqli():
    query_str = ""
    result = None
    error = None
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        mode = request.form.get('mode', 'vulnerable')
        
        db = get_db()
        cursor = db.cursor()
        
        try:
            if mode == 'vulnerable':
                # VULNERABLE: Direct string formatting allows malicious input to alter the SQL logic
                query_str = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
                cursor.execute(query_str)
            else:
                # SECURE: Parameterized queries treat input purely as data, not executable code
                query_str = "SELECT * FROM users WHERE username=? AND password=?   -- [Parameters attached safely by engine]"
                cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
            
            user = cursor.fetchone()
            if user:
                result = f"Success! Logged in as: {user['username']} (Balance: ${user['balance']})"
            else:
                error = "Invalid credentials."
        except Exception as e:
            error = f"Database Error: {str(e)}"
            
    return render_template('sqli.html', query_str=query_str, result=result, error=error)

@app.route('/xss', methods=['GET', 'POST'])
def xss():
    search_query = ""
    result = ""
    mode = "vulnerable"
    
    if request.method == 'POST':
        search_query = request.form.get('search_query', '')
        mode = request.form.get('mode', 'vulnerable')
        
        if search_query:
            if mode == 'vulnerable':
                # VULNERABLE: Using Markup() bypasses Jinja2's auto-escaping, 
                # allowing raw HTML and JavaScript to be rendered in the DOM.
                result = Markup(search_query)
            else:
                # SECURE: Flask/Jinja2 automatically escapes variables by default.
                # '<' becomes '&lt;', making scripts harmless text.
                result = search_query

    return render_template('xss.html', search_query=search_query, result=result, mode=mode)

@app.route('/idor', methods=['GET', 'POST'])
def idor():
    # We mock a hardcoded session where the user is currently logged in as 'bob' (ID: 2)
    current_session_user_id = 2 
    
    target_id = ""
    result = None
    error = None
    mode = "vulnerable"
    
    if request.method == 'POST':
        target_id = request.form.get('target_user_id', '')
        mode = request.form.get('mode', 'vulnerable')
        
        try:
            target_id_int = int(target_id)
            db = get_db()
            cursor = db.cursor()
            
            if mode == 'vulnerable':
                # VULNERABLE: The server fetches the record purely based on user input (target_id)
                # It completely ignores the current_session_user_id!
                cursor.execute("SELECT * FROM users WHERE id=?", (target_id_int,))
                user = cursor.fetchone()
                if user:
                    result = f"Statement retrieved! User: {user['username']} - Balance: ${user['balance']}"
                else:
                    error = "User ID not found."
            else:
                # SECURE: Access Control validation!
                # The server explicitly checks if the requested ID matches the authenticated session ID.
                if target_id_int != current_session_user_id:
                    error = "🚨 403 Forbidden: You do not have permission to view this statement."
                else:
                    cursor.execute("SELECT * FROM users WHERE id=?", (target_id_int,))
                    user = cursor.fetchone()
                    if user:
                        result = f"Statement retrieved! User: {user['username']} - Balance: ${user['balance']}"
                    else:
                        error = "User not found."
        except ValueError:
            error = "Please enter a valid numeric ID."

    return render_template('idor.html', current_user_id=current_session_user_id, target_id=target_id, result=result, error=error, mode=mode)

@app.route('/logic', methods=['GET', 'POST'])
def logic():
    # Mocking the session: Logged in as 'bob' (ID: 2)
    current_session_user_id = 2 
    
    result = None
    error = None
    mode = "vulnerable"
    
    if request.method == 'POST':
        # the 'from_account' simulates a hidden HTML field the user tampered with
        from_account = request.form.get('from_account', '') 
        to_account = request.form.get('to_account', '')
        amount_str = request.form.get('amount', '0')
        mode = request.form.get('mode', 'vulnerable')
        
        try:
            amount = float(amount_str)
            target_to = int(to_account)
            
            db = get_db()
            cursor = db.cursor()
            
            if mode == 'vulnerable':
                # VULNERABLE: The server trusts the client's form data to dictate where the money comes from!
                actual_from = int(from_account)
            else:
                # SECURE: The server ignores the client's claim and forces the source account to be the logged-in session.
                actual_from = current_session_user_id
                
            cursor.execute("SELECT username FROM users WHERE id=?", (actual_from,))
            from_user = cursor.fetchone()
            cursor.execute("SELECT username FROM users WHERE id=?", (target_to,))
            to_user = cursor.fetchone()
            
            if not from_user or not to_user:
                error = "Invalid account IDs."
            else:
                result = f"Transferred ${amount:.2f} FROM {from_user['username']} TO {to_user['username']}. (Source ID processed: {actual_from})"
                
        except ValueError:
            error = "Please enter valid numbers."

    return render_template('logic.html', current_user_id=current_session_user_id, result=result, error=error, mode=mode)

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
