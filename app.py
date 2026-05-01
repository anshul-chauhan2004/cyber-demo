import os
import sqlite3
from flask import Flask, render_template, request, g
from markupsafe import Markup

app = Flask(__name__)
app.secret_key = "super_secret_group_5_key"

# Reliable DB path for Railway / local
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "demo.db")


# ---------------- DATABASE ----------------
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                password TEXT,
                balance REAL
            )
        """)

        cursor.execute("SELECT COUNT(*) FROM users")
        count = cursor.fetchone()[0]

        if count == 0:
            cursor.execute(
                "INSERT INTO users (username,password,balance) VALUES (?,?,?)",
                ("admin", "admin123", 1000000.00)
            )
            cursor.execute(
                "INSERT INTO users (username,password,balance) VALUES (?,?,?)",
                ("bob", "bobpass", 500.00)
            )
            cursor.execute(
                "INSERT INTO users (username,password,balance) VALUES (?,?,?)",
                ("alice", "alicepass", 750.00)
            )
            db.commit()


# ---------------- HOME ----------------
@app.route("/")
def index():
    return render_template("index.html")


# ---------------- SQL INJECTION ----------------
@app.route("/sqli", methods=["GET", "POST"])
def sqli():
    query_str = ""
    result = None
    error = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        mode = request.form.get("mode", "vulnerable")

        db = get_db()
        cursor = db.cursor()

        try:
            if mode == "vulnerable":
                query_str = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
                cursor.execute(query_str)
            else:
                query_str = "SELECT * FROM users WHERE username=? AND password=?"
                cursor.execute(
                    "SELECT * FROM users WHERE username=? AND password=?",
                    (username, password)
                )

            user = cursor.fetchone()

            if user:
                result = f"Success! Logged in as {user['username']} (Balance: ${user['balance']})"
            else:
                error = "Invalid credentials."

        except Exception as e:
            error = str(e)

    return render_template(
        "sqli.html",
        query_str=query_str,
        result=result,
        error=error
    )


# ---------------- XSS ----------------
@app.route("/xss", methods=["GET", "POST"])
def xss():
    search_query = ""
    result = ""
    mode = "vulnerable"

    if request.method == "POST":
        search_query = request.form.get("search_query", "")
        mode = request.form.get("mode", "vulnerable")

        if mode == "vulnerable":
            result = Markup(search_query)
        else:
            result = search_query

    return render_template(
        "xss.html",
        search_query=search_query,
        result=result,
        mode=mode
    )


# ---------------- IDOR ----------------
@app.route("/idor", methods=["GET", "POST"])
def idor():
    current_session_user_id = 2
    target_id = ""
    result = None
    error = None
    mode = "vulnerable"

    if request.method == "POST":
        target_id = request.form.get("target_user_id", "")
        mode = request.form.get("mode", "vulnerable")

        try:
            target_id_int = int(target_id)

            db = get_db()
            cursor = db.cursor()

            if mode == "vulnerable":
                cursor.execute(
                    "SELECT * FROM users WHERE id=?",
                    (target_id_int,)
                )
            else:
                if target_id_int != current_session_user_id:
                    error = "403 Forbidden"
                    return render_template(
                        "idor.html",
                        current_user_id=current_session_user_id,
                        target_id=target_id,
                        result=result,
                        error=error,
                        mode=mode
                    )

                cursor.execute(
                    "SELECT * FROM users WHERE id=?",
                    (target_id_int,)
                )

            user = cursor.fetchone()

            if user:
                result = f"User: {user['username']} Balance: ${user['balance']}"
            else:
                error = "User not found."

        except:
            error = "Enter valid numeric ID."

    return render_template(
        "idor.html",
        current_user_id=current_session_user_id,
        target_id=target_id,
        result=result,
        error=error,
        mode=mode
    )


# ---------------- BUSINESS LOGIC ----------------
@app.route("/logic", methods=["GET", "POST"])
def logic():
    current_session_user_id = 2
    result = None
    error = None
    mode = "vulnerable"

    if request.method == "POST":
        from_account = request.form.get("from_account", "")
        to_account = request.form.get("to_account", "")
        amount_str = request.form.get("amount", "0")
        mode = request.form.get("mode", "vulnerable")

        try:
            amount = float(amount_str)
            target_to = int(to_account)

            db = get_db()
            cursor = db.cursor()

            if mode == "vulnerable":
                actual_from = int(from_account)
            else:
                actual_from = current_session_user_id

            cursor.execute(
                "SELECT username FROM users WHERE id=?",
                (actual_from,)
            )
            from_user = cursor.fetchone()

            cursor.execute(
                "SELECT username FROM users WHERE id=?",
                (target_to,)
            )
            to_user = cursor.fetchone()

            if from_user and to_user:
                result = f"Transferred ${amount:.2f} FROM {from_user['username']} TO {to_user['username']}"
            else:
                error = "Invalid accounts."

        except:
            error = "Invalid input."

    return render_template(
        "logic.html",
        current_user_id=current_session_user_id,
        result=result,
        error=error,
        mode=mode
    )


# IMPORTANT FOR RAILWAY / GUNICORN
with app.app_context():
    init_db()


# LOCAL RUN
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
