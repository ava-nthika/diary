import os
import sqlite3
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-this-secret'
app.config['DATABASE'] = os.path.join(os.path.dirname(__file__), 'diary.db')

# ---------- DB Helpers ----------
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'], detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)
    db.commit()

with app.app_context():
    init_db()

# ---------- Auth Utilities ----------
def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            flash("Please log in to continue.", "warning")
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

def current_user():
    if 'user_id' not in session:
        return None
    db = get_db()
    return db.execute("SELECT id, username, email FROM users WHERE id = ?", (session['user_id'],)).fetchone()

# ---------- Routes ----------
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', "").strip()
        email = request.form.get('email', "").strip().lower()
        password = request.form.get('password', "")
        confirm = request.form.get('confirm', "")

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template('signup.html')

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template('signup.html')

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, generate_password_hash(password))
            )
            db.commit()
            flash("Account created! Please log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username or email already exists.", "danger")
            return render_template('signup.html')

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email_or_username = request.form.get('email_or_username', "").strip()
        password = request.form.get('password', "")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE email = ? OR username = ?",
            (email_or_username.lower(), email_or_username)
        ).fetchone()

        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials.", "danger")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    user = current_user()
    entries = db.execute(
        "SELECT id, title, content, created_at, updated_at FROM entries WHERE user_id = ? ORDER BY created_at DESC",
        (user['id'],)
    ).fetchall()
    return render_template('dashboard.html', user=user, entries=entries)

@app.route('/entry/new', methods=['GET', 'POST'])
@login_required
def new_entry():
    if request.method == 'POST':
        title = request.form.get('title', "").strip()
        content = request.form.get('content', "").strip()

        if not title or not content:
            flash("Title and content are required.", "danger")
            return render_template('entry_form.html', mode='new', title_val=title, content_val=content)

        db = get_db()
        db.execute(
            "INSERT INTO entries (user_id, title, content, created_at) VALUES (?, ?, ?, ?)",
            (session['user_id'], title, content, datetime.utcnow())
        )
        db.commit()
        flash("Entry added ✨", "success")
        return redirect(url_for('dashboard'))

    return render_template('entry_form.html', mode='new')

@app.route('/entry/<int:entry_id>')
@login_required
def view_entry(entry_id):
    db = get_db()
    entry = db.execute(
        "SELECT * FROM entries WHERE id = ? AND user_id = ?",
        (entry_id, session['user_id'])
    ).fetchone()
    if not entry:
        flash("Entry not found.", "warning")
        return redirect(url_for('dashboard'))
    return render_template('view_entry.html', entry=entry)

@app.route('/entry/<int:entry_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_entry(entry_id):
    db = get_db()
    entry = db.execute(
        "SELECT * FROM entries WHERE id = ? AND user_id = ?",
        (entry_id, session['user_id'])
    ).fetchone()
    if not entry:
        flash("Entry not found.", "warning")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form.get('title', "").strip()
        content = request.form.get('content', "").strip()

        if not title or not content:
            flash("Title and content are required.", "danger")
            return render_template('entry_form.html', mode='edit', entry=entry, title_val=title, content_val=content)

        db.execute(
            "UPDATE entries SET title = ?, content = ?, updated_at = ? WHERE id = ? AND user_id = ?",
            (title, content, datetime.utcnow(), entry_id, session['user_id'])
        )
        db.commit()
        flash("Entry updated 💖", "success")
        return redirect(url_for('view_entry', entry_id=entry_id))

    return render_template('entry_form.html', mode='edit', entry=entry, title_val=entry['title'], content_val=entry['content'])

@app.route('/entry/<int:entry_id>/delete', methods=['POST'])
@login_required
def delete_entry(entry_id):
    db = get_db()
    db.execute("DELETE FROM entries WHERE id = ? AND user_id = ?", (entry_id, session['user_id']))
    db.commit()
    flash("Entry deleted 🗑️", "info")
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    os.makedirs(os.path.dirname(app.config['DATABASE']), exist_ok=True)
    with app.app_context():
        init_db()
    app.run(debug=True)
