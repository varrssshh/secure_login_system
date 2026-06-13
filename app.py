"""
Secure Login System
A Flask web application implementing:
- User registration & login with bcrypt password hashing
- Protection against SQL injection via parameterized queries
- Input validation
- Session management with logout
- Optional Two-Factor Authentication (TOTP-based)
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash
import bcrypt
import re
import pyotp
import qrcode
import io
import base64
from database import get_db_connection, init_db

app = Flask(__name__)
app.secret_key = "change-this-secret-key-in-production"  # use env var in production

# ---------------------------
# Validation helpers
# ---------------------------

def is_valid_email(email):
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    return re.match(pattern, email) is not None


def is_valid_username(username):
    # Alphanumeric + underscore, 3-20 chars
    pattern = r"^[A-Za-z0-9_]{3,20}$"
    return re.match(pattern, username) is not None


def is_strong_password(password):
    # At least 8 chars, one uppercase, one lowercase, one digit
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    return True


# ---------------------------
# Routes
# ---------------------------

@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # --- Input validation ---
        if not is_valid_username(username):
            flash("Username must be 3-20 characters (letters, numbers, underscore only).", "error")
            return render_template("register.html")

        if not is_valid_email(email):
            flash("Please enter a valid email address.", "error")
            return render_template("register.html")

        if not is_strong_password(password):
            flash("Password must be at least 8 characters, with uppercase, lowercase, and a number.", "error")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        # --- Hash password using bcrypt ---
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        conn = get_db_connection()
        cursor = conn.cursor()

        # Check for existing username/email (parameterized query)
        cursor.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?",
            (username, email)
        )
        existing = cursor.fetchone()

        if existing:
            flash("Username or email already registered.", "error")
            conn.close()
            return render_template("register.html")

        # Insert new user (parameterized query prevents SQL injection)
        cursor.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash.decode("utf-8"))
        )
        conn.commit()
        conn.close()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        cursor = conn.cursor()

        # Parameterized query - prevents SQL injection
        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
        conn.close()

        if user is None:
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        stored_hash = user["password_hash"].encode("utf-8")

        if not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        # If 2FA is enabled, redirect to verification step
        if user["two_fa_enabled"]:
            session["pending_user_id"] = user["id"]
            return redirect(url_for("verify_2fa"))

        # Successful login
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        flash("Logged in successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    if "pending_user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE id = ?",
            (session["pending_user_id"],)
        )
        user = cursor.fetchone()
        conn.close()

        if user is None:
            return redirect(url_for("login"))

        totp = pyotp.TOTP(user["totp_secret"])

        if totp.verify(code):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session.pop("pending_user_id", None)
            flash("Logged in successfully with 2FA!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid 2FA code. Please try again.", "error")

    return render_template("verify_2fa.html")


@app.route("/setup-2fa")
def setup_2fa():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],))
    user = cursor.fetchone()

    if not user["totp_secret"]:
        secret = pyotp.random_base32()
        cursor.execute(
            "UPDATE users SET totp_secret = ?, two_fa_enabled = 1 WHERE id = ?",
            (secret, session["user_id"])
        )
        conn.commit()
    else:
        secret = user["totp_secret"]
        cursor.execute(
            "UPDATE users SET two_fa_enabled = 1 WHERE id = ?",
            (session["user_id"],)
        )
        conn.commit()

    conn.close()

    # Generate QR code for authenticator apps
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user["email"], issuer_name="SecureLoginApp"
    )

    img = qrcode.make(totp_uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    flash("2FA enabled! Scan the QR code with your authenticator app.", "success")
    return render_template("dashboard.html", username=session["username"],
                            qr_code=qr_b64, secret=secret, two_fa_enabled=True)


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please log in to access the dashboard.", "error")
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT two_fa_enabled FROM users WHERE id = ?", (session["user_id"],))
    user = cursor.fetchone()
    conn.close()

    return render_template("dashboard.html", username=session["username"],
                            two_fa_enabled=bool(user["two_fa_enabled"]),
                            qr_code=None, secret=None)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)