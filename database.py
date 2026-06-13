"""
Database setup and connection handling using SQLite.
Uses parameterized queries throughout to prevent SQL injection.
"""

import sqlite3

DB_NAME = "users.db"


def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret TEXT,
            two_fa_enabled INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()
    print("[+] Database initialized: users.db")


if __name__ == "__main__":
    init_db()