import sqlite3
from flask import g

DATABASE = 'pehchan.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone TEXT NOT NULL,
                cnic TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                verified BOOLEAN NOT NULL DEFAULT 0
            )
        ''')

def add_user(full_name, email, phone, cnic, password):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (full_name, email, phone, cnic, password)
            VALUES (?, ?, ?, ?, ?)
        ''', (full_name, email, phone, cnic, password))
        return cursor.lastrowid

def get_user_by_email(email):
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        if user:
            return {
                'id': user[0],
                'full_name': user[1],
                'email': user[2],
                'phone': user[3],
                'cnic': user[4],
                'password': user[5],
                'verified': user[6]
            }
        return None

def verify_user(user_id):
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('UPDATE users SET verified = 1 WHERE id = ?', (user_id,))
