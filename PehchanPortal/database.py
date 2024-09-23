import sqlite3
from flask import g

DATABASE = 'pehchan.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

def init_db():
    """Initialize the database schema with Keycloak User ID."""
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone TEXT NOT NULL,
                cnic TEXT UNIQUE NOT NULL,
                keycloak_user_id TEXT UNIQUE,  -- Store Keycloak UUID
                gender TEXT DEFAULT 'N/A',
                mothers_name TEXT DEFAULT 'N/A',
                address TEXT DEFAULT 'N/A',
                date_of_birth TEXT DEFAULT 'N/A',
                avatar TEXT DEFAULT 'default_avatar.png',
                verified BOOLEAN NOT NULL DEFAULT 0
            )
        ''')



def add_user(full_name, email, phone, cnic, keycloak_user_id):
    """Add a new user to the database, including Keycloak User ID."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (full_name, email, phone, cnic, keycloak_user_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (full_name, email, phone, cnic, keycloak_user_id))
        return cursor.lastrowid

    
def update_user_profile(user_id, full_name, phone, email, cnic, gender, mothers_name, address, date_of_birth):
    """Update a user's profile information."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users
            SET full_name = ?, phone = ?, email = ?, cnic = ?, gender = ?, mothers_name = ?, address = ?, date_of_birth = ?
            WHERE id = ?
        ''', (full_name, phone, email, cnic, gender, mothers_name, address, date_of_birth, user_id))
        return cursor.rowcount > 0


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
    
def get_user_by_id(user_id):
    """Retrieve a user by their ID."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if user:
            return {
                'id': user[0],
                'full_name': user[1],
                'email': user[2],
                'phone': user[3],
                'cnic': user[4],
                'gender': user[5],
                'mothers_name': user[6],
                'address': user[7],
                'date_of_birth': user[8],
                'avatar': user[9],
                'verified': user[10]
            }
        return None


def verify_user(user_id):
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('UPDATE users SET verified = 1 WHERE id = ?', (user_id,))

def update_avatar(user_id, avatar_filename):
    """Update the user's avatar in the database."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE users
            SET avatar = ?
            WHERE id = ?
        ''', (avatar_filename, user_id))
        return cursor.rowcount > 0

def get_user_by_keycloak_id(keycloak_user_id):
    """Retrieve a user by their Keycloak user ID."""
    with sqlite3.connect(DATABASE) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE keycloak_user_id = ?', (keycloak_user_id,))
        user = cursor.fetchone()
        if user:
            return {
                'id': user[0],
                'full_name': user[1],
                'email': user[2],
                'phone': user[3],
                'cnic': user[4],
                'avatar': user[9]
            }
        return None
