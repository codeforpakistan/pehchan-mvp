from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from database import init_db, add_user, get_user_by_email, verify_user
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # In production, use a proper secret key

init_db()

@app.route('/')
def home():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['fullName']
        email = request.form['email']
        phone = request.form['phone']
        cnic = request.form['cnic']
        password = request.form['password']

        # Server-side validation
        if not re.match(r'^[A-Za-z\s]+$', full_name):
            return jsonify({'success': False, 'message': 'Invalid full name'})
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            return jsonify({'success': False, 'message': 'Invalid email'})
        if not re.match(r'^\d{11}$', phone):
            return jsonify({'success': False, 'message': 'Invalid phone number'})
        if not re.match(r'^\d{13}$', cnic):
            return jsonify({'success': False, 'message': 'Invalid CNIC'})
        if len(password) < 8:
            return jsonify({'success': False, 'message': 'Password must be at least 8 characters long'})

        # Check if user already exists
        if get_user_by_email(email):
            return jsonify({'success': False, 'message': 'Email already registered'})

        # Hash password
        hashed_password = generate_password_hash(password)

        # Add user to database
        user_id = add_user(full_name, email, phone, cnic, hashed_password)
        if user_id:
            # Simulating email verification
            verify_user(user_id)
            return jsonify({'success': True, 'message': 'Registration successful! Please log in.'})
        else:
            return jsonify({'success': False, 'message': 'Registration failed. Please try again.'})

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = get_user_by_email(email)
        if user and check_password_hash(user['password'], password):
            if user['verified']:
                session['user_id'] = user['id']
                return jsonify({'success': True, 'redirect': url_for('dashboard')})
            else:
                return jsonify({'success': False, 'message': 'Please verify your email first.'})
        else:
            return jsonify({'success': False, 'message': 'Invalid email or password.'})

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = get_user_by_email(session['user_id'])
    return render_template('dashboard.html', user=user)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
