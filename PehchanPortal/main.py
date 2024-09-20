from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from database import init_db, add_user, get_user_by_email, verify_user
import re
import os
import requests
from keycloak import KeycloakAdmin
from keycloak import KeycloakOpenIDConnection

keycloak_connection = KeycloakOpenIDConnection(
                        server_url=os.getenv('KEYCLOAK_URL', 'http://keycloak:8080'),
                        username='admin',
                        password='admin_password',
                        realm_name=os.getenv('KEYCLOAK_REALM', 'pehchan'),
                        client_id=os.getenv('KEYCLOAK_CLIENT_ID', 'pportal'),
                        client_secret_key='vB9uruPX8DGlglHFKVMGPwRrNE19NTrW',
                        verify=True)


keycloak_admin = KeycloakAdmin(connection=keycloak_connection)

# # Add user
# new_user = keycloak_admin.create_user({"email": "example@example.com",
#                                        "username": "example@example.com",
#                                        "enabled": True,
#                                        "firstName": "Example",
#                                        "lastName": "Example"})

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # In production, use a proper secret key

KEYCLOAK_URL = os.getenv('KEYCLOAK_URL', 'http://keycloak:8080')
KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'pportal')
KEYCLOAK_CLIENT_SECRET = 'vB9uruPX8DGlglHFKVMGPwRrNE19NTrW'
KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'pehchan')

init_db()


# Function to obtain the admin token
def get_admin_token():
    token_url = f"{KEYCLOAK_URL}/realms/pehchan/protocol/openid-connect/token"
    payload = {
        'grant_type': 'client_credentials',
        'client_id': KEYCLOAK_CLIENT_ID,
        'client_secret': KEYCLOAK_CLIENT_SECRET
    }

    response = requests.post(token_url, data=payload)
    response.raise_for_status()  # Raise an exception for any error responses
    return response.json().get('access_token')


def create_user_in_keycloak(user_data):
    print('here we are')
    token = get_admin_token()
    print('got token', token)
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    create_user_url = f"{KEYCLOAK_URL}/admin/realms/{KEYCLOAK_REALM}/users"

    response = requests.post(create_user_url, headers=headers, json=user_data)
    response.raise_for_status()  # Raise an exception for any error responses

    return response.status_code == 201  # 201 Created means success

@app.route('/')
def home():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        # Render the registration form for GET requests
        return render_template('register.html')
    
    if request.method == 'POST':
        # Handle the form submission
        full_name = request.form['fullName']
        email = request.form['email']
        phone = request.form['phone']
        cnic = request.form['cnic']
        password = request.form['password']

        # Split full name into first and last name
        first_name = full_name.split()[0]
        last_name = " ".join(full_name.split()[1:])

        # Create the user payload for Keycloak
        user_data = {
            "username": email,  # Using email as username
            "email": email,
            "enabled": True,
            "emailVerified": False,
            "firstName": first_name,
            "lastName": last_name,
            "attributes": {
                "phoneNumber": [phone],
                "cnic": [cnic]
            },
            "credentials": [
                {
                    "type": "password",
                    "value": password,
                    "temporary": False
                }
            ]
        }

        print('user data', user_data)

        # Try creating the user in Keycloak
        try:
            user_created =  keycloak_admin.create_user(user_data)#create_user_in_keycloak(user_data)
            if user_created:
                return jsonify({'success': True, 'message': 'Registration successful! Please log in.'})
            else:
                return jsonify({'success': False, 'message': 'Failed to register user in Keycloak'})
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)})


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
    app.run(host="0.0.0.0", port=5002, debug=True)
