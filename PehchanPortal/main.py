from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from database import init_db, add_user, get_user_by_email, verify_user, update_avatar
import re
=import os
from werkzeug.utils import secure_filename
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
                # also store in db
                add_user(full_name, email, phone, cnic)
                return jsonify({'success': True, 'message': 'Registration successful! Please log in.'})
            else:
                return jsonify({'success': False, 'message': 'Failed to register user in Keycloak'})
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)})


# Login route
@app.route('/login')
def login():
    keycloak_login_url = f'http://localhost:8080/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth'
    client_id = KEYCLOAK_CLIENT_ID
    redirect_uri = 'http://localhost:5002/dashboard'
    state = os.urandom(8).hex()
    nonce = os.urandom(8).hex()
    response_type = 'code'
    scope = 'openid'

    login_url = f'{keycloak_login_url}?client_id={client_id}&redirect_uri={redirect_uri}&state={state}&response_type={response_type}&scope={scope}&nonce={nonce}'
    
    return redirect(login_url)

@app.route('/dashboard')
def dashboard():
    code = request.args.get('code')

    if not code:
        return "Error: No authorization code returned from Keycloak", 400

    # Exchange authorization code for tokens
    token_url = f'{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token'
    data = {
        'grant_type': 'authorization_code',
        'client_id': KEYCLOAK_CLIENT_ID,
        'client_secret': KEYCLOAK_CLIENT_SECRET,
        'code': code,
        'redirect_uri': 'http://localhost:5002/dashboard'
    }
    
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    # Send request to Keycloak to get tokens
    token_response = requests.post(token_url, data=data, headers=headers)
    
    if token_response.status_code != 200:
        return f"Error exchanging code for tokens: {token_response.text}", 500

    tokens = token_response.json()

    # Store the tokens in the session (just for demonstration; adjust as per your needs)
    session['access_token'] = tokens.get('access_token')
    session['refresh_token'] = tokens.get('refresh_token')
    session['id_token'] = tokens.get('id_token')

    # Render callback view (You can modify to redirect elsewhere)
    return render_template('dashboard.html', code=code)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))


@app.route('/upload_avatar', methods=['POST'])
def upload_avatar():
    if 'avatar' not in request.files:
        return jsonify({'success': False, 'message': 'No file uploaded'})
    
    file = request.files['avatar']
    
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No selected file'})
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Update the avatar for the user
        user_id = session.get('user_id')  # Assuming you store user ID in session
        update_avatar(user_id, filename)

        return jsonify({'success': True, 'message': 'Avatar updated successfully', 'avatar_url': file_path})
    else:
        return jsonify({'success': False, 'message': 'Invalid file format'})
    
@app.route('/remove_avatar', methods=['POST'])
def remove_avatar():
    user_id = session.get('user_id')  # Assuming you store user ID in session
    update_avatar(user_id, 'default_avatar.png')  # Reset avatar to default

    return jsonify({'success': True, 'message': 'Avatar removed. Default avatar restored.'})


@app.route('/update_profile', methods=['POST'])
def update_profile():
    user_id = session.get('user_id')  # Assuming you store user ID in session
    full_name = request.form['full_name']
    phone = request.form['phone']
    email = request.form['email']
    cnic = request.form['cnic']
    gender = request.form['gender']
    mothers_name = request.form['mothers_name']
    address = request.form['address']
    date_of_birth = request.form['date_of_birth']

    updated = update_user_profile(user_id, full_name, phone, email, cnic, gender, mothers_name, address, date_of_birth)

    if updated:
        return jsonify({'success': True, 'message': 'Profile updated successfully!'})
    else:
        return jsonify({'success': False, 'message': 'Error updating profile.'})




if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5002, debug=True)
