from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from database import init_db, add_user, get_user_by_email, verify_user, update_avatar, update_user_profile, get_user_by_keycloak_id
import re
import os
from werkzeug.utils import secure_filename
import requests
from keycloak import KeycloakAdmin, KeycloakOpenIDConnection, KeycloakOpenID



KEYCLOAK_URL = os.getenv('KEYCLOAK_URL', 'http://keycloak:8080')
KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'pportal')
KEYCLOAK_CLIENT_SECRET = 'vB9uruPX8DGlglHFKVMGPwRrNE19NTrW'
KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'pehchan')

keycloak_connection = KeycloakOpenIDConnection(
                        server_url=os.getenv('KEYCLOAK_URL', 'http://keycloak:8080'),
                        username='admin',
                        password='admin_password',
                        realm_name=os.getenv('KEYCLOAK_REALM', 'pehchan'),
                        client_id=os.getenv('KEYCLOAK_CLIENT_ID', 'pportal'),
                        client_secret_key='vB9uruPX8DGlglHFKVMGPwRrNE19NTrW',
                        verify=True)

# Set up KeycloakOpenID instance
keycloak_openid = KeycloakOpenID(
    server_url="http://keycloak:8080",  # Access via service name inside Docker
    client_id="pportal",
    realm_name="pehchan",
    client_secret_key="vB9uruPX8DGlglHFKVMGPwRrNE19NTrW"
)




keycloak_admin = KeycloakAdmin(connection=keycloak_connection)

# # Add user
# new_user = keycloak_admin.create_user({"email": "example@example.com",
#                                        "username": "example@example.com",
#                                        "enabled": True,
#                                        "firstName": "Example",
#                                        "lastName": "Example"})

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # In production, use a proper secret key


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

        try:
            # Create the user in Keycloak
            keycloak_admin.create_user(user_data)
            
            # Retrieve the user by email to get Keycloak's unique user ID
            users = keycloak_admin.get_users({"email": email})
            if not users:
                return jsonify({'success': False, 'message': 'User not found in Keycloak'})
            
            keycloak_user_id = users[0]['id']  # Keycloak's unique user ID

            # Also store the user in your database with the Keycloak user ID
            add_user(full_name, email, phone, cnic, keycloak_user_id=keycloak_user_id)

            return jsonify({'success': True, 'message': 'Registration successful! Please log in.'})

        except Exception as e:
            return jsonify({'success': False, 'message': str(e)})



# Login route
@app.route('/login')
def login():
    keycloak_login_url = f'http://keycloak:8080/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth'
    client_id = KEYCLOAK_CLIENT_ID
    redirect_uri = 'http://pechchan-mvp-pehchan-portal-1:5002/callback'
    state = os.urandom(8).hex()
    nonce = os.urandom(8).hex()
    response_type = 'code'
    scope = 'openid'

    login_url = f'{keycloak_login_url}?client_id={client_id}&redirect_uri={redirect_uri}&state={state}&response_type={response_type}&scope={scope}&nonce={nonce}'
    
    return redirect(login_url)

@app.route('/dashboard')
def dashboard():
    # Ensure the user is logged in
    user_id = session.get('user_id')
    if not user_id:
        return redirect('/login')

    # Fetch the user from the database
    user = get_user_by_keycloak_id(user_id)

    if not user:
        return "User not found", 404

    # Render the dashboard with the user's profile
    return render_template('dashboard.html', user=user)


@app.route('/callback')
def callback():
    code = request.args.get('code')
    print('Code from Keyclock', code)

    if not code:
        return "Error: No authorization code returned from Keycloak", 400

    try:
        # Use python-keycloak to exchange the authorization code for tokens
        token = keycloak_openid.token(
            grant_type='authorization_code',
            code=code,
            redirect_uri='http://pechchan-mvp-pehchan-portal-1:5002/callback'
        )

        # Store tokens in session
        session['access_token'] = token['access_token']
        session['refresh_token'] = token['refresh_token']
        session['id_token'] = token['id_token']

        # Print the access token to the console for verification
        print(f"Access Token: {session['access_token']}")

        # Use the access token to get user info from Keycloak
        user_info = keycloak_openid.userinfo(token=session['access_token'])

        keycloak_user_id = user_info['sub']  # Keycloak's unique user ID

        # Store the user_id in the session for future use
        session['user_id'] = keycloak_user_id

        return redirect('/dashboard')

    except Exception as e:
        print(f"Error fetching tokens or user info: {str(e)}")
        return f"Error fetching tokens or user info: {str(e)}", 500





@app.route('/logout')
def logout():
    # Keycloak logout URL
    keycloak_logout_url = f'http://keycloak:8080/realms/{KEYCLOAK_REALM}/protocol/openid-connect/logout'
    
    # Redirect URI after logging out from Keycloak
    redirect_uri = 'http://pechchan-mvp-pehchan-portal-1:5002'  # Redirect back to home after logout
    
    # Construct the logout URL with post logout redirect URI and client ID
    logout_url = f'{keycloak_logout_url}?post_logout_redirect_uri={redirect_uri}&client_id={KEYCLOAK_CLIENT_ID}'
    
    # Clear session or tokens in Flask
    session.pop('user_id', None)
    session.pop('access_token', None)
    session.pop('refresh_token', None)
    session.pop('id_token', None)
    
    # Redirect to Keycloak logout URL
    return redirect(logout_url)



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
