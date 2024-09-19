# app.py
from flask import Flask, request, jsonify

app = Flask(__name__)
"""
curl -X POST \
  http://localhost:5001/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "CNIC": "1234567890123",
    "Phone": "+923001234567",
    "Email": "test@example.com",
    "Mother Name": "Jane Doe",
    "Date of Birth": "1990-01-01"
  }'
"""
@app.route('/verify', methods=['POST'])
def verify():
    # Extract parameters from the request
    cnic = request.json.get('CNIC')
    phone = request.json.get('Phone')
    email = request.json.get('Email')
    mother_name = request.json.get('Mother Name')
    date_of_birth = request.json.get('Date of Birth')

    # You can add any validation or processing logic here if needed

    # Always return True
    return jsonify({"result": True}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)