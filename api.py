
from flask import Flask, request, jsonify
import re
from tools import is_password_strong, is_email_valid, encrypt_password, is_name_valid
from UserFactory import UserFactory

userFactory = UserFactory()

app = Flask(__name__)

@app.route('/')
def home():
    return "Hello world"

@app.route('/signup', methods=['POST'])
def register():
    
    jsonData = request.get_json()

    if 'email' not in jsonData or 'name' not in jsonData or 'password' not in jsonData: 
        return jsonify({'error': True, 'message': 'Missing data. Not Acceptable'})

    if not jsonData['email']:
        return jsonify({'error': True, 'message': 'Missing email!'})
    
    if not is_email_valid(jsonData['email']):
        return jsonify({'error': True, 'message': 'Email is not valid!'})

    if userFactory.userAlreadyExistsInDB(jsonData['email']):
        return jsonify({'error': True, 'message': 'User already exists!'})
    
    if not jsonData['name']:
        return jsonify({'error': True, 'message': 'Name is invalid'})

    if not is_name_valid(jsonData['name']):
        return jsonify({'error': True, 'message': 'That name is not valid!'})

    if not jsonData['password']:
        return jsonify({'error': True, 'message': 'Password is missing!'})   

    if not is_password_strong(jsonData['password']):
        return jsonify({'error': True, 'message': 'Password is weak!'})
    
    hashedPassword = encrypt_password(jsonData['password'])
    try:
        userFactory.createUser(jsonData['email'], jsonData['name'], hashedPassword)
        return jsonify({'error': False, 'message': 'signup successfull! '})
    except:
        return jsonify({'error': True, 'message': 'Not successfull! DB error!'})

if __name__ == "__main__":
    app.run(debug=True)
