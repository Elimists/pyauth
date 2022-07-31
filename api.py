
import json
from flask import Flask, request, jsonify
import re
from tools import is_password_strong, is_email_valid, encrypt_password, is_name_valid, check_password
from tools import random_code_generator
from UserFactory import UserFactory
from VerificationCodeFactory import VerificationCodeFactory
#Look into Flask-Limiter package that can throttle requests

SUPER_SECRET = "Kejth0Bf0zCV92bh8Yxz"

userFactory = UserFactory()
verificationCodeFactory = VerificationCodeFactory()

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
    verificationCode = random_code_generator()
    try:
        userFactory.createUser(jsonData['email'], jsonData['name'], hashedPassword)   
    except:
        return jsonify({'error': True, 'message': 'User was NOT created!'})


    try:
        verificationCodeFactory.saveVerificationCode(jsonData['email'], verificationCode)
    except:
        return jsonify({'error': True, 'message': 'Verification code was NOT saved!'})
    
    return jsonify({'error': False, 'message': 'user and verification code saved!'})


@app.route('/verify', methods=['POST'])
def verify():

    if not request.headers.get('Content-Type'):
        return jsonify({'error': True, 'message': 'Forbidden. Invalid content-type'}), 403

    jsonData = request.get_json()

    if not jsonData:
        return jsonify({'error': True, 'message': 'Missing data. Not acceptable'})
    
    if 'verificationCode' not in jsonData or 'email' not in jsonData:
        return jsonify({'error': True, 'message': 'Missing data. Not acceptable!'})
    
    if not jsonData['verificationCode']:
        return jsonify({'error': True, 'message': 'Code field cannot be empty!'})

    if not jsonData['email']:
        return jsonify({'error': True, 'message': 'Email cannot be null!'})

    verificationCodeInDb = verificationCodeFactory.getVerificationCode(jsonData['email'])
    if len(verificationCodeInDb) == 0:
        return jsonify({'error': True, 'message': 'Verification code for this user does not exist!'})

    if verificationCodeInDb[0][0] != jsonData['verificationCode']:
        return jsonify({'error': True, 'message': 'Code does not match!'})
    
    try:
        userFactory.updateUserAccountStatusToVerfied(jsonData['email'])
    except:
        return jsonify({'error': True, 'message': 'Could not update the account status!'})
    
    try:
        verificationCodeFactory.deleteVerificationCode(jsonData['email'])
    except:
        return jsonify({'error': True, 'message': 'Could not delete verification code from db!'})
    
    return jsonify({'error': False, 'message': 'User Verified successfully! Updated account status and deleted verification code.'})
    

@app.route('/login', methods=['POST'])
def login():
    
    if not request.headers.get('Content-Type'):
        return jsonify({'error': True, 'message': 'Forbidden. Invalid content-type'}), 403
    
    jsonData = request.get_json()

    if not jsonData:
        return jsonify({'error': True, 'message': 'Missing data. Not Acceptable'})
        
    if 'email' not in jsonData or 'password' not in jsonData:
        return jsonify({'error': True, 'message': 'Missing data. Not Acceptable'})
    
    if not jsonData['email'] or not jsonData['password']:
        return jsonify({'error': True, 'message': 'Email/Password fields cannot be empty!'})

    if not userFactory.userAlreadyExistsInDB(jsonData['email']):
        return jsonify({'error': True, 'message': 'User not found. Please register!'})
    

    passwordFromDB = userFactory.getUserPassword(jsonData['email'])[0][0]
 
    if not check_password(jsonData['password'].encode("utf-8"), passwordFromDB.encode("utf-8")):
        return jsonify({'error': True, 'message': 'Could not authenticate! Incorrect password!'})
    
 
    userFactory.updateLastLoggedIn(jsonData['email'])
    return jsonify({'error': False, 'message': 'Authentication successfull!'})
    

@app.route('/special-route', methods=['GET'])
def authenticated_route():

    if not request.headers.get('Content-Type'):
        return jsonify({'error': True, 'status_code': 403, 'message': 'Forbidden. Invalid content-type'}), 403

    if not request.headers.get('Session-Id'):
        return jsonify({'error': True, 'status_code': 403, 'message': 'Forbidden'}), 403

    return jsonify({'error': False, 'message': 'Session-Id present in header!'})

if __name__ == "__main__":
    app.run(debug=True)
