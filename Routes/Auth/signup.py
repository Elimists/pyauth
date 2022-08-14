from flask import request, jsonify
from Routes import Routes
from Tools import GeneratorTools as gt, PasswordTools as pt, StringTools as st
from Database import UserFactory, VerificationCodeFactory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    Routes,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Removes limiter for localhost.
@limiter.request_filter
def ip_whitelist():
    return request.remote_addr == "127.0.0.1"


@Routes.route('/api/signup', methods=['POST'])
@limiter.limit("6/hour")
def signup():
    
    if not request.headers.get('Content-Type'):
        return jsonify({'error': True, 'message': 'Missing required headers!', 'code': 'MISSING_REQUIRED_HEADERS'}), 400
    
    jsonData = request.get_json()

    if not jsonData or 'email' not in jsonData or 'name' not in jsonData or 'password' not in jsonData:
        return jsonify({'error': True, 'message': 'Not accepted!', 'code': 'MISSING_REQUIRED_KEYS'}), 400

    if not jsonData['email'] or not jsonData['name'] or not jsonData['password']:
        return jsonify({'error': True, 'message': 'Empty values in input field', 'code': 'MISSING_REQUIRED_VALUES'}), 400
    
    if not isinstance(jsonData['email'], str) or not isinstance(jsonData['name'], str) or not isinstance(jsonData['password'], str):
        return jsonify({'error': True, 'message': 'Recieved invalid value type!', 'code': 'INVALID_TYPE'}), 400
    
    emailCheck = st(jsonData['email'])
    if not emailCheck.is_email_valid():
        return jsonify({'error': True, 'message': 'Email is not valid!', 'code': 'INVALID_EMAIL'}), 400

    nameCheck = st(jsonData['name'])
    if not nameCheck.is_name_valid():
        return jsonify({'error': True, 'message': 'Name is not valid!', 'code': 'INVALID_NAME'}), 400

    passwordString = pt(jsonData['password'])
    if not passwordString.is_password_strong():
        return jsonify({'error': True, 'message': 'Password needs to be stronger!', 'code': 'WEAK_PASSWORD'}), 400

    try:
        user = UserFactory()
        verification = VerificationCodeFactory()
    except:
        return jsonify({'error': True, 'message': 'Unable to initialize!', 'code': 'INIT_ERROR'}), 500

    if user.userAlreadyExistsInDB(jsonData['email']):
        return jsonify({'error': True, 'message': 'User already exists!', 'code': 'DUPLICATE_USER'}), 200
    
    hashedPassword = passwordString.encrypt_password()
    verificationCode = gt.verification_code_generator()
  
    try:
        user.createUser(jsonData['email'], jsonData['name'], hashedPassword)
    except:
        return jsonify({'error': True, 'message': 'Unable to initialize database!', 'code': 'DB_TABLE_ERROR'})
    
    try:
        verification.saveVerificationCode(jsonData['email'], verificationCode)
    except:
        user.deleteUser(jsonData['email'])
        verification.deleteVerificationCode(jsonData['email'])
        return jsonify({'error': True, 'message': 'Unable to initialize database!', 'code': 'DB_TABLE_ERROR'})
    
    return jsonify({'error': False, 'message': 'User created successfully!', 'code': 'SUCCESS'})