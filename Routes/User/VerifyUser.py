from flask import request, jsonify
from Routes import Routes
from Database import UserFactory, VerificationCodeFactory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


limiter = Limiter(
    Routes,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)


@Routes.route('/verify-user', methods=['POST'])
@limiter.limit("20/hour")
def verify_user():

    if not request.headers.get('Content-Type'):
        return jsonify({'error': True, 'message': 'Missing required headers!', 'code': 'MISSING_REQUIRED_HEADERS'})

    jsonData = request.get_json()
    

    if not jsonData or 'verificationCode' not in jsonData or 'email' not in jsonData:
        return jsonify({'error': True, 'message': 'Not accepted!', 'code': 'MISSING_REQUIRED_KEYS'})
    
    if not jsonData['verificationCode'] or not jsonData['email']:
        return jsonify({'error': True, 'message': 'Empty values in input field', 'code': 'MISSING_REQUIRED_VALUES'})
    
    if not isinstance(jsonData['email'], str) or not isinstance(jsonData['verificationCode'], str):
        return jsonify({'error': True, 'message': 'Recieved invalid value type!', 'code': 'INVALID_TYPE'})
    
    try:
        verificationCodeFactory = VerificationCodeFactory()
        user = UserFactory()
    except:
        return jsonify({'error': True, 'message': 'Unable to initialize database!', 'code': 'DB_TABLE_ERROR'})

    verificationCodeInDb = verificationCodeFactory.getVerificationCode(jsonData['email'])
    # Check if the verification code exists in the database.
    if not verificationCodeInDb:
        return jsonify({'error': True, 'message': 'Verification code for this user does not exist!', 'code': 'DOES_NOT_EXIST'})
    
    # Check if provide verification code does not match with the one in the database.
    if verificationCodeInDb['verificationCode'] != jsonData['verificationCode']:
        return jsonify({'error': True, 'message': 'Code does not match!', 'code': 'DOES_NOT_MATCH'})
    
    # Check if the verification code has expired.
    if verificationCodeFactory.verificationCodeHasExpired(jsonData['email']):
        return jsonify({'error': True, 'message': 'Verification code has expired.', 'code': 'EXPIRED'})
    
    try:
        # Update the user account status to verfied.
        user.updateUserAccountStatusToVerfied(jsonData['email'])
    except:
        return jsonify({'error': True, 'message': 'Unable to initialize database!', 'code': 'DB_TABLE_ERROR'})
    
    try:
        # Delete the verification code from the db table.
        verificationCodeFactory.deleteVerificationCode(jsonData['email'])
    except:
        return jsonify({'error': True, 'message': 'Unable to initialize database!', 'code': 'DB_TABLE_ERROR'})
    
    return jsonify({'error': False, 'message': 'Account status is set to verified!', 'code': 'SUCCESS'})