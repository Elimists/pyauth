from flask import request, jsonify
from Routes import Routes
from Database import UserFactory, PasswordResetFactory
from Tools import GeneratorTools as gt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    Routes,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)


@Routes.route('/api/reset-password-generate-token', methods=['POST'])
@limiter.limit("7 / 2 minute")
def generate_token():
    if not request.headers.get('Content-Type'):
        return jsonify({'error': True, 'message': 'Forbidden. Invalid content-type'}), 403
    
    jsonData = request.get_json()

    if not jsonData:
        return jsonify({'error': True, 'message': 'Missing data. Not Acceptable!'})
    
    if 'email' not in jsonData or not jsonData['email']:
        return jsonify({'error': True, 'message': 'Missing data. Not Acceptable!'})
    
    try:
        user = UserFactory()
        passwordResetFactory = PasswordResetFactory(jsonData['email'])
    except:
        return jsonify({'error': True, 'message': 'Unable to initialize!'})
    
    if not user.userAlreadyExistsInDB(jsonData['email']):
        return jsonify({'error': True, 'message': 'User does not exist!'})
    
    randomToken = gt.password_reset_token_generator()
    
    try:
        passwordResetFactory.savePasswordResetToken(randomToken)
    except:
        return jsonify({'error': True, 'message': 'Encountered error while trying to save token!'})
    
    return jsonify({'error': False, 'message': 'Created reset password key.', 'token': randomToken})