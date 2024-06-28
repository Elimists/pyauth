from flask import request, jsonify, make_response
from Routes import Routes
from Tools import GeneratorTools as gt, PasswordTools as pt, StringTools as st
from Database import UserFactory, VerificationCodeFactory, SessionFactory, PasswordResetFactory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from Decorators import is_user_authorized
import os

CLIENT_DOMAIN = os.getenv('CLIENT_DOMAIN')


@Routes.route('/delete-user', methods=['DELETE'])
@is_user_authorized
def delete_user():
    
    jsonData = request.get_json()

    if not 'email' in jsonData or not jsonData['email']:
        return jsonify({'error': True, 'message': 'Missing data. Not Acceptable'})
    if not 'password' in jsonData or not jsonData['password']:
        return jsonify({'error': True, 'message': 'Missing data. Not Acceptable'})

    if not request.cookies.get('appSessionId'):
            return jsonify({'error': True, 'message': 'Cookies are missing. Not authorized!'})
   
    appSessionId = request.cookies.get('appSessionId')
    
    try:
        session = SessionFactory()
        user = UserFactory()
        verification = VerificationCodeFactory()
    except:
        return jsonify({'error': True, 'message': 'Cannot initialize user table!'})
    
    if not session.sessionIdExists(appSessionId) or session.sessionHasExpired(appSessionId):
        return jsonify({'error': True, 'message': 'Invalid session. Please log in again!', 'code': "INVALID_SESSION"})
    
    retrievedUserEmail = session.getSessionData(appSessionId)['userEmail']
    
    if retrievedUserEmail != jsonData['email']:
        return jsonify({'error': True, 'message': "Given user email and user session email does not match!"})
    
    if not user.userAlreadyExistsInDB(jsonData['email']):
        return jsonify({'error': True, 'message': 'User does not exist!'})

    passwordFromDB = user.getUserPassword(jsonData['email'])[0][0]
    passwordHandler = pt(jsonData['password'].encode("utf-8"))
    if not passwordHandler.check_password(passwordFromDB.encode("utf-8")):
        return jsonify({'error': True, 'message': 'Iccorrect password. Could not delete user!'})
    
    try:
        user.deleteUser(jsonData['email'])
        session.deleteSession(appSessionId)
        verification.deleteVerificationCode(jsonData['email'])
        
    except:
        return jsonify({'error': True, 'message': 'Can\'t delete user!'})

    listOfCookies = [
        {
            'key': "appSessionId", 
            'value':"",
            'expires': 0,
            'secure':False,
            'httponly':True,
            'domain':CLIENT_DOMAIN  
        },
        {
            'key': "appUserEmail", 
            'value':"",
            'expires': 0,
            'secure':False,
            'httponly':True,
            'domain':CLIENT_DOMAIN  
        }
    ]
    #Invalidate cookie on client side.
    res = make_response(jsonify({'error': False, 'message': 'Invalidated cookies! User Deleted!'}))
    for cookie in listOfCookies:
        res.set_cookie(
            key=cookie['key'], 
            value=cookie['value'],
            expires=cookie['expires'],
            secure=cookie['secure'],
            httponly=cookie['httponly'],
            domain=cookie['domain']
        )
    return res