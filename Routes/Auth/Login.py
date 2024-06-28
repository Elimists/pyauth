from flask import request, jsonify, make_response
from Routes import Routes
from Tools import GeneratorTools as gt, PasswordTools as pt
from Database import UserFactory, SessionFactory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os


CLIENT_DOMAIN = os.getenv('CLIENT_DOMAIN')

limiter = Limiter(
    Routes,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@limiter.request_filter
def ip_whitelist():
    return request.remote_addr == os.getenv('IP_WHITELIST')

@Routes.route('/api/login', methods=['POST'])
@limiter.limit("7 / 2 minute")
def login():
    
    if not request.headers.get('Content-Type'):
        return jsonify({'error': True, 'message': 'Missing required headers!', 'code': 'MISSING_REQUIRED_HEADERS'})
    
    jsonData = request.get_json()

    if not jsonData or 'email' not in jsonData or 'password' not in jsonData:
         return jsonify({'error': True, 'message': 'Not accepted!', 'code': 'MISSING_REQUIRED_KEYS'})
        
    if not jsonData['email'] or not jsonData['password']:
        return jsonify({'error': True, 'message': 'Empty values in input field', 'code': 'MISSING_REQUIRED_VALUES'})
    
    if not isinstance(jsonData['email'], str) or not isinstance(jsonData['password'], str):
        return jsonify({'error': True, 'message': 'Recieved invalid value type!', 'code': 'INVALID_TYPE'})

    try:
        user = UserFactory()
        sessionFactory = SessionFactory()
    except:
        return jsonify({'error': True, 'message': 'Unable to initialize database!', 'code': 'DB_TABLE_ERROR'})

    if not user.userAlreadyExistsInDB(jsonData['email']):
        return jsonify({'error': True, 'message': 'User not found. Please register!', 'code': 'DOES_NOT_EXIST'})
    
    passwordFromDB = user.getUserPassword(jsonData['email'])[0][0]
    if not pt(jsonData['password'].encode("utf-8")).check_password(passwordFromDB.encode("utf-8")):
        return jsonify({'error': True, 'message': 'Incorrect credentials!', 'code': 'INCORRECT_CREDENTIALS'})
    
    if not user.userIsVerfied(jsonData['email']):
        return jsonify({'error': True, 'message': 'User is not yet verfied! Check email!', 'code': 'NOT_VERIFIED'})
    
    if user.userIsLocked(jsonData['email']):
        return jsonify({'error': True, 'message': 'User\'s account is locked!', 'code': 'ACCOUNT_LOCKED'})
    
    sessionData = sessionFactory.getSessionDataByEmailAndIp(jsonData['email'], getPublicIpAddressOfClient())
    if sessionData != None:
        sessionFactory.deleteSession(sessionData['sessionId'])

    # generate new session      
    generatedSessionId = gt.generate_session_id()
    sessionFactory.createSession(generatedSessionId, jsonData['email'], getPublicIpAddressOfClient())
    listOfCookies = [
        {
            'key': "appSessionId", 
            'value':generatedSessionId,
            'expires': sessionFactory.getSessionExpiryTime(generatedSessionId),
            'secure':False,
            'httponly':True,
            'domain':CLIENT_DOMAIN  
        },
        {
            'key': "appUserEmail", 
            'value':jsonData['email'],
            'expires': sessionFactory.getSessionExpiryTime(generatedSessionId),
            'secure':False,
            'httponly':True,
            'domain':CLIENT_DOMAIN  
        }
    ]
    
    res = make_response(jsonify({'error': False, 'message': 'Authentication successfull!', 'code': 'SUCCESS'}))
    for cookie in listOfCookies:
        
        res.set_cookie(
                key=cookie['key'], 
                value=cookie['value'],
                expires=cookie['expires'],
                secure=cookie['secure'],
                httponly=cookie['httponly'],
                domain=cookie['domain']
                )
    user.updateLastLoggedIn(jsonData['email'])
    return res


def getPublicIpAddressOfClient():

    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        return request.environ['REMOTE_ADDR']
    else:
        return request.environ['HTTP_X_FORWARDED_FOR']