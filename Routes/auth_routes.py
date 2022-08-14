"""
from flask import request, jsonify, make_response
from Routes import Routes
from Tools import GeneratorTools as gt, PasswordTools as pt, StringTools as st
from Database import UserFactory, VerificationCodeFactory, SessionFactory, PasswordResetFactory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from Decorators import is_user_authorized

limiter = Limiter(
    Routes,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Don't limit requests coming from localhost

@limiter.request_filter
def ip_whitelist():
    return request.remote_addr == "127.0.0.1"

CLIENT_DOMAIN = '127.0.0.1:5500'

@Routes.route('/signup', methods=['POST'])
@limiter.limit("6/hour")
def register():
    
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


@Routes.route('/verify', methods=['POST'])
@limiter.limit("20/hour")
def verify():

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
    

@Routes.route('/login', methods=['POST'])
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
    

@Routes.route('/logout', methods=['GET'])
def logout():

    if not request.cookies.get('appSessionId'):
        return jsonify({'error': True, 'message': 'Missing cookies'})
    
    cookieSessionId = request.cookies.get('appSessionId')

    try:
        sessionFactory = SessionFactory()
    except:
        return jsonify({'error': True, 'message': 'Can\'t initialize session!'})
    
    if not sessionFactory.sessionIdExists(cookieSessionId):
        res = make_response(jsonify({'error': True, 'message': 'Did not receive any cookie!'}))
        return res
    
   
    sessionFactory.deleteSession(cookieSessionId)
    
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
    res = make_response(jsonify({'error': False, 'message': 'User logged out!'}))
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
    

@Routes.route('/reset-password-generate-token', methods=['POST'])
@limiter.limit("7 / 2 minute")
def reset_password_generate_token():
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


@Routes.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    if not token:
        return jsonify({'error': True, 'message': 'Password reset token is missing'})
    
    jsonData = request.get_json()

    if not 'email' in jsonData or not jsonData['email']:
        return jsonify({'error': True, 'message': 'Missing data. Not Acceptable'})
    if not 'password' in jsonData or not jsonData['password']:
        return jsonify({'error': True, 'message': 'Missing data. Not Acceptable'})
    
    passwordHandler= pt(jsonData['password'])
    if not passwordHandler.is_password_strong():
        return jsonify({'error': True, 'message': 'Password is weak!'})

    try:
        passwordResetFactory = PasswordResetFactory(jsonData['email'])
        user = UserFactory()
    except:
        return jsonify({'error': True, 'message': 'Unable to initialize'})
    
    if not user.userAlreadyExistsInDB(jsonData['email']):
        return jsonify({'error': True, 'message': 'Hmmm... User not found!'})
    
    tokenData = passwordResetFactory.getPasswordResetTokenData()
    if not tokenData['token']:
        return jsonify({'error': True, 'message': 'User has not initiated a password reset!'})

    if passwordResetFactory.isTokenExpired():
        return jsonify({'error': True, 'message': 'Token has expired! Please resubmit another request to reset password!'})

    if tokenData['token'] != token:
        return jsonify({'error': True, 'message': 'Token doesn\'t match!'})

    hashedPassword = passwordHandler.encrypt_password()
    try:
        user.updateUserPassword(jsonData['email'], hashedPassword)
        passwordResetFactory.deleteTokenData()
    except:
        return jsonify({'error': True, 'message': 'Could not update password for the user!'})
    
    return jsonify({'error': False, 'message': 'Password changed successfully'})
    

#TODO
@Routes.route('/request-new-verification-code', methods=['POST'])
def request_new_verification_code():
    pass


#TODO
@Routes.route('/change-user-password', methods=['POST'])
@is_user_authorized
def change_user_password():
    pass


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


@Routes.errorhandler(404)
def route_not_found(e):
    return jsonify({"error": True, "message": "The requested url was not found!", "code": "NOT_FOUND"})


@Routes.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": True, "message": "Too many requests. Please try again later.", "code": "TOO_MANY_REQUESTS"}), 429


@Routes.errorhandler(500)
def server_error_handler(e):
    return jsonify({"error": True, "message": "Internal server error!", "code": "SERVER_ERROR"}), 500


@Routes.errorhandler(405)
def method_not_allowed_handler(e):
    return jsonify({"error": True, "message": "Method rejected by server!", "code": "REJECTED"}), 405


def getPublicIpAddressOfClient():

    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        return request.environ['REMOTE_ADDR']
    else:
        return request.environ['HTTP_X_FORWARDED_FOR']
"""