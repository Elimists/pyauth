from flask import request, jsonify, make_response
from Routes import Routes
from Tools import GeneratorTools as gt, PasswordTools as pt, StringTools as st
from Database import UserFactory, VerificationCodeFactory, SessionFactory, PasswordResetFactory
from ErrorHandler import ErrorHandler as err
from functools import wraps
from Decorators import is_user_authorized

CLIENT_DOMAIN = '127.0.0.1:5500'

@Routes.route('/signup', methods=['POST'])
def register():
    
    jsonData = request.get_json()

    if not jsonData or 'email' not in jsonData or 'name' not in jsonData or 'password' not in jsonData:
        return err.packet(True, 1000, "Inccorrect form submsision!")

    if not jsonData['email'] or not jsonData['name'] or not jsonData['password']:
        return err.packet(True, 1001, "Missing required values. Not acceptable!")
    
    emailCheck = st(jsonData['email'])
    if not emailCheck.is_email_valid():
        return err.packet(True, 1002, "Email is not valid!")

    nameCheck = st(jsonData['name'])
    if not nameCheck.is_name_valid():
        return err.packet(True, 1003, "Name is not valid!")

    passwordString = pt(jsonData['password'])
    if not passwordString.is_password_strong():
        return err.packet(True, 1004, "Password is not strong enough!")

    try:
        user = UserFactory()
        verification = VerificationCodeFactory()
    except:
        return err.packet(True, 5000, "Couldn't initialize tables!")

    if user.userAlreadyExistsInDB(jsonData['email']):
        return err.packet(True, 5001, "User already exists! Please log in!")
    
    hashedPassword = passwordString.encrypt_password()
    verificationCode = gt.verification_code_generator()
    try:
        user.createUser(jsonData['email'], jsonData['name'], hashedPassword)   
    except:
        return err.packet(True, 5000, "Couldn't initialize tables!")

    try:
        verification.saveVerificationCode(jsonData['email'], verificationCode)
    except:
        return err.packet(True, 5000, "Couldn't initialize tables!")
    
    return err.packet(False, 2000, "Signed up successfull! Please check email for a verification code!")


@Routes.route('/verify', methods=['POST'])
def verify():

    if not request.headers.get('Content-Type'):
        return err.packet(True, 999, "Missing required headers")

    jsonData = request.get_json()

    if not jsonData or 'verificationCode' not in jsonData or 'email' not in jsonData:
        return jsonify({'error': True, 'message': 'Missing data. Not acceptable!'})
    
    if not jsonData['verificationCode'] or not jsonData['email']:
        return jsonify({'error': True, 'message': 'Recieved empty fields! Not acceptable!'})
    
    try:
        verificationCodeFactory = VerificationCodeFactory()
        user = UserFactory()
    except:
        return jsonify({'error': True, 'message': 'Unable to initialize.'})

    verificationCodeInDb = verificationCodeFactory.getVerificationCode(jsonData['email'])
    if not verificationCodeInDb:
        return jsonify({'error': True, 'message': 'Verification code for this user does not exist!'})

    if verificationCodeInDb['verificationCode'] != jsonData['verificationCode']:
        return jsonify({'error': True, 'message': 'Code does not match!'})
    
    try:
        user.updateUserAccountStatusToVerfied(jsonData['email'])
    except:
        return jsonify({'error': True, 'message': 'Could not update the account status!'})
    
    try:
        verificationCodeFactory.deleteVerificationCode(jsonData['email'])
    except:
        return jsonify({'error': True, 'message': 'Could not delete verification code from db!'})
    
    return jsonify({'error': False, 'message': 'Email address is now verified!'})
    

@Routes.route('/login', methods=['POST'])
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

    try:
        user = UserFactory()
        sessionFactory = SessionFactory()
    except:
        return jsonify({'error': True, 'message': 'Can\'t initialize db tables!'})

    if not user.userAlreadyExistsInDB(jsonData['email']):
        return jsonify({'error': True, 'message': 'User not found. Please register!'})
    
    passwordFromDB = user.getUserPassword(jsonData['email'])[0][0]
    if not pt(jsonData['password'].encode("utf-8")).check_password(passwordFromDB.encode("utf-8")):
        return jsonify({'error': True, 'message': 'Incorrect credentials!'})
    
    if not user.userIsVerfied(jsonData['email']):
        return jsonify({'error': True, 'message': 'User is not yet verfied! Check email!'})
    
    if user.userIsLocked(jsonData['email']):
        return jsonify({'error': True, 'message': 'User\'s account is locked!'})
    
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
    
    res = make_response(jsonify({'error': False, 'message': 'Authentication successfull!'}))
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
    #res.headers.add('Access-Control-Allow-Origin', '127.0.0.1:5500')
    return res
    

@Routes.route('/reset-password-initial', methods=['POST'])
def reset_password_initial():
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
    tokenData = passwordResetFactory.getPasswordResetTokenData()
    if tokenData['token']:
        if passwordResetFactory.isTokenExpired():
            try:
                passwordResetFactory.updateTokenExpiration(randomToken)
                return jsonify({'error': False, 'message': 'Token update.'})
            except:
                return jsonify({'error': True, 'message': 'Unable to update token.'})
        else:
            return jsonify({'error': True, 'message': 'Token is not expired yet. Please check your email'})
    
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
    
    tokenData = passwordResetFactory.getPasswordResetTokenData()
    if not tokenData['token']:
        return jsonify({'error': True, 'message': 'User has not initiated a password reset!'})

    if passwordResetFactory.isTokenExpired():
        return jsonify({'error': True, 'message': 'Token has expired! Please resubmit anouther request!'})

    if tokenData['token'] != token:
        return jsonify({'error': True, 'message': 'Token doesn\'t match!'})

    if not user.userAlreadyExistsInDB(jsonData['email']):
        return jsonify({'error': True, 'message': 'Hmmm... User not found!'})

    hashedPassword = passwordHandler.encrypt_password()
    try:
        user.updateUserPassword(jsonData['email'], hashedPassword)
        passwordResetFactory.deleteTokenData()
    except:
        return jsonify({'error': True, 'message': 'Could not update password for the user!'})
    
    return jsonify({'error': False, 'message': 'Password changed successfully'})
    

@Routes.route('/delete-user', methods=['DELETE'])
def delete_user():

    jsonData = request.get_json()
    if not 'email' in jsonData or not jsonData['email'] or not jsonData:
        return jsonify({'error': True, 'message': 'Missing data. Request Not Acceptable!'})
    if not 'password' in jsonData or not jsonData['password'] or not jsonData:
        return jsonify({'error': True, 'message': 'Missing data. Request Not Acceptable!'})
    
    try:
        user = UserFactory()
    except:
        return jsonify({'error': True, 'message': 'Cannot initialize user table!'})
    
    if not user.userAlreadyExistsInDB(jsonData['email']):
        return jsonify({'error': True, 'message': 'User does not exist!'})

    passwordFromDB = user.getUserPassword(jsonData['email'])[0][0]
    passwordHandler = pt(jsonData['password'].encode("utf-8"))
    try:
        if not passwordHandler.check_password(passwordFromDB.encode("utf-8")):
            return jsonify({'error': True, 'message': 'Iccorrect password. Could not delete user!'})
    except:
        return jsonify({'error': True, 'message': 'Unable to delete user. Try resetting password and then delete your account!'})
    
    try:
        user.deleteUser(jsonData['email'])
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
    


def getPublicIpAddressOfClient():
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        return request.environ['REMOTE_ADDR']
    else:
        return request.environ['HTTP_X_FORWARDED_FOR']