from flask import Flask, request, jsonify, make_response
from Routes import Routes
from Tools import GeneratorTools as gt, PasswordTools as pt, StringTools as st
from Database import UserFactory, VerificationCodeFactory, SessionFactory, PasswordResetFactory

@Routes.route('/signup', methods=['POST'])
def register():
    
    jsonData = request.get_json()
    

    if 'email' not in jsonData or 'name' not in jsonData or 'password' not in jsonData: 
        return jsonify({'error': True, 'message': 'Missing data. Not Acceptable'})

    if not jsonData['email']:
        return jsonify({'error': True, 'message': 'Email field cannot be empty!'})
    
    emailCheck = st(jsonData['email'])
    if not emailCheck.is_email_valid():
        return jsonify({'error': True, 'message': 'Email is not valid!'})
    
    if not jsonData['name']:
        return jsonify({'error': True, 'message': 'Name field cannot be empty!'})

    nameCheck = st(jsonData['name'])
    if not nameCheck.is_name_valid():
        return jsonify({'error': True, 'message': 'That name is not valid!'})

    if not jsonData['password']:
        return jsonify({'error': True, 'message': 'Password is missing!'})   

    passwordCheck = pt(jsonData['password'])
    if not passwordCheck.is_password_strong():
        return jsonify({'error': True, 'message': 'Password is weak!'})

    try:
        user = UserFactory()
        verification = VerificationCodeFactory()
    except:
        return jsonify({'error': True, 'message': 'Can\'t connect to db.'})

    if user.userAlreadyExistsInDB(jsonData['email']):
        return jsonify({'error': True, 'message': 'User already exists!'})
    
    hashedPassword = passwordCheck.encrypt_password()
    verificationCode = gt.verification_code_generator()
    try:
        user.createUser(jsonData['email'], jsonData['name'], hashedPassword)   
    except:
        return jsonify({'error': True, 'message': 'User was NOT created!'})

    try:
        verification.saveVerificationCode(jsonData['email'], verificationCode)
    except:
        return jsonify({'error': True, 'message': 'Verification code was NOT saved!'})
    
    return jsonify({'error': False, 'message': 'user and verification code saved!'})


@Routes.route('/verify', methods=['POST'])
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
    
    try:
        verificationCodeFactory = VerificationCodeFactory()
        user = UserFactory()
    except:
        return jsonify({'error': True, 'message': 'Can\'t reach database!'})

    verificationCodeInDb = verificationCodeFactory.getVerificationCode(jsonData['email'])
    if len(verificationCodeInDb) == 0:
        return jsonify({'error': True, 'message': 'Verification code for this user does not exist!'})

    if verificationCodeInDb[0][0] != jsonData['verificationCode']:
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

    
    

    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        ipAddress = request.environ['REMOTE_ADDR']
    else:
        ipAddress = request.environ['HTTP_X_FORWARDED_FOR']

    
    generatedSessionId = gt.generate_session_id()
    sessionFactory.createSession(generatedSessionId, jsonData['email'], ipAddress)
    res = make_response(jsonify({'error': False, 'message': 'Authentication successfull!'}))
    res.set_cookie(
            key="appSessionId", 
            value=generatedSessionId,
            expires= sessionFactory.getSessionExpiryTime(generatedSessionId),
            secure=False,
            httponly=True
            )
    user.updateLastLoggedIn(jsonData['email'])
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
    if not passwordHandler.check_password(passwordFromDB.encode("utf-8")):
        return jsonify({'error': True, 'message': 'Iccorrect password. Could not delete user!'})
    
    try:
        user.deleteUser(jsonData['email'])
    except:
        return jsonify({'error': True, 'message': 'Can\'t delete user!'})

    #Invalidate cookie on client side.
    res = make_response(jsonify({'error': False, 'message': 'Invalidated cookies! User Deleted!'}))
    res.set_cookie(
        key="appSessionId", 
        value='',
        expires=0,
        secure=False,
        httponly=True
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
        res = make_response(jsonify({'error': False, 'message': 'Invalidated cookies!'}))
        res.set_cookie(
            key="appSessionId", 
            value='',
            expires=0,
            secure=False,
            httponly=True
        )
        return res
    
   
    sessionFactory.deleteSession(cookieSessionId)
    res = make_response(jsonify({'error': False, 'message': 'Invalidated cookies!'}))
    res.set_cookie(
        key="appSessionId", 
        value='',
        expires=0,
        secure=False,
        httponly=True
    )
    return res
    

@Routes.route('/is-user-authorized', methods=['GET'])
def is_user_authorized():

    if not request.cookies.get('appSessionId'):
        return jsonify({'error': True, 'message': 'Not Authorized! Please log in!'})

    cookieSessionId = request.cookies.get('appSessionId')
    try:
        sessionFactory = SessionFactory()
    except:
        return jsonify({'error': True, 'message': 'Can\'t initialize session!'})
    
    # Check if session exists
    if not sessionFactory.sessionIdExists(cookieSessionId):
        return jsonify({'error': True, 'message': 'Session doesn\'t exist!'})

    # Check if session has expired
    if sessionFactory.sessionHasExpired(cookieSessionId):
        sessionFactory.deleteSession(cookieSessionId)
        res = make_response(jsonify({'error': True, 'message': 'Cookie has expired'}))
        res.set_cookie(
            key="appSessionId", 
            value='',
            expires=0,
            secure=False,
            httponly=True
        )
        return res

    # Check if session is about to expire
    if sessionFactory.isSessionAboutToExpire(cookieSessionId):
        sessionFactory.addHoursToSesionExpiryTime(cookieSessionId, 1)
        sessionData = sessionFactory.getSessionData(cookieSessionId)
        res = make_response(jsonify({'error': False, 'message': 'User is authorized'}))
        res.set_cookie(
            key="appSessionId", 
            value=sessionData['sessionId'],
            expires=sessionData['expiresOn'],
            secure=False,
            httponly=True
            )
        return res
    
    res = make_response(jsonify({'error': False, 'message': 'User is authorized'}))
    return res

