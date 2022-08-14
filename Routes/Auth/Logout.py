from flask import request, jsonify, make_response
from Routes import Routes
from Database import SessionFactory

CLIENT_DOMAIN = "http://127.0.0.1"

@Routes.route('/api/logout', methods=['GET'])
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