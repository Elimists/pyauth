from functools import wraps
from flask import request, jsonify, make_response
from Database import SessionFactory


def is_user_authorized(f):
    
    @wraps(f)
    def decorator(*args, **kwargs):
        if not request.cookies.get('appSessionId'):
            return jsonify({'error': True, 'message': 'Cookeies are missing. Not authorized!'})

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
    return decorator