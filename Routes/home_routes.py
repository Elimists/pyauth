from flask import request, jsonify, make_response
from Routes import Routes

@Routes.route('/home', methods=['GET'])
def home():
    res = make_response(jsonify({'status': 'Connected', 'message': 'Hello from home route! Changed'}))
    return res