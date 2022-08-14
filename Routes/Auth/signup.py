from flask import request, jsonify, make_response
from Routes import Routes


@Routes.route('/newsignup', methods=['POST'])
def signup():
    return jsonify({'error': False, 'message': "Hello from autho folder!"})