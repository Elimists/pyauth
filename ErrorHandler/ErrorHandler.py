import json
from flask import jsonify

class ErrorHandler:

    """
    error: True or False,
    code: 4 digit code for error as define in Errors.py
    message: String message describing the error. Can be empty
    """


    def packet(error, code, message):
        return jsonify({'error': error, 'code': code, 'message': message})
