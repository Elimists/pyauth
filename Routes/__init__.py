from flask import Flask
from flask_cors import CORS

Routes = Flask(__name__)
Routes.config['APPLICATION_ROOT'] = '/api' # Idicates the url a request is sent to. So example: https://mydomain.com/api/
cors = CORS(Routes, resources={
    r"*": {"origins": "http://127.0.0.1:5500/"} # Only allow traffic coming from this ip address.
    }
)


from Routes import Auth
from Routes import error_routes