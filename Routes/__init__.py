from flask import Flask
from flask_cors import CORS
import os

Routes = Flask(__name__)
Routes.config['SERVER_NAME'] = os.getenv('SERVER') # Set to localhost on DEV. Change this in production to your domain.
Routes.config['APPLICATION_ROOT'] = '/api' # Idicates the url a request is sent to. So example: https://mydomain.com/api/
cors = CORS(Routes, resources={
    r"*": {"origins": os.getenv('ORIGINS')} # Only allow traffic coming from this ip address.
    }
)

from Routes import Auth
from Routes import PasswordReset
from Routes import User
from Routes import ErrorRoutes