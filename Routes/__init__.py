from flask import Flask
from flask_cors import CORS
import os

Routes = Flask(__name__)
Routes.config['SERVER_NAME'] = os.getenv('SERVER')
Routes.config['APPLICATION_ROOT'] = '/api' 
cors = CORS(Routes, resources={
    r"*": {"origins": os.getenv('ORIGINS')}
    }
)

from Routes import Auth
from Routes import PasswordReset
from Routes import User
from Routes import ErrorRoutes