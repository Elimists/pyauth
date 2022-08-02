from flask import Flask
from flask_cors import CORS

Routes = Flask(__name__)
cors = CORS(Routes, resources={
    r"*": {"origins": "http://127.0.0.1:5500"}
    }
)

from Routes import auth_routes
from Routes import home_routes