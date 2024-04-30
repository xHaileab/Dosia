from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_session import Session  
from config import Config
from flask_cors import CORS

app = Flask(__name__)
app.config.from_object(Config)

# Session configuration
app.config['SECRET_KEY'] = 'ayii'  # Set a secure secret key
app.config['SESSION_TYPE'] = 'filesystem'  # Store sessions on the filesystem
app.config['SESSION_FILE_DIR'] = 'C:/DEVELOPMENT/Dosia/path_to_session_files'  # Define path for session files
app.config['SESSION_PERMANENT'] = True

Session(app)  # Initialize Flask-Session

db = SQLAlchemy(app)
migrate = Migrate(app, db)

CORS(app, supports_credentials=True)

from . import routes  # Import routes
from . import models  # Import models after db initialization to avoid circular imports
