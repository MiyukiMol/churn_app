from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost/predicts2'
app.config['SECRET_KEY'] = '\x07\xb0\xd5\xd8+\xc4+\x8aa\x06A\x80_\xc5\xdc\xbb>\xfb\xb9\xe8(\xcf[\x15' #pour sécuriser les requêtes (à mettre dans le .ENV)
db = SQLAlchemy(app)
login_manager = LoginManager(app)

from app import *