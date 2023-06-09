from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from flask_assets import Environment,Bundle
from flask_wtf.csrf import CSRFProtect
from flask_migrate import Migrate

app = Flask(__name__)

db = SQLAlchemy(app)# db here
mmirr = Migrate(app,db)
bcrypt = Bcrypt(app)

app.config['SECRET_KEY'] = ''
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
csrf = CSRFProtect(app)

assets = Environment(app)
css_admin = Bundle("style.css",filters="cssmin",output="gen/packed.css")
assets.register("css_admin",css_admin)

css_admin2 = Bundle("login.css",filters="cssmin",output="gen/packed2.css")
assets.register("css_admin2",css_admin2)



UPLOAD_FOLDER = '../static/img/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"
app.config["MAIL_SERVER"] = "smtp.googlemail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "mexaw0bot@gmail.com"
app.config["MAIL_PASSWORD"] = ""
mail = Mail(app)

from falcon_web import routes
