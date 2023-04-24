from falcon_web import db,login_manager# impore each other in same time ! so don't // so we change it to main
from flask_login import UserMixin
import datetime
"""

    NOTES !!: this Models is not final version 
    not Good pratice for Models 

    For Future versions i will update this model


"""

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='12.gif')
    password = db.Column(db.String(60), nullable=False)
    regster_time = db.Column(db.String(60),default=str(datetime.datetime.now()))
    is_programmer = db.Column(db.String(5), nullable=False)
    bio = db.Column(db.String(400) , nullable=True)
    instagram_link = db.Column(db.String(120), unique=False, nullable=True)
    discord_link = db.Column(db.String(120), unique=False, nullable=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"


class Copoun_id_app(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    coupon_id = db.Column(db.String(10),unique=True, nullable=True)
    state = db.Column(db.Boolean())
    app_name = db.Column(db.String(120),unique=False, nullable=False)
    owner_username = db.Column(db.String(20),unique=False, nullable=False)
    is_monthly = db.Column(db.Boolean())

    """
    Delete After Register Then Give it Peremsion to Edit his ip 

    
    """


class apps_database(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    app_name = db.Column(db.String(120),unique=False, nullable=True)
    ip_allowed = db.Column(db.String(18), nullable=True)
    username = db.Column(db.String(80), nullable=True)
    owner_username =  db.Column(db.String(20), nullable=False)
    is_monthly = db.Column(db.Boolean())
    regster_time = db.Column(db.String(60),default=datetime.datetime.now())


class admin_apps(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    Registered = db.Column(db.DateTime, default=datetime.datetime.now(),nullable=True)
    app_name = db.Column(db.String(120),unique=False, nullable=True)
    username = db.Column(db.String(80), nullable=True)


class apps_database_show(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    app_name = db.Column(db.String(120),unique=True, nullable=False)
    app_field = db.Column(db.String(120), nullable=False)
    app_desribe = db.Column(db.String(400), nullable=False)
    price_app = db.Column(db.String(20), nullable=False)
    owner_username = db.Column(db.String(20), nullable=False)
    hold = db.Column(db.Boolean(),default=False)
    buyers = db.Column(db.Integer(),default=0)
    not_app = db.Column(db.Boolean(),default=False)
    image_file = db.Column(db.String(20), nullable=False, default='back.gif')

class transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    app_name = db.Column(db.String(120),unique=False,default="")
    user_id = db.Column(db.String(10), nullable=True)
    payment = db.Column(db.Boolean(),default=False)
    username = db.Column(db.String(80), nullable=True)
    payment_id = db.Column(db.String(80), nullable=True)
    transaction_id = db.Column(db.String(80), nullable=True)


class transaction_backup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    app_name = db.Column(db.String(120),unique=False,default="")
    user_id = db.Column(db.String(10), nullable=True)
    payment = db.Column(db.Boolean(),default=False)
    username = db.Column(db.String(80), nullable=True)
    payment_id = db.Column(db.String(80), nullable=True)
    transaction_id = db.Column(db.String(80), nullable=True)


class scanned_payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    app_name = db.Column(db.String(120),unique=False,default="")
    username = db.Column(db.String(80), nullable=True)
    payment_id = db.Column(db.String(80), nullable=True)
    check = db.Column(db.Integer(),default=0)
    


class offers_owner2(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    app_name = db.Column(db.String(120), unique=False, default="")
    username = db.Column(db.String(80), nullable=True)
    owner_username = db.Column(db.String(80), nullable=True)
    price = db.Column(db.String(80), nullable=True)
    ip_active = db.Column(db.Integer(), default=0)
    app_desribe = db.Column(db.String(400), nullable=False)
    month = db.Column(db.Boolean(), default=False)
    image_file = db.Column(db.String(20), nullable=False, default='back.gif')
