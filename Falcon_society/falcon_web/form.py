from flask_wtf import FlaskForm
from flask_wtf.file import FileField,FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, validators, IntegerField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from falcon_web.model import User # to check if user in db or not


class RegistrationForm(FlaskForm):
    username = StringField('Username [حسابك في الانستقرام مهم ]',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

    submit = SubmitField('Sign Up')

    def validate_username(self,username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken')
    def validate_email(self,email):
        email_check = User.query.filter_by(email=email.data).first()
        if email_check:
            raise ValidationError('That email is taken')
class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class code_generationr(FlaskForm):
    code_filed = StringField('Enter Code',validators=[DataRequired()])
    submit = SubmitField('Make Code')

class Update(FlaskForm):
    username = StringField('Username [حسابك في الانستقرام مهم ]',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    instagram_link = StringField('Instagram link')
    discord_link =  StringField('Discord link')
    bio =  TextAreaField(u'Personal Bio ', [validators.optional(), validators.length(max=400)])
    picture = FileField("Account Picture",validators=[FileAllowed(["jpg","png","ico","jpeg"])])
    submit = SubmitField('Update')


class New_app(FlaskForm):
    app_name = StringField('APPLICTION NAME',
                           validators=[DataRequired(), ])
    label_label = StringField('Choice Field')
    app_desribe =  TextAreaField(u'APPLICTION Describe', [validators.optional(), validators.length(max=400)])
    app_price = StringField('Enter Price [IN DOLLAR WITH OUT $]')
    picture = FileField("Application Picture",validators=[FileAllowed(["jpg","png","ico","jpeg"])])
    submit = SubmitField('submit')


class offer_form(FlaskForm):
    app_desribe = TextAreaField(u'offer text [ اشرح الاتفاقييه ( متجر ولا تيم )', [
                                validators.optional(), validators.length(max=400)])
    app_price = StringField('PRICE IN $ [ سعر بالدولار')

    number_of_ip = IntegerField('IP ACTIVESTIONS [تفعيلات كم عددها]')
    submit = SubmitField('SEND')


class buy_app_form(FlaskForm):
    label_label = StringField('Register Code ')
    submit = SubmitField('Buy')
class edit_app_form(FlaskForm):
    label_label = StringField('IP ADDRESS ')
    submit = SubmitField('Save')



class RequestsResetForm(FlaskForm):
    email = StringField('Requests Password',validators=[DataRequired(),Email()])
    submit = SubmitField('Send')
    def validate_email(self,email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError("There is no account with that email")
        

class ResetForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')
