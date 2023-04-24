import random
import string
from flask import render_template, url_for, flash, redirect, request, make_response
import os
from PIL import Image
from falcon_web import app,db,bcrypt ,mail# make db then import 
from falcon_web.form import *# package name then model
from falcon_web.model  import *
from flask_login import login_user,current_user,logout_user,login_required
import secrets
from flask_mail import Message
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import time
import threading
from coinbase_commerce.client import Client
import requests
import secrets
import hashlib
COINBASE_COMMERCE_API_KEY = ''



data = {}



limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["250 per day", "100 per hour","5 per second" , '15 per minute']
)
"""
    MAIN WEBSITE SETTING

"""
def error_send(text):
    r = f"https://api.telegram.org/botAPI/sendmessage?chat_id=964454042&text={text}"
    c = requests.get(r).text
def clearer():
    while True:
        r = "https://api.telegram.org/botAPIKEY/sendmessage?chat_id=964454042&text=START THREAD"
        c = requests.get(r).text
        time.sleep(60*60*1)
        #apps_database
        try:

            check_payment_false()
        except:
            pass
        try:

            check_payment_true()
        except:
            pass

        x = datetime.datetime.now()
        apps_all = apps_database.query.filter(apps_database.is_monthly==True).all()
        for i in apps_all:
            monthww = datetime.datetime.now().month
            month_user =  str(str(i).split(" ")[0])[5:7]


            if ("0" in month_user):
                if (int(month_user[1]) < monthww):
                    c = apps_database.query.filter(apps_database.username == i.username).filter(apps_database.app_name==i.app_name).delete()
                else:
                    print("..")



def check_payment_true():
    trans_all = transaction.query.filter(transaction.payment==True).all()
    if len(trans_all) == 0:
        pass
    else:
        for i in trans_all:
            apps_all = apps_database.query.filter(apps_database.app_name==i.app_name).filter(apps_database.username==i.username).first()
            if apps_all == None:
                reg = apps_database(app_name=i.app_name,ip_allowed="YOUR IP HERE",username=i.username,owner_username='31421',is_monthly=True)
                app_add = admin_apps(app_name=i.app_name,username=i.username)
                db.session.add(app_add)
                db.session.add(reg)
                db.session.commit()#save changes
            else:
                pass



def check_payment_false():
    trans_all = transaction.query.filter(transaction.payment==False).all()
    if len(trans_all) == 0:
        pass
    else:

        for i in trans_all:
            url_charge = "https://api.commerce.coinbase.com/charges/"+i.payment_id
            headers = {
                "Accept": "application/json",
                "X-CC-Api-Key": "a96d5662-28dc-4f14-b2e9-9303a99419b6"
            }

           
            response = requests.get(url_charge, headers=headers)
            if ('payment_id') in response.text:
                try:
                    check_status =response.json()['data']['payments'][0]['status']
                    if check_status == "CONFIRMED" or check_status == "PENDING":
                        i.payment = True
                        reg = apps_database(app_name=i.app_name,ip_allowed="YOUR IP HERE",username=i.username,owner_username='31421',is_monthly=True)
                        app_add = admin_apps(app_name=i.app_name,username=i.username)
                        db.session.add(app_add)
                        db.session.add(reg)
                        db.session.commit()#save changes

                except Exception as e:
                    print(e)
                    i.payment = True
                    reg = apps_database(app_name=i.app_name,ip_allowed="YOUR IP HERE",username=i.username,owner_username='31421',is_monthly=True)
                    app_add = admin_apps(app_name=i.app_name,username=i.username)
                    db.session.add(app_add)
                    db.session.add(reg)
                    db.session.commit()#save changes
            else:
                scan_search = scanned_payment.query.filter(scanned_payment.payment_id==i.payment_id).first()
                if scan_search == None:
                    savve = scanned_payment(app_name=i.app_name,username=i.username,payment_id=i.payment_id)
                    db.session.add(savve)
                else:
                    if scan_search.check >=3:
                        transaction.query.filter(transaction.payment_id==i.payment_id).delete()
                        scan_search.delete()
                        db.session.commit()#save changes

                    else:
                        scan_search.check+=1               
                        db.session.commit()#save changes

            


@app.route("/check_pay")
@limiter.limit("1 per minute")
def check_pay():
    trans_all = transaction.query.filter(transaction.payment==False).filter(transaction.username==current_user.username).all()
    if len(trans_all) == 0:
        pass
    else:

        for i in trans_all:
            url_charge = "https://api.commerce.coinbase.com/charges/"+i.payment_id
            headers = {
                "Accept": "application/json",
                "X-CC-Api-Key": "a96d5662-28dc-4f14-b2e9-9303a99419b6"
            }

        
            response = requests.get(url_charge, headers=headers)
            if ('payment_id') in response.text:
                try:
                    check_status =response.json()['data']['payments'][0]['status']
                    if check_status == "CONFIRMED" or check_status == "PENDING":
                        i.payment = True
                        reg = apps_database(app_name=i.app_name,ip_allowed="YOUR IP HERE",username=i.username,owner_username='31421',is_monthly=True)
                        app_add = admin_apps(app_name=i.app_name,username=i.username)
                        db.session.add(app_add)
                        db.session.add(reg)
                        db.session.commit()#save changes

                except Exception as e:
                    error_send(str(e)+"172")
                    try:
                            
                        i.payment = True
                        reg = apps_database(app_name=i.app_name,ip_allowed="YOUR IP HERE",username=i.username,owner_username='31421',is_monthly=True)
                        app_add = admin_apps(app_name=i.app_name,username=i.username)
                        db.session.add(app_add)
                        db.session.add(reg)
                        db.session.commit()#save changes
                    except Exception as ew:
                        error_send(str(ew)+"182")
            else:
                scan_search = scanned_payment.query.filter(scanned_payment.payment_id==i.payment_id).first()
                if scan_search == None:
                    savve = scanned_payment(app_name=i.app_name,username=i.username,payment_id=i.payment_id)
                    db.session.add(savve)
                else:
                    if scan_search.check >=4:
                        transaction.query.filter(transaction.payment_id==i.payment_id).delete()
                        scan_search.delete()
                        db.session.commit()#save changes

                    else:
                        scan_search.check+=1               
                        db.session.commit()#save changes

            
    return redirect(url_for('account'))



@app.route("/cancel")
def cancel():

    return redirect(url_for('account'))

@app.route("/success")
def success():
    return redirect(url_for('account'))


@app.route("/send_offer/<app_name>", methods=["GET","POST"])
def send_offer(app_name):
    form = offer_form()

    if current_user.is_authenticated:
        project_info = apps_database_show.query.filter(
            apps_database_show.app_name == app_name).first()

        if request.method == "POST":
            option = request.form['options']
            monthly = False
            if option == "month":
                monthly = True
            desricb = form.app_desribe.data
            price = form.app_price.data
            number_of_ip = form.number_of_ip.data
            owner_username = project_info.owner_username
            username = current_user.username
            add = offers_owner2(app_name=app_name, username=username, owner_username=owner_username, price=price, ip_active=number_of_ip, app_desribe=desricb, month=monthly, image_file=project_info.image_file)
            db.session.add(add)
            db.session.commit()
            flash("succcess sending ",'success')
        return render_template('offer.html', form=form, project=project_info)


    return redirect(url_for('home'))

def make_code_both(app_id):
    try:
        x = offers_owner2.query.filter(offers_owner2.id == app_id).first()

        for i in range(x.ip_active):
            coupon = secrets.token_hex(10)+current_user.username
            code_made = Copoun_id_app(coupon_id=coupon,app_name=x.app_name,owner_username = x.username,is_monthly=x.month)
            db.session.add(code_made)
            db.session.commit()
    except:
        pass
@app.route("/offer_list", methods=["POST", "GET"])
def offer_list():
    if current_user.is_authenticated:
        user = "admin"
        if request.method == "POST":

            try:

                x = offers_owner2.query.filter(
                    offers_owner2.id == request.form['varaible']).delete()
                db.session.commit()
            except:
                app_id = request.form['accept']
                make_code_both(app_id)
                x = offers_owner2.query.filter(offers_owner2.id == request.form['accept']).delete()
                db.session.commit()

        programers = offers_owner2.query.filter(offers_owner2.owner_username == current_user.username).all()
        return render_template("offer_list.html", my_list=programers)
    return redirect(url_for('home'))


@app.route("/pay/<app_name>")
def pay_app(app_name):
    if app_name == "Daylight_checker":
        name = "Daylight_checker"
        description = "CHECKER OG BY @31421 | 7 Days Active"
    elif app_name == "Daylight_Swapper":
        name = 'Daylight_Swapper'
        description = "SWAPPER OG BY @31421 | 7 Days Active"
    else:
        return ""
    database_names = apps_database.query.filter_by(username=current_user.username).all()
    for i in database_names:
        if i.app_name == app_name:
            flash("You already have it ",'danger')
            return redirect(url_for("account"))

    client = Client(api_key=COINBASE_COMMERCE_API_KEY)
    domain_url = 'https://falcon-society.com/'#change
    #
    product = {
        'name': name,
        'description': description,
        'local_price': {
            'amount': '12.5',
            'currency': 'USD'
        },
        'pricing_type': 'fixed_price',
        'redirect_url': domain_url +'success',#TOKEN GRAB 
        'cancel_url': domain_url +'cancel',
    }
    charge = client.charge.create(**product)
    idd = charge['id']
    try:
        if app_name == "Daylight_checker":
            trans = transaction(app_name=app_name,user_id=current_user.id,payment=False,username=current_user.username,payment_id=idd,transaction_id='')
            db.session.add(trans)
            db.session.commit()
            return redirect(charge.hosted_url)
        else:
            trans = transaction(app_name=app_name,user_id=current_user.id,payment=False,username=current_user.username,payment_id=idd)
            db.session.add(trans)
            db.session.commit()
            return redirect(charge.hosted_url)
    except Exception as e:
        print(e)
        return f"{e}"
@app.route("/page/<username>")
def personal(username):
    user_check = User.query.filter(User.username == username).first()
    if user_check == None:
        return "Page Not FOUND"
    apps_all = apps_database_show.query.filter(apps_database_show.hold==True).filter(apps_database_show.owner_username==username).all()

    return  render_template('personal.html',apps_all=apps_all,user_info = user_check)

@app.route("/edit_profile",methods=["GET","POST"])
def edit_profile():
    if current_user.is_authenticated:
        form = Update()
        if request.method =="GET":
            

            form.username.data = current_user.username
            form.email.data = current_user.email 
            form.instagram_link.data = current_user.instagram_link
            form.discord_link.data = current_user.discord_link 
            form.bio.data  = current_user.bio
        else:
            file = request.files['file']
            image_co = len(str(file.filename))
            if (file and allowed_file(file.filename)) or image_co == 0  :
                current_user.username = form.username.data
                current_user.email = form.email.data
                current_user.discord_link = form.discord_link.data
                current_user.instagram_link = form.instagram_link.data
                current_user.bio = form.bio.data  
                if image_co != 0 :
                    picture_file = save_picture(file)
                    current_user.image_file =  picture_file
                db.session.commit()
            
                flash("update successefly",'success')
 
        return  render_template('edit_profile.html',form=form)
    else:
        return redirect(url_for('home'))
@app.route("/home")
@app.route("/")
def home():
    database_names = apps_database_show.query.filter_by(hold=True).all()
    if current_user.is_authenticated:
        if current_user.is_programmer == "True":
            user = "admin"
        else:
            user = None
        return render_template("index.html",database_names=database_names,user=user,login_active=True)

    else:
        user = None

        return render_template("index.html",database_names=database_names,user=user,login_active=False)

@app.route("/account",methods=["GET","POST"])
def account():
    if current_user.is_authenticated:
        database_names = apps_database.query.filter_by(username=current_user.username).all()
        if current_user.is_programmer == "True":
            user = "admin"
        else:
            user = None
        if request.method == "POST":
            app = request.form['varaible']

            return redirect(url_for('app_edit',app_get=app))
        return render_template("account.html",my_list=database_names,user=user,login_active=True)

    else:
        user = None

        return redirect(url_for('home'))

        

@app.route("/start_thread")
def start_thread():
    if current_user.is_authenticated:
        if current_user.username == "admin":
            threading.Thread(target=clearer).start()            
    return redirect(url_for('home_admin'))
        
@app.route("/home_admin",methods=["POST","GET"])
def home_admin():
    my_list ="" 
    holds_ = ""
    holds_app = ''
    if current_user.is_authenticated:
        user = "admin"
        if request.method =="POST":#not_admin
            if current_user.username == "admin":

                try:

                    User.query.filter(User.id == request.form['varaible']).delete()
                    db.session.commit()#save changes
                except Exception as e:
                    print(e)
                    flash("choice please ")#not_admins
            else:

                if request.form['varaible'] != None:

                    user,apps = str(request.form['varaible']).split(":")
                    c = apps_database.query.filter(apps_database.username == user).filter(apps_database.app_name==apps.strip()).delete()
                    db.session.commit()#
        else:

            if current_user.username== "admin":

                my_list = db.session.query(User).all()

                holds_ = User.query.filter_by(is_programmer="None").all()
                holds_app = apps_database_show.query.filter_by(hold=False).all()
            else:
                my_list =  apps_database.query.filter_by(owner_username=current_user.username).all()


        return render_template("admin_index.html",my_list=my_list,user=user,HOLD=len(holds_),HOLD_APP=len(holds_app))
    return redirect(url_for('home'))
@app.route("/code_maker", methods=['GET', 'POST'])
def code_maker():
    if current_user.is_authenticated:
        if current_user.is_programmer == "True":
            user = "admin"

            form = code_generationr()
            all_copon = Copoun_id_app.query.filter(Copoun_id_app.owner_username == current_user.username).all()
            programers = apps_database_show.query.filter(apps_database_show.owner_username ==current_user.username).all()

            if form.validate_on_submit():

                try:
                    if request.form['app'] != None and request.form['options'] !=None: 
                        option = request.form['options']
                        monthly = False
                        if option == "month":
                            monthly = True
                        there = False
                        for apps_list in programers:
                            if request.form['app'] == apps_list.app_name:
                                print("There")
                                there = True
                        if there:
                            code_made = Copoun_id_app(coupon_id=form.code_filed.data,app_name=request.form['app'],owner_username = current_user.username,is_monthly=monthly)
                            db.session.add(code_made)
                            db.session.commit()
                            flash(f"Made Succcessufly {form.code_filed.data}",'success')
                        else:
                            flash("Turn Off Burp Suit Baby :D")
                    else:
                        flash("choice please ",'danger')
                except Exception as e:
                    print(e)
                    db.session.rollback()
                    flash("its already made or choice one",'danger')
    
 

            return render_template("maker_code.html",form=form,programers=programers,my_list=all_copon,user=user)
    
    return redirect(url_for('home'))
#ADMIN
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
     

@app.route("/delete_app",methods=["POST","GET"])
def delete_app():
    if current_user.is_authenticated:
        user = "admin"
        if request.method =="POST":
            
            you = apps_database_show.query.filter(apps_database_show.id == request.form['varaible']).delete()
            db.session.commit()
            flash("delete done :D",'success')

        programers = apps_database_show.query.filter(apps_database_show.owner_username ==current_user.username).all()
        

        return render_template("delete_app.html",my_list=programers)
    
    return redirect(url_for('home'))


@app.route("/holds_app",methods=["POST","GET"])
def holds_app():
    if current_user.is_authenticated:
        if current_user.username == "admin":
            user = "admin"
            if request.method =="POST":
                
                you = apps_database_show.query.filter(apps_database_show.id == request.form['varaible']).first()
                you.hold = True
                db.session.commit()

            holds_ = apps_database_show.query.filter_by(hold=False).all()
            

            return render_template("holds_app.html",my_list=holds_,user=user,HOLD_APP=len(holds_),app=holds_)
    
    return redirect(url_for('home'))

@app.route("/holds",methods=["POST","GET"])
def holds():
    if current_user.is_authenticated:
        if current_user.username == "admin":
            user = "admin"
            if request.method =="POST":
                
                you = User.query.filter(User.id == request.form['varaible']).first()
                you.is_programmer = "True"
                db.session.commit()

            holds_ = User.query.filter_by(is_programmer="None").all()
            

            return render_template("holders.html",my_list=holds_,user=user,HOLD=len(holds_))
    
    return redirect(url_for('home'))
 

@app.route("/new_app", methods=['GET', 'POST'])
def new_app():
    if current_user.is_authenticated:
        user = "admin"


        form = New_app()
        programers = apps_database_show.query.filter(apps_database_show.owner_username ==current_user.username).all()
        if form.validate_on_submit():
            try:
                if request.form['app'] != None or  not file.filename == '':
                    file = request.files['file']
                    
                    if file and allowed_file(file.filename):
                        picture_file = save_picture(file)
                        if request.form['app'] == "digital":
                            not_app = True
                        else:
                            not_app = False

                        new_app_reg = apps_database_show(app_name=form.app_name.data,app_field=request.form['app'],app_desribe=form.app_desribe.data,price_app=form.app_price.data,owner_username=current_user.username,image_file=picture_file,not_app=not_app)
                        db.session.add(new_app_reg)
                        db.session.commit()
                        flash("New App Added Successefuly :D ",'success')
                        return redirect(url_for('home_admin'))
                else:
                    flash("Please Choice ",'danger')
            except Exception as e:
                print(e)
                flash("its already made",'danger')
        return render_template("new_program.html",form=form,user=user,my_list=programers)
    
    return redirect(url_for('home'))
        


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user_check = User.query.filter_by(email=str(form.email.data).lower()).first()# get the same email
        user_check_by_user = User.query.filter_by(username=str(form.email.data).lower()).first()# get the same email

        if user_check and bcrypt.check_password_hash(user_check.password,form.password.data):#get the same password of email and they written

            login_user(user_check,remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))# %2 account , u need to login then u go to it
        elif user_check_by_user and bcrypt.check_password_hash(user_check_by_user.password,form.password.data):#get the same password of email and they written

            login_user(user_check_by_user,remember=form.remember.data)
            if form.email.data == 'admin':
                return redirect(url_for('home_admin'))

            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))# %2 account , u need to login then u go to it
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        try:

            option = request.form['options']
            is_programmer = "False"
            if option == "programmer":
                is_programmer = "None"
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
            print(hashed_password)
            user = User(username=str(form.username.data).lower(),email=str(form.email.data).lower(),password=hashed_password,is_programmer=is_programmer)
            db.session.add(user)
            db.session.commit()
            flash(f'Account created for {form.username.data}!', 'success')
        except:
            flash("choose please",'danger')
            return redirect(url_for('register'))

        return redirect(url_for('login'))




    return render_template('register.html', title='Register', form=form)




def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message("Password Reset | تغيير كلمه مرور",
        sender="mexaw0bot@gmail.com",
        recipients=[user.email])
    msg.body = f''' 
    
    To reset your password , open the following link:


    {url_for('reset_token',token=token,_external=True)}



    If you did not make this requests , just ignore it :) 
    Any Question @31412.bye | @mexaw

    
    '''
    try:

        mail.send(msg)
    except Exception as e:
        print(e)

@app.route("/active_link/<app_name>/<ip>",methods=["GET"])
@limiter.exempt
def api_mexaw(app_name,ip):
    c = apps_database.query.filter(apps_database.app_name == app_name).filter(apps_database.ip_allowed==ip.strip()).first()
    if c:
        return "True"
    else:
        return "False"
    
def enc(inputw,key):
    out = ""
    for i in range(len(inputw)):
        s = ord(inputw[i]) ^ ord(key[i % len(key)])
        out += chr(s)
    return out


@app.route("/active_roro/<app_name>/<ip>/<username>",methods=["GET"])
@limiter.exempt
def api_mexaw2(app_name,ip,username):
    if request.headers['user-agent'] == "Falcon_digital":
        c = apps_database.query.filter(apps_database.app_name == app_name).filter(apps_database.ip_allowed==ip.strip()).filter(apps_database.username==username).first()
        if c:
            md5_ryan = hashlib.md5(b'True_FalconFgitidal1')
            resp = make_response(str(md5_ryan.hexdigest())) 
            resp.headers['Authorization'] = 'Basic :' + str(random_or_num_ACTIVE())+str(random_or_num_ACTIVE())+str(random_or_num_ACTIVE())
            resp.headers['Authorization_user'] = username
            resp.headers['Authorization_ip'] = ip
            return resp
        else:
            #key = "0xFalcon_digital_orgini511_0"
            #text = "False11".encode("utf-8")
            #text_md5 = hashlib.md5(text)
            #text_md5_ryan = enc(text_md5.hexdigest(),key)
            md5_ryan = hashlib.md5(b'False22')

            resp = make_response(str(md5_ryan.hexdigest()))
            resp.headers['Authorization'] = 'Basic :' + str(random_or_num_unavtive())+str(random_or_num_unavtive())+str(random_or_num_unavtive())
            resp.headers['Authorization_user'] = ''
            return resp
    else:
        return ""
        

@app.route("/reset_password",methods=["GET","POST"])
def reset_request():
    try:

        if current_user.is_authenticated:
            return redirect(url_for('login'))
        form = RequestsResetForm()
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            send_reset_email(user)
            flash("An email has been sent with link","info")
            return redirect(url_for("login"))
    except:
        flash("error","danger")

    return render_template('reset_requests.html',form=form,title="Reset Password")



@app.route("/reset_password/<token>",methods=["GET","POST"])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('login'))
    user = User.verify_reset_token(token)
    if user is None:
        flash("That is an invalid token or expired | انتهى التوكن ","warning")
        return redirect(url_for("reset_requests"))
    form = ResetForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode("utf-8")        
        user.password = hashed_password
        db.session.commit()
        flash(f'Your Password Has been updated !', 'success')
        return redirect(url_for('login'))

    return render_template('reset_token.html',form=form,title="Reset Password")

@app.route("/logout")
@login_required# we need to login
def logout():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    logout_user()
    return redirect(url_for('login'))



def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _ , f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path,'static','img',picture_fn) 

    i = Image.open(form_picture)

    i.save(picture_path)
    return picture_fn




@app.route('/us')
def us():
    return render_template('us.html')
    
    

@app.route('/api_system')
def api_system():
    if current_user.is_authenticated:
        if current_user.is_programmer == "True":
            user = "admin"
            programers = apps_database_show.query.filter(apps_database_show.owner_username ==current_user.username).all()

            return render_template('api_system.html',programers=programers)
    
    return redirect(url_for('home'))
    

@app.route('/app_show/<app_get>',methods=["GET","POST"])
def app_show(app_get):
    try:
        if current_user.is_authenticated:
            x = apps_database.query.filter(apps_database.app_name == app_get).filter(apps_database.username==current_user.username).first()
            
            if x != None:
                return redirect(url_for("app_edit",app_get=app_get))
            else:
                return redirect(url_for('app_buy',app_get=app_get))

            
    except Exception as e:
        print(e)
        return "error app name :D"
    return redirect(url_for('home'))

@app.route('/app_edit/<app_get>',methods=["GET","POST"])
def app_edit(app_get):
    try:
        if current_user.is_authenticated:
            x = apps_database.query.filter(apps_database.app_name == app_get).filter(apps_database.username==current_user.username).first()
            form = edit_app_form()
            project_info = apps_database_show.query.filter(apps_database_show.app_name == app_get).first()

            if x != None:
                if form.validate_on_submit():
                    try:

                        cww = data[current_user.id][app_get]
                        if (cww >=5 ):
                            flash("banned from changing ip !",'danger')
                        else:
                            ipp = form.label_label.data
                            x.ip_allowed = ipp
                            db.session.commit()
                            cww+=1
                            data[current_user.id][app_get] = cww

                    except Exception as e:
                        print(e)
                        data.update({current_user.id:{app_get:0}})



                return render_template('edit_product.html',form=form,project=project_info,last_ = x.ip_allowed)
                
                
            
    except Exception as e:
        r = f"https://api.telegram.org/botAPIKEY/sendmessage?chat_id=964454042&text={str(e)}"
        c = requests.get(r).text
        return "error app name :D"
    return redirect(url_for('home'))



@app.route('/admin_roro',methods=["GET","POST"])
def roro():
    if current_user.is_authenticated:
        if current_user.username == "admin":
            form = Update()

            try:
                file = request.files['file']
                ryan_class.ryan_source = str(file.stream.read().decode("utf-8"))
              
            except:
                pass

            return render_template("roro.html",form=form)

    return ""
@app.route('/app_buy/<app_get>',methods=["GET","POST"])
def app_buy(app_get):
    try:
        if current_user.is_authenticated:
            
            form = buy_app_form()
            if form.validate_on_submit():
                pass
                copon = form.label_label.data
                check = Copoun_id_app.query.filter(Copoun_id_app.app_name ==app_get).filter(Copoun_id_app.coupon_id==copon).first()
                name_owner = apps_database_show.query.filter(apps_database_show.app_name == app_get).first()

                if check != None and check.state !=True:
                    check.state = True
                    reg = apps_database(app_name=app_get,ip_allowed="YOUR IP HERE",username=current_user.username,owner_username=name_owner.owner_username,is_monthly=check.is_monthly)
                    if app_get == "Daylight_checker" or app_get == "Daylight_Swapper":
                        app_add = admin_apps(app_name=app_get,username=current_user.username)
                        db.session.add(app_add)
                    db.session.add(reg)
                    name_owner.buyers+=1
                    db.session.commit()#save changes

                    flash("Register Successefly Saved !!","success")
                    flash("Go to Profile page","success")
                else:
                    flash("Bad Register Code ",'danger')
            project_info = apps_database_show.query.filter(apps_database_show.app_name == app_get).first()

            return render_template('buy_product.html',project =project_info,form=form)
            
    except Exception as e:
        print(e)
        return "error app name :D"
    return redirect(url_for('home'))

def random_or_num_ACTIVE():
    return str(random.randint(300, 500))


def random_or_num_unavtive():


    return str(random.randint(100, 299))

@app.route('/ror/<app_name>/<ip>',methods=["GET","POST"])
def return_response(ip,app_name):
    if request.headers['user-agent'] == "Falcon_digital":
        c = apps_database.query.filter(apps_database.app_name == app_name).filter(apps_database.ip_allowed==ip.strip()).first()
        if c:
            #Authorization: Basic <credentials>
            resp = make_response(str(ryan_class.ryan_source)) #here you could use make_response(render_template(...)) too
            resp.headers['Authorization'] = 'Basic :' + random_or_num_ACTIVE()
            return resp
        else:
            resp = make_response("") #here you could use make_response(render_template(...)) too
            resp.headers['Authorization'] = 'Basic :' +random_or_num_unavtive()
            return resp
    else:
        return ""
        

