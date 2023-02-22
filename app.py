from flask import Flask, request, render_template, redirect, flash, Response
import pickle
from flask_mysqldb import MySQL
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.types import Float,Integer,String,DateTime
#from flask_migrate import Migrate

from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, LoginManager, login_user,logout_user, login_required, current_user

import os
import numpy as np
from datetime import datetime
import pytz

from webforms import LoginForm, UserForm

import flask_monitoringdashboard as dashboard
# from flask_admin import Admin
# from flask_admin.contrib.sqla import ModelView
import requests


app = Flask(__name__)



# flask monitoring dashboard
dashboard.bind(app)



#-----------------------------------------Connection Database-----------------------------------------
# MySQL DB
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://username:password@localhost/db_name'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:root@localhost/predicts2'

# encode session info with secret key
app.config['SECRET_KEY'] = '\x07\xb0\xd5\xd8+\xc4+\x8aa\x06A\x80_\xc5\xdc\xbb>\xfb\xb9\xe8(\xcf[\x15'

# initialize the database
db = SQLAlchemy(app)
#migrate = Migrate(app, db)

# associate login function and login manager
login_manager = LoginManager()
login_manager.init_app(app)
# login_view = redirect to 'login'
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

@app.route('/test')
def root():
    return "root"


# create home page
@app.route('/', methods=['GET','POST'])
def home():
    try : 
        return render_template('home.html')
    except :
        #app.logger.debug('debug')
        #app.logger.info('info')
        #app.logger.warning('message')
        app.logger.error("error - no connexion : pas de base de donnees")
        #app.logger.critical('critical - no connexion : pas de base de données')
        return Response("Error, Pas de page d'accuil", status=200, mimetype='text/html')  
    



# create login page
@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            # check the hash
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash("Login succesfull")
                #requests.post("https://ntfy.sh/alert_churn", data=f"{user} vient de se connecter".encode(encoding='utf-8'))
                return redirect('/predict')
            else:
                flash("Password incorrect")
        else:
            flash("That user doesn't exist. Please tray again")
    return render_template('login.html', form=form)

# create logout page
@app.route('/logout', methods=['GET','POST'])
@login_required # access only to login user
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect('/login')

# create user dashboard page
@app.route('/user_dashboard', methods=['GET','POST'])
@login_required
def user_dashboard():
    return render_template('user_dashboard.html')





# create BD predict
class Predict(db.Model):
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    account_length = db.Column(db.Integer, nullable=False)
    international_plan = db.Column(db.Integer, nullable=False)
    number_vmail_messages = db.Column(db.Integer, nullable=False)
    total_day_minutes = db.Column(db.Float, nullable=False)
    total_day_calls = db.Column(db.Integer, nullable=False)
    total_eve_minutes = db.Column(db.Float, nullable=False)
    total_eve_calls = db.Column(db.Integer, nullable=False)
    total_night_minutes = db.Column(db.Float, nullable=False)
    total_night_calls = db.Column(db.Integer, nullable=False)
    total_intl_minutes = db.Column(db.Float, nullable=False)
    total_intl_calls = db.Column(db.Integer, nullable=False)
    number_customer_service_calls = db.Column(db.Integer, nullable=False)
    areas = db.Column(db.String(20), nullable=False)
    # foreign key to link Users (refer to primary key of the user)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    output = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(pytz.timezone('Europe/Paris')))
    


#----------------------------------------- User class -----------------------------------------
# create BD user
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True,autoincrement=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    # User can have Many prédictions
    predict = db.relationship('Predict', backref='user', lazy=True) # associer avec foreign key
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.now(pytz.timezone('Europe/Paris')))

    @property
    def password(self):
        raise AttributeError('password is not a readable')
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    # create a string
    def __repr__(self):
        return '<name %r>' % self.name



#----------------------------------------- Role class -----------------------------------------



# register
@app.route('/user/add',methods=['GET', 'POST'])
def add_user():
    name = None
    username = None
    form = UserForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        user1 = Users.query.filter_by(username=form.username.data).first()
        if user1 is None:
            if user is None:
                # hash the password
                hashed_pw = generate_password_hash(form.password_hash.data, "sha256")
                user = Users(username=form.username.data, name=form.name.data, email=form.email.data, password_hash=hashed_pw)
                db.session.add(user)
                db.session.commit()
            
                name = form.name.data
                form.name.data = ''
                form.username.data = ''
                form.email.data = ''
                form.password_hash.data = ''
                flash("User added successfully")
            else:
                flash("Email has exist. Please try with another email")
        else:
            flash("Username exist. Please try another username")
    our_users = Users.query.order_by(Users.created_at)
  
    return render_template('register.html',
            form=form,
            name=name,
            username=username,
            our_users=our_users
            )

# update database record
@app.route("/update/<int:id>",methods=['GET', 'POST'])
@login_required
def update(id):
    form = UserForm()
    name_to_update = Users.query.get_or_404(id)
    if request.method == "POST":
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']
        try:
            db.session.commit()
            flash("User Updated Successfully!")
            return render_template("update.html",
            form=form,
            name_to_update = name_to_update)
        except:
            flash("Error...Please try again later.")
            return render_template("update.html",
            form=form,
            name_to_update = name_to_update)
    else:
        return render_template("update.html",
            form=form,
            name_to_update = name_to_update,
            id=id)


# delete database record
@app.route("/delete_user/<int:id>",methods=['GET', 'POST'])
def delete_user(id):
    user_to_delete = Users.query.get_or_404(id)
    name = None
    form = UserForm()
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash("User deleted Successfully!")
        our_users = Users.query.order_by(Users.created_at)
        return render_template("add_user.html",
            form=form,
            name = name,
            our_users= our_users)

    except:
        flash("Error...Please try again later.")
        return render_template("add_user.html",
            form=form,
            name = name,
            our_users= our_users)



#-----------------------------------------upload prediction model-----------------------------------------
# upload prediction model
model = pickle.load(open('model_areas.pkl', 'rb'))







# upload prediction model
@app.route('/predict',methods=['GET','POST'])
@login_required
def predict():
    areas = ['area_code_408', 'area_code_415', 'area_code_510']
    predict_array = np.zeros(15)
    #predict_array = np.zeros(54)
    idx = 0


    if request.method == 'GET':
        return render_template('index copy.html',areas=areas)
    else:
        
        account_length = float(request.form["account_length"])
        international_plan = int(request.form["international_plan"])
        number_vmail_messages = int(request.form["number_vmail_messages"])
        total_day_minutes = float(request.form["total_day_minutes"])
        total_day_calls = int(request.form["total_day_calls"])
        total_eve_minutes = float(request.form["total_eve_minutes"])
        total_eve_calls = int(request.form["total_eve_calls"])
        total_night_minutes = float(request.form["total_night_minutes"])
        total_night_calls = int(request.form["total_night_calls"])
        total_intl_minutes = float(request.form["total_intl_minutes"])
        total_intl_calls = int(request.form["total_intl_calls"])
        number_customer_service_calls = int(request.form["number_customer_service_calls"])

        area = request.form["areas"]
        predict_array[0] = account_length
        predict_array[1] = international_plan 
        predict_array[2] = number_vmail_messages
        predict_array[3] = total_day_minutes
        predict_array[4] = total_day_calls
        predict_array[5] = total_eve_minutes
        predict_array[6] = total_eve_calls
        predict_array[7] = total_night_minutes
        predict_array[8] = total_night_calls
        predict_array[9] = total_intl_minutes
        predict_array[10] = total_intl_calls
        predict_array[11] = number_customer_service_calls

        for index, item in enumerate(areas):
            if item == area:
                idx = index
        idx = idx + 3
        predict_array[idx] = 1

        #prediction = model.predict([[account_length, number_customer_service_calls,total_eve_charge]])  
        prediction = model.predict([predict_array])  
        output = round(prediction[0], 2) 

        # assigner les données remplit dans le form à la BD
        predict = Predict(account_length = account_length,
                    international_plan =  international_plan ,
                    number_vmail_messages = number_vmail_messages,
                    total_day_minutes = total_day_minutes,
                    total_day_calls = total_day_calls,
                    total_eve_minutes = total_eve_minutes,
                    total_eve_calls = total_eve_calls,
                    total_night_minutes = total_night_minutes,
                    total_night_calls = total_night_calls,
                    total_intl_minutes = total_intl_minutes,
                    total_intl_calls = total_intl_calls,
                    number_customer_service_calls=number_customer_service_calls,
                    areas=area,
                    output=int.from_bytes(output, "little"),
                    user_id = current_user.id # current_user function
                    )
        
        # add les données dans la BD
        db.session.add(predict)
        db.session.commit()

        if output == 0:
            return render_template('index copy.html', areas=areas, 
                                    prediction_text=f'Un account_length = {account_length} , international_plan = {international_plan}, number_vmail_messages = {number_vmail_messages}, total_day_minutes = {total_day_minutes}, total_day_calls = {total_day_calls}, total_eve_minutes = {total_eve_minutes}, total_eve_calls = {total_eve_calls}, total_night_minutes = {total_night_minutes}, total_night_calls = {total_night_calls}, total_intl_minutes = {total_intl_minutes}, total_intl_calls = {total_intl_calls} , number_customer_service_calls = {number_customer_service_calls}  et area = {area} : "no risk of churn"')
        else :
            return render_template('index copy.html', areas=areas, 
                                    prediction_text=f'Un account_length = {account_length} , international_plan = {international_plan}, number_vmail_messages  ={number_vmail_messages}, total_day_minutes = {total_day_minutes}, total_day_calls = {total_day_calls}, total_eve_minutes = {total_eve_minutes}, total_eve_calls = {total_eve_calls}, total_night_minutes = {total_night_minutes}, total_night_calls = {total_night_calls}, total_intl_minutes = {total_intl_minutes}, total_intl_calls = {total_intl_calls} , number_customer_service_calls = {number_customer_service_calls}  et area = {area} : "risk of churn"')
          

@app.route('/resultat', methods=['GET','POST'])
@login_required 
def resultat():
    try :
        if request.method == 'GET':
            # get all data with list format
            #predicts = Predict.query.all() # take all the data
            predicts = Predict.query.filter_by(user_id = current_user.id).all() # filtre only current user data
            print("test",predicts)
        return render_template('resultats.html', predicts=predicts)
    except :
        app.logger.critical('critical - no connexion : pas de base de données "Predict"')
        return Response("Error, Pas de base de données 'Predict'.", status=200, mimetype='text/html') 


# delete a resultat
@app.route('/<int:id>/delete', methods=['GET'])
#@login_required 
def delete(id):
    try :
        predict_delete = Predict.query.get_or_404(id)

        try:
            db.session.delete(predict_delete)
            db.session.commit()
            #flash("Résultat deleted successfully")
            return redirect('/resultat')
        except:
            #flash("There was a problem deleting resultat, please try it later.")
            return redirect('/resultat')
    except :
        #app.logger.debug('debug')
        #app.logger.info('info')
        #app.logger.warning('message')
        #app.logger.error('error')
        app.logger.critical('critical - no connexion : pas de base de données')
        return Response("Error, Pas de base de données.", status=200, mimetype='text/html') 





# Create Custom Error Pages

# Invalid URL
@app.errorhandler(404)
def page_not_found(e):
	return render_template("404.html"), 404

# Internal Server Error
@app.errorhandler(500)
def page_not_found(e):
	return render_template("500.html"), 500


# flask admin
# class MyModelView(ModelView):
    # is_accessible True = admin is visible by a user
#     def is_accessible(self):
#         return current_user.is_authenticated


# admin = Admin(app)

# admin.add_view(MyModelView(Users, db.session))
# admin.add_view(MyModelView(Predict, db.session))

@app.route('/admins/user', methods=['GET','POST'])
@login_required 
def admin_user():
    name = None
    form = UserForm()
    if request.method == 'GET':
        #id = current_user.id
        email = current_user.email
        if email == 'admin@test.fr':
            our_users = Users.query.order_by(Users.created_at)
            return render_template('admin_user.html',
                form=form,
                name = name,
                our_users= our_users)
        else:
            flash('You are not authorised to visit admin page')
            return render_template('user_dashboard.html')


@app.route('/admins/resultat', methods=['GET','POST'])
@login_required 
def admin_resultat():
    #name = None
    #form = UserForm()
    if request.method == 'GET':
        #id = current_user.id
        email = current_user.email
        predicts = Predict.query.all()
        if email == 'admin@test.fr':
            #our_users = Users.query.order_by(Users.created_at)
            return render_template('resultats.html', predicts=predicts)
        else:
            flash('You are not authorised to visit admin page')
            return render_template('user_dashboard.html')




from logging.handlers import SMTPHandler
from logging import FileHandler, WARNING, ERROR, CRITICAL, INFO, Formatter

file_handler = FileHandler('logs/errorlog.txt')
file_handler.setLevel(ERROR)

app.logger.addHandler(file_handler)

mail_handler = SMTPHandler(
     mailhost=('127.0.0.1', 1025),
     fromaddr='server-error@test.com',
     toaddrs=['admin@test.localhost'],
     subject='Application Error'
  )
mail_handler.setLevel(ERROR)
mail_handler.setFormatter(Formatter(
     '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'
     ))

app.logger.addHandler(mail_handler)

@app.route("/log")
def log():
    app.logger.debug('debug')
    app.logger.info('info')
    app.logger.warning('message')
    app.logger.error('error')
    app.logger.critical('critical')
    #return render_template('home.html')
    return Response("test", status=200, mimetype='text/html')

# https://qiita.com/k_future/items/d74b1a26cd9efee8315d
# https://www.youtube.com/watch?v=Ns2baWEoVFg
# https://msiz07-flask-docs-ja.readthedocs.io/ja/latest/logging.html
# http://localhost:8025/

# where is BD
# http://yamav102.cocolog-nifty.com/blog/2017/03/mysql-myini-dat.html

if __name__ == "__main__":
    app.run(debug=True)

# https://www.youtube.com/watch?v=2LqrfEzuIMk


# deactivate under churn-app/venv
# actiavet under churn-app/venv/Scripts