from flask import Blueprint, render_template,redirect,url_for, request,flash
from app import db
from models import User
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import login_user,logout_user
auth = Blueprint('auth',__name__)

@auth.route("/browse_missions")
def browse_missions():
    return render_template('browse_missions.html') 
@auth.route("/")
def index():
    return render_template('browse_missions.html')    
@auth.route("/login")
def login():
    return render_template('login.html')
@auth.route("/login",methods=['POST'])
def login_post():
    email=request.form.get('email')
    password=request.form.get('password')
    user=User.query.filter_by(email=email).first()
    if user==None:
        flash('Invalid username or password. Try again','danger')
    else:
        if not user or not check_password_hash(user.password,password):
            flash('Invalid username or password. Try again','danger')
        else:
            flash('Successfully logged in!','success')
            print(user.name)
            print(user.urole)
            print(user.password)
            print(user.email)
            login_user(user)
            return redirect(url_for("auth.index"))
    return redirect(url_for('auth.login'))
@auth.route("/signup")
def signup():
    return render_template('signup.html')
@auth.route("/signup",methods=['POST'])
def signup_post():
    email=request.form.get('email')
    name=request.form.get('name')
    password=request.form.get('password')
    urole=request.form.get('urole')
    user=User.query.filter_by(email=email).first()
    if user:
        # Go to <a href="{{url_for('auth.login')}}">Login page</a>
        flash('Email address already exists. ','danger')
    elif urole!="student" and urole!="company":
        flash('Please select role as student or company','danger')
    else:
        new_user=User(email=email,name=name,password=generate_password_hash(password),urole=urole)
        db.session.add(new_user)
        db.session.commit()
        flash('You are successfully registered!','success')
    return render_template('signup.html')
@auth.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('auth.index'))