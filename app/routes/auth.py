#import required modules
from flask import Blueprint,render_template,request,redirect,url_for,flash
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import login_user,logout_user,current_user,login_required
from flask_dance.contrib.google import make_google_blueprint, google
from app.model import User
from app import db

#create auth blueprint
auth=Blueprint('auth',__name__)

@auth.route("/google/authorized")
def google_authorized():
    if not google.authorized:
        return redirect(url_for("auth.google.login"))  # If not authorized, redirect to Google login

    # Get the user's info from Google
    response = google.get("/oauth2/v2/userinfo")
    assert response.ok, response.text
    user_info = response.json()

    # Here you can create a new user in the database or log in the user
    # For example, if the user already exists, log them in:
    user = User.query.filter_by(email=user_info["emails"][0]["value"]).first()
    if user:
        login_user(user)
        return redirect(url_for('main.dashboard'))  # Redirect to the dashboard or wherever you want

    # If the user doesn't exist, create a new user
    new_user = User(username=user_info['displayName'], email=user_info['emails'][0]['value'])
    db.session.add(new_user)
    db.session.commit()
    login_user(new_user)

    return redirect(url_for('main.dashboard'))

@auth.route('/register',methods=['GET','POST'])
def register():
    if request.method=='POST':
        username=request.form['username']
        email = request.form['email']
        password=request.form['password']
        confirm_password=request.form['confirm_password']

        if password!=confirm_password:
            flash('Password and confirm password do not match')
            return redirect(url_for('auth.register'))
        

        existing_user=User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists')
            return redirect(url_for('auth.register'))

        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return redirect(url_for('auth.register'))

        new_user=User(username=username,email=email,password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('auth.login'))

    return render_template('admin/register.html')


@auth.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        username=request.form['username']
        password=request.form['password']

        user=User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password,password):
            login_user(user)
            #flash('Login successful')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid username or password')
    
    return render_template('admin/login.html')

@auth.route('/logout')
def logout():
    logout_user()
    #flash('Logged out successfully')
    return redirect(url_for('auth.login'))
