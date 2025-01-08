from enum import unique
from flask import Flask
from flask import render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin,LoginManager,login_user,login_required,logout_user
from werkzeug.security import generate_password_hash,check_password_hash
import os
from datetime import datetime
import pytz

 
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SECRET_KEY'] = os.urandom(24)
db = SQLAlchemy(app)

login_manager=LoginManager()
login_manager.init_app(app)

# class Post(db.Model):
#     id=db.Column(db.Integer,primary_key=True)
#     title=db.Column(db.String(50),nullable=False)
#     body=db.Column(db.String(300),nullable=False)
#     created_at=db.Column(db.DateTime,nullable=False, default=datetime.now())

class User(UserMixin, db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(30), unique=True)
	password = db.Column(db.String(12))

@login_manager.user_loader
def load_user(user_id):
      return User.query.get(int(user_id))

@app.route('/',methods=['GET', 'POST'])
#@login_required
def index():
     if request.method=='GET':
        #   posts=Post.query.all()
          return render_template('index.html')
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        # Userのインスタンスを作成
        user = User(username=username, password=generate_password_hash(password, method='sha256'))
        db.session.add(user)
        db.session.commit()
        return redirect('/login')
    else:
        return render_template('signup.html')
    

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        # Userテーブルからusernameに一致するユーザを取得
        user = User.query.filter_by(username=username).first()
        if check_password_hash(user.password, password):
            login_user(user)
            return redirect('/')
    else:
        return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')
