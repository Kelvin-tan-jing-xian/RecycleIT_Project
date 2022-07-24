import email

import tensorflow
from flask import Flask, render_template, redirect, request, session, url_for, flash, jsonify, json, abort
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from tensorflow import keras
import matplotlib.pyplot as plt
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from authlib.integrations.flask_client import OAuth
from werkzeug.utils import secure_filename
import os
import urllib.request
from keras.models import load_model
import numpy as np
from keras.utils import load_img, img_to_array
from keras.applications.resnet import preprocess_input
from tensorflow.python.ops.nn import softmax
from PIL import Image
from keras.applications import imagenet_utils
from keras.applications.resnet import decode_predictions
import cv2




app = Flask(__name__)
app.secret_key = "kelvin-tan"
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = set(['jpg','jpeg','png'])
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



oauth = OAuth(app)

app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

    def __init__(self, username, email, password):

        self.username = username
        self.email = email
        self.password = password


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    email = StringField('email', validators=[
        InputRequired(), Length(min=4, max=50)])
    password = PasswordField('password', validators=[
                             InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(
        message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[
                           InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[
                             InputRequired(), Length(min=8, max=80)])


@app.route('/')
def index():
    return render_template('index.html', user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))
            else:
                flash("Incorrect Username or password")

                return redirect('/login')
        else:
            flash("Incorrect Username or Password")
            return redirect('/login')

        # return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form, user=current_user)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(
            form.password.data, method='sha256')
        new_user = User(username=form.username.data,
                        email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        session["user_created"] = new_user.email
        return redirect("/login")
        # return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form, user=current_user)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username, user=current_user)


@app.route("/viewAllUsers")
@login_required
def viewAllUsers():
    return render_template("viewAllUsers.html", user=current_user, values=User.query.all())


@app.route('/user/update', methods=['GET', 'POST'])
def update():

    if request.method == 'POST':
        my_data = User.query.get(request.form.get('id'))

        my_data.username = request.form['username']
        my_data.email = request.form['email']
        my_data.password = request.form['password']

        db.session.commit()
        flash("User Updated Successfully")

        return redirect(url_for('viewAllUsers'))

# This route is for deleting our user


@app.route('/user/delete/<id>/', methods=['POST'])
def delete(id):
    my_data = User.query.get(id)
    db.session.delete(my_data)
    db.session.commit()
    flash("User Deleted Successfully")

    return redirect(url_for('viewAllUsers'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/api', methods=['GET', 'POST'])
def api():
    class_names = ['lamp', 'power_assisted_bicycle', 'printer', 'television']
    img_height = 150
    img_width = 150
    threshold = 0.52
    if 'files[]' not in request.files:
        resp = jsonify({'message': 'No file part in the request'})
        resp.status_code = 400
        return resp
    files = request.files.getlist('files[]')
    errors = {}
    success = False

    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            success = True
        else:
            errors[file.filename] = 'File type is not allowed'
    if success and errors:
        errors['message'] = 'File(s) successfully uploaded'
        resp = jsonify(errors)
        resp.status_code = 500
        return resp
    if success:
        print("filename = ", filename)
        path = 'static/uploads/{}'.format(filename)
        img = cv2.imread(path)
        img = cv2.resize(img, (img_height,img_width))
        img_normalized = img/255
        print("loading my model")
        model = load_model('resnet50-saved-model-46-val_acc-0.76.hdf5')
        print("model loaded successfully")
        predictions = model.predict(np.array([img_normalized]))
        print("Predictions = ", predictions)
        array = predictions[np.argmax(predictions)]
        index = np.argmax(array)
        print("Highest prediction value = ", array[index])

        if array[index] > threshold:
            item = class_names[np.argmax(predictions)]
            print("Item = ", item)
            resp = jsonify({'message': 'This is a/an {} and it is a regulated e waste. Feel free to recycle it!'.format(item)})

        else:
            resp = jsonify({'message': 'This is a non regulated e waste'})

        resp.status_code = 201
        return resp
    else:
        resp = jsonify(errors)
        resp.status_code = 500
        return resp
if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)