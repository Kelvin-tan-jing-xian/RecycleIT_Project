import email
from re import sub
import tensorflow
from flask import Flask, render_template, redirect, request, session, url_for, flash, jsonify, json, abort
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from tensorflow import keras
import matplotlib.pyplot as plt
from wtforms import StringField, PasswordField, BooleanField, RadioField
from wtforms.validators import InputRequired, Email, Length, Optional
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from authlib.integrations.flask_client import OAuth
from werkzeug.utils import secure_filename
from random import randint
import os
from sqlalchemy.sql import func
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
from email.message import EmailMessage
import ssl
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

app = Flask(__name__)
app.secret_key = "kelvin-tan"
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
ALLOWED_EXTENSIONS = set(['jpg', 'jpeg', 'png'])


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

# database

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    role = db.Column(db.String(80))
    street_address = db.Column(db.String(100))
    unit_number = db.Column(db.String)
    block_number = db.Column(db.String)

    def __init__(self, username, email, password, role, street_address, unit_number, block_number):

        self.username = username
        self.email = email
        self.password = password
        self.role = role
        self.street_address = street_address
        self.unit_number = unit_number
        self.block_number = block_number


class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    time_created = db.Column(db.DateTime(
        timezone=True), server_default=func.now())
    time_updated = db.Column(db.DateTime(timezone=True), onupdate=func.now())
    items = db.Column(db.String)
    username = db.Column(db.String(15))
    email = db.Column(db.String(50))
    street_address = db.Column(db.String(100))
    unit_number = db.Column(db.String)
    block_number = db.Column(db.String)

    def __init__(self, items, username, email, street_address, unit_number, block_number):
        self.items = items
        self.username = username
        self.email = email
        self.street_address = street_address
        self.unit_number = unit_number
        self.block_number = block_number


class PIN(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    time_created = db.Column(db.DateTime(timezone=True), server_default=func.now())
    pin = db.Column(db.String)
    username = db.Column(db.String(15))
    email = db.Column(db.String(50))

    def __init__(self, pin, username, email):
        self.pin = pin
        self.username = username
        self.email = email

# forms

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
    email = StringField(label='Email', validators=[InputRequired(), Email(
        message='Invalid email'), Length(max=50)])
    username = StringField(label='Username', validators=[
                           InputRequired(), Length(min=4, max=15)])
    password = PasswordField(label='Password', validators=[
                             InputRequired(), Length(min=8, max=80)])
    role = RadioField(label='Role',  choices=[
                      ('consumer', 'Sign up as consumer'), ('admin', 'Sign up as admin')], default='consumer')
    street_address = StringField(label='Street Address', validators=[
                                 InputRequired()], default='Ang Mo Kio Avenue 1')
    unit_number = StringField(label='Unit Number', validators=[
                              InputRequired()], default='#07-06')
    block_number = StringField(label='Block Number', validators=[
                               InputRequired()], default='896A')


class RequestForm(FlaskForm):
    lamp = BooleanField(label='Lamp', validators=[Optional()])
    router = BooleanField(label='Router', validators=[Optional()])
    battery = BooleanField(label='Household Batteries',
                           validators=[Optional()])
    modem = BooleanField(label='Modem', validators=[Optional()])
    network_switch = BooleanField(
        label='Network Switch', validators=[Optional()])
    laptop = BooleanField(label='Laptop', validators=[Optional()])
    tablet = BooleanField(label='Tablet', validators=[Optional()])
    smartphone = BooleanField(label='Mobile Phone', validators=[Optional()])
    fluorescent_tube = BooleanField(
        label='Consumer Lamp (fluorescent tube)', validators=[Optional()])
    bulb = BooleanField(label='Consumer Lamp (bulb)', validators=[Optional()])
    dryer = BooleanField(label='Dryer', validators=[Optional()])
    washing_machine = BooleanField(
        label='Washing Machine', validators=[Optional()])
    electric_vehicle_battery = BooleanField(
        label='Consumer Electric Vehicle Battery', validators=[Optional()])
    pmd = BooleanField(label='Personal Mobility Device',
                       validators=[Optional()])
    electric_mobility_device = BooleanField(
        label='Electric Mobility Device', validators=[Optional()])
    aircon = BooleanField(label='Air-conditioner', validators=[Optional()])
    refrigerator = BooleanField(
        label='Consumer Refrigerator(=<900L)', validators=[Optional()])
    television = BooleanField(label='Television', validators=[Optional()])
    printer = BooleanField(
        label='Printer (less than 20kg)', validators=[Optional()])
    power_assisted_bicycle = BooleanField(
        label='Power Assisted Bicycle (PAB)', validators=[Optional()])

class PINForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Length(min=4, max=50)])

# route

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
                if user.role == "admin":
                    return redirect(url_for('dashboard'))
                else:
                    return redirect(url_for('createRequest'))
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
                        email=form.email.data,
                        password=hashed_password,
                        role=form.role.data,
                        street_address=form.street_address.data,
                        unit_number=form.unit_number.data,
                        block_number=form.block_number.data)
        db.session.add(new_user)
        db.session.commit()
        session["user_created"] = new_user.email
        return redirect("/login")

    return render_template('signup.html', form=form, user=current_user)


@app.route('/createRequest', methods=['GET', 'POST'])
@login_required
def createRequest():
    form = RequestForm()

    if request.method == "POST":
        user = User.query.filter_by(email=current_user.email).first()
        items = ""
        if form.network_switch.data is True:
            items = "network switch"
        if form.aircon.data is True:
            items = items + ", aircon"
        if form.battery.data is True:
            items = items + ", battery"
        if form.dryer.data is True:
            items = items + ", dryer"
        if form.bulb.data is True:
            items = items + ", bulb"
        if form.electric_mobility_device.data is True:
            items = items + ", electric mobility device"
        if form.electric_vehicle_battery.data is True:
            items = items + ", electric vehicle battery"
        new_request = Request(items=items,
                              username=user.username,
                              email=user.email,
                              street_address=user.street_address,
                              unit_number=user.unit_number,
                              block_number=user.block_number)
        db.session.add(new_request)
        db.session.commit()
        return redirect("/retrieveRequest")

    return render_template('createRequest.html', form=form, user=current_user)

def sendPINEmail(pin, email): # will update this
    email_sender = ""
    email_password = ""
    email_receiver = email

    subject = "Your PIN to recycle the E-waste"

    #HTML Message Part
    html = """\
    <html>
    <body style="font-family: 'Poppins', sans-serif;" >
        <p>Dear customer,</p>
        <p>THANK YOU FOR RECYCLING!</p>
        <br>
        <span>Your PIN to access our bins is: <h2 style="color: #a4c639;">{}</h2></span>
        <p>Do use this only for the E-Wastes that you have scanned previously.</p>
        <p>Thanks,</p>
        <h2 style="color: #a4c639;">RECYCLEIT</h2>
    </body>
    </html>
    """.format(pin)

    part = MIMEText(html, "html")
                
    em = MIMEMultipart("alternative")
    em["From"] = email_sender
    em["To"] = email_receiver
    em["Subject"] = subject
    em.attach(part)

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=ssl.create_default_context()) as smtp:
        smtp.login(email_sender, email_password)
        smtp.sendmail(email_sender, email_receiver, em.as_string())
        
    return

@app.route("/getPIN",  methods=['GET', 'POST'])
def getPIN():
    form = PINForm()

    # generate pin and check if exists in db
    while True:
        generated_num = np.random.randint(9,size=(4))
        pin = ""
        for i in generated_num:
            pin += str(i)
        pinExists = PIN.query.filter_by(pin=pin).first()
        if pinExists == None:
            break

    if current_user.is_authenticated:
        user = User.query.filter_by(email=current_user.email).first()
        has_pin = PIN.query.filter_by(email=current_user.email).first()
        if has_pin == None:
            new_pin = PIN(pin=pin, username=user.username, email=user.email)
            db.session.add(new_pin)
            db.session.commit()

            # send pin to email 
            sendPINEmail(pin, str(user.email))

            get_pin=PIN.query.filter_by(email=current_user.email).first()
            return render_template('getPIN.html', user=current_user, get_pin=get_pin)
        else:
            hasPIN = True
            print("you have a pin already!")

    else:
        hasPIN = False
        if request.method == "POST": # for user not logged in
    
            has_pin = PIN.query.filter_by(email=form.email.data).first()
            print("this is has pin", has_pin)
            if has_pin == None:
                new_pin = PIN(pin=pin, username="NotRegisteredUser", email=form.email.data)
                db.session.add(new_pin)
                db.session.commit()

                # send pin to email 
                sendPINEmail(pin, str(form.email.data))

                get_pin=PIN.query.filter_by(email=form.email.data).first()
                return render_template('getPIN.html', form=form, user=current_user, get_pin=get_pin)

            else:
                hasPIN = True
                print("you have a PIN already!")
    
    return render_template('getPIN.html', form=form, user=current_user, get_pin=[], hasPIN=hasPIN)
        

@app.route("/retrieveRequest")
@login_required
def retrieveRequest():
    return render_template("retrieveRequest.html", user=current_user, values=Request.query.all())


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username, user=current_user)


@app.route('/education')
def education():
    return render_template('education.html', user=current_user)


@app.route('/types_of_ewaste')
def types_of_ewaste():
    return render_template('types_of_ewaste.html', user=current_user)


@app.route("/viewAllUsers")
@login_required
def viewAllUsers():
    return render_template("viewAllUsers.html", user=current_user, values=User.query.all())


@app.route("/manageRequests")
@login_required
def manageRequests():
    return render_template("manageRequests.html", user=current_user, values=Request.query.all())


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

# our models

@app.route('/api', methods=['POST'])
def api():

    class_names = ['electric vehicle battery', 'lamp', 'power assisted bicycle', 'printer', 'television',
                   'Router', 'battery', 'modem', 'network switch', 'refrigerator', 'aircon', 'consumer computer',
                   'dryer', 'monitor', 'personal mobility device', 'electric mobility device',
                   'mobile phone', 'network hub', 'set top box', 'washing machine']

    ICT_subcategory = ["printer", "Router", "modem", "network switch",
                       "mobile phone", "network hub", "set top box", "monitor", "consumer computer"]
    Household_subcategory = [
        "television", "refrigerator", "washing machine", "dryer", "aircon"]
    ElectricMobilityDevice_subcategory = [
        "power assisted bicycle", "electric mobility device", 'personal mobility device']
    Batteries_subcategory = ["electric vehicle battery", "battery"]
    Lamps_subcategory = ["lamp"]
    img_height = 180
    img_width = 180
    threshold = 0.74
    showRegulated = False
    showNon = False
    if 'file' not in request.files:
        flash('File input cannot be empty!')
        return render_template('index.html', user=current_user)
    file = request.files['file']
    if file.filename == '':
        flash('No image selected for uploading')
        return render_template('index.html', user=current_user)
    errors = {}
    success = False

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        flash("Image successfully uploaded and displayed below")
        print("filename = ", filename)
        path = 'static/uploads/{}'.format(filename)
        img = cv2.imread(path)
        img = cv2.resize(img, (img_height, img_width))
        img_normalized = img/255
        print("loading my model")
        model_kelvin = load_model('kelvin-saved-model-53-val_acc-0.814.hdf5')
        model_trumen = load_model('trumen-saved-model-59-val_acc-0.832.hdf5')
        model_geoffrey = load_model(
            'geoffrey-saved-model-60-val_acc-0.738.hdf5')
        model_khei = load_model('khei-saved-model-57-val_acc-0.817.hdf5')
        print("model loaded successfully")

        predictions_kelvin = model_kelvin.predict(np.array([img_normalized]))
        predictions_trumen = model_trumen.predict(np.array([img_normalized]))
        predictions_geoffrey = model_geoffrey.predict(
            np.array([img_normalized]))
        predictions_khei = model_khei.predict(np.array([img_normalized]))

        predictions_concat = np.concatenate(
            (predictions_kelvin, predictions_trumen, predictions_geoffrey, predictions_khei), axis=None)
        print("Predictions concat = ", predictions_concat)
        print("Highest value = ", np.amax(predictions_concat))
        if np.amax(predictions_concat) > threshold:
            item = class_names[np.argmax(predictions_concat)]
            print("Item = ", item)
            for i in ICT_subcategory:
                if i.lower() == item.lower():
                    subcategory = "ICT"

            for i in Household_subcategory:
                if i.lower() == item.lower():
                    subcategory = "Household Appliances"

            for i in ElectricMobilityDevice_subcategory:
                if i.lower() == item.lower():
                    subcategory = "Electric Mobility Device"

            for i in Batteries_subcategory:
                if i.lower() == item.lower():
                    subcategory = "Batteries"

            for i in Lamps_subcategory:
                if i.lower() == item.lower():
                    subcategory = "Lamps"
            #resp = jsonify({'message': 'This is a/an {} and it is a regulated e waste. Feel free to recycle it!'.format(item)})
            print(
                'This is a/an {} and it is a regulated e waste. Go ahead and recycle it!'.format(item))
            showRegulated = True
        else:
            item = ""
            subcategory = ""
            #resp = jsonify({'message': 'This is a non regulated e waste'})
            print('This is a picture of non regulated e waste')
            showNon = True

        # resp.status_code = 201
        # return resp

        return render_template('index.html',
                               filename=filename,
                               user=current_user,
                               item=item,
                               showRegulated=showRegulated,
                               showNon=showNon,
                               subcategory=subcategory
                               )
    else:
        flash('Allowed image types are - png, jpg, jpeg, gif', category='error')
        return render_template('index.html', user=current_user)


@app.route('/display/<filename>')
def display_image(filename):
    return redirect(url_for('static', filename='uploads/' + filename), code=301)


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
