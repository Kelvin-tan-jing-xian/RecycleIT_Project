import email
import tensorflow
from flask import Flask, render_template, redirect, request, session, url_for, flash, jsonify, json, abort
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from tensorflow import keras
import matplotlib.pyplot as plt
from wtforms import StringField, PasswordField, BooleanField, RadioField
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
     

class Rewards(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    description = db.Column(db.String(100))
    cost = db.Column(db.String(100))


    def __init__(self, username, email, description, cost):
        self.username = username
        self.email = email
        self.description = description
        self.cost = cost

class Request(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    items = db.Column(db.String)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    street_address = db.Column(db.String(100))
    unit_number = db.Column(db.String)
    block_number = db.Column(db.String)

    def __init__(self, items, username, email, password, role, street_address, unit_number, block_number):
        self.items = items
        self.username = username
        self.email = email
        self.street_address = street_address
        self.unit_number = unit_number
        self.block_number = block_number


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

class createReward(FlaskForm):
    description = StringField(label='Description', validators=[InputRequired(), Length(max=50)])
    cost = RadioField(label='Cost',  choices=[
                      ('1', '1 point'), ('2', '2 points'), ('3', '3 points')], default='1')

class RequestForm(FlaskForm):
    lamp = BooleanField(label='Lamp')
    router = BooleanField(label='Router')
    battery = BooleanField(label='Household Batteries')
    modem = BooleanField(label='Modem')
    network_switch = BooleanField(label='Network Switch')
    laptop = BooleanField(label='Laptop')
    tablet = BooleanField(label='Tablet')
    smartphone = BooleanField(label='Mobile Phone')
    fluorescent_tube = BooleanField(label='Consumer Lamp (fluorescent tube)')
    bulb = BooleanField(label='Consumer Lamp (bulb)')
    dryer = BooleanField(label='Dryer')
    washing_machine = BooleanField(label='Washing Machine')
    electric_vehicle_battery = BooleanField(
        label='Consumer Electric Vehicle Battery')
    pmd = BooleanField(label='Personal Mobility Device')
    electric_mobility_device = BooleanField(label='Electric Mobility Device')
    aircon = BooleanField(label='Air-conditioner')
    refrigerator = BooleanField(label='Consumer Refrigerator(=<900L)')
    television = BooleanField(label='Television')
    printer = BooleanField(label='Printer (less than 20kg)')
    power_assisted_bicycle = BooleanField(label='Power Assisted Bicycle (PAB)')


@app.route('/',  methods=['GET', 'POST'])
def index():
    if (db.session.query(User.email).filter_by(email='admin123@gmail.com').first() == None): 
        hashed_password = generate_password_hash(
            "admin123", method='sha256')
        admin = User(username="admin123",
                        email="admin123@gmail.com",
                        password=hashed_password,
                        role="admin",
                        street_address="none",
                        unit_number="none",
                        block_number="none",
                        )
        db.session.add(admin)
        db.session.commit()
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
                    session["email"] = user.email
                    session["username"] = user.username
                    return redirect(url_for('dashboard'))
                else:
                    session["email"] = user.email
                    session["username"] = user.username
                    return redirect(url_for('consumerHome'))
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


@app.route('/createRequest', methods=['POST'])
def createRequest():
    form = RequestForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(
            form.password.data, method='sha256')
        user = User.query.filter_by(email=current_user.email).first()

        new_request = Request(username=user.username,
                              email=user.email,
                              street_address=user.street_address,
                              unit_number=user.unit_number,
                              block_number=user.block_number)
        db.session.add(new_request)
        db.session.commit()
        return redirect("/retrieveRequest")

    return render_template('consumerHome.html', user=current_user)


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', name=current_user.username, user=current_user)


@app.route('/consumerHome')
@login_required
def consumerHome():
    return render_template('consumerHome.html', name=current_user.username, user=current_user)


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


@app.route('/creatingRewards', methods=['GET', 'POST'])
def creatingRewards():
    form = createReward()
    print("1")
    if request.method == 'POST' and form.validate_on_submit():
        print("3")
        print(form.description.data)
        new_reward = Rewards(
                        username="",
                        email="",
                        description=form.description.data,
                        cost=form.cost.data
        )
        db.session.add(new_reward)
        db.session.commit()
        print("4")
        return redirect(url_for('allRewards'))
    print("2")
    return render_template('creatingRewards.html', form=form, user=current_user)

@app.route('/deleteRewards/<id>/', methods=['POST'])
def deleteReward(id):
    reward = Rewards.query.get(id)
    db.session.delete(reward)
    db.session.commit()
    flash("Reward Deleted Successfully")

    return redirect(url_for('allRewards'))


@app.route('/getReward/<id>/', methods=['POST'])
def getReward(id):
    reward = Rewards.query.get(id)
    reward.username = session["username"]
    reward.email = session["email"]
    db.session.commit()
    flash("User Deleted Successfully")

    return redirect(url_for('displayRewards'))


@app.route('/allRewards')
def allRewards():
    rewards_list = []
    rewards = Rewards.query.all()
    for reward in rewards:
        rewards_list.append(reward)
    return render_template('allRewards.html', user=current_user, rewards_list = rewards_list)


@app.route('/displayRewards')
def displayRewards():
    rewards_list = []
    rewards = Rewards.query.all()
    for reward in rewards:
        if rewards.email == "":
            rewards_list.append(reward)
   
    return render_template('displayRewards.html', rewards=rewards_list, user=current_user)

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
            'geoffrey-saved-model-58-val_acc-0.866.hdf5')
        model_khei = load_model('khei-saved-model-55-val_acc-0.837.hdf5')
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
