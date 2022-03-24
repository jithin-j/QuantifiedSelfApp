from ast import Str
from crypt import methods
from enum import unique
from re import L
import sqlite3
from sre_parse import GLOBAL_FLAGS
import bcrypt
from flask import Flask, render_template, request, session, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from datetime import datetime
import os
current_dir = os.path.abspath(os.path.dirname(__file__))


app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///" + os.path.join(current_dir, "database.sqlite3") 
app.config['SECRET_KEY'] = 'thisisasecretkey'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), nullable = False, unique = True)
    password = db.Column(db.String(80), nullable = False)
    all = db.relationship('All')

class All(db.Model):
    __tablename__ = 'all'
    Tracker_id = db.Column(db.String)
    Tracker = db.Column(db.String)
    Last_Tracked = db.Column(db.String, primary_key = True)
    New_Event = db.Column(db.String)
    Action = db.Column(db.String)
    tracker_type = db.Column(db.String(150))
    On = db.Column(db.String)
    Value = db.Column(db.String)
    Description = db.Column(db.String)
    Setting = db.Column(db.String)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class TrackerForm(FlaskForm):
    Tracker = StringField(validators=[InputRequired(), Length(
        min = 4, max = 20)], render_kw={"placeholder": "Tracker"})
    
    Tracker_id = StringField(validators=[InputRequired(), Length(
        min = 4, max = 20)], render_kw={"placeholder": "Tracker ID"})

    Description = StringField(validators=[InputRequired(), Length(
        min = 4, max = 200)], render_kw={"placeholder": "Description"})
    
    Value = StringField(validators=[InputRequired(), Length(
        min = 1, max = 100)], render_kw={"placeholder": "Value"})

    submit = SubmitField("Submit Tracker")

class TrackerAddForm(FlaskForm):
    
    Tracker_id = StringField(validators=[InputRequired(), Length(
        min = 4, max = 20)], render_kw={"placeholder": "Tracker ID"})

    Description = StringField(validators=[InputRequired(), Length(
        min = 4, max = 200)], render_kw={"placeholder": "Description"})
    
    #Value = StringField(validators=[InputRequired(), Length(
        #min = 1, max = 100)], render_kw={"placeholder": "Value"})

    submit = SubmitField("Submit Tracker")

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min = 4, max = 20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min = 4, max = 20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        
        if existing_user_username:
            raise ValidationError("Username already in use. Please choose another one.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min = 4, max = 20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(
        min = 4, max = 20)], render_kw={"placeholder": "Password"})

    submit = SubmitField("Login")

@app.route('/')
def home():
    return render_template("home.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template("login.html", form = form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    trackers = db.session.query(All.Tracker).filter(All.user_id == current_user.id).distinct()
    user = current_user.username
    return render_template("dashboard.html", trackers = trackers, user = user)

@app.route('/addNewTracker', methods=['GET', 'POST'])
@login_required
def addNewTracker():
    form = TrackerForm()
    current_user_id = current_user.id
    if form.validate_on_submit():
        new_tracker = All(Setting = request.form['choices'], tracker_type = request.form['type'], user_id = current_user_id, Tracker = form.Tracker.data, Last_Tracked = datetime.now(), Tracker_id = form.Tracker_id.data, Description = form.Description.data, Value = form.Value.data)
        db.session.add(new_tracker)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template("trackerAdd.html", form = form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/tracker/<type>', methods = ["GET", "POST"])
def trackers(type):
    if request.method == "GET":
        from app import All
        trackers = All.query.filter(All.Tracker == type, All.user_id == current_user.id)
        trackers2 = db.session.query(All.Last_Tracked, All.Value).filter(All.Tracker == type, All.user_id == current_user.id)
        dates = []
        values = []
        import matplotlib.pyplot as plt
        from matplotlib.pyplot import figure
        from matplotlib import style
        import numpy as np
        style.use('fivethirtyeight')
        figure(figsize=(10, 6), dpi=80)
        from dateutil import parser
        for row in trackers2:
            print(row)
            dates.append((row['Last_Tracked'][:19]))
            values.append((row['Value']))
        #fig = plt.figure(figsize=(18, 8))
        #plt.plot_date(dates, values, '-')
        print(dates)
        plt.xlabel('Date and Time')
        plt.ylabel('Values')
        xpoints = np.array(dates)
        ypoints = np.array(values)
        plt.plot(xpoints, ypoints, marker = 'o')
        plt.tight_layout()
        plt.savefig('static/graph.png')
        return render_template("tracker.html", trackers = trackers)

@app.route('/addtracker/<trackername>', methods=["GET", "POST"])
def addtracker(trackername):
    form = TrackerAddForm()
    data = All.query.filter(All.Tracker == trackername).first()
    if(data.Setting):
        opts = data.Setting
        opts = opts.split(',')
    else:
        opts = ''
    if form.validate_on_submit():
        current_user_id = current_user.id  
        new_tracker = All(user_id = current_user_id, Tracker = trackername, Last_Tracked = datetime.now(), Tracker_id = form.Tracker_id.data, Description = form.Description.data, Value = request.form['value'])
        print(new_tracker)
        db.session.add(new_tracker)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template("logtracker.html", form = form, trackername = trackername, opts = opts, data = data)

@app.route('/edit_tracker/<tracker>/<time>', methods=["GET", "POST"])
@login_required
def edittracker(time, tracker):
    this_log = All.query.get((time))
    form = TrackerAddForm()
    data = All.query.filter(All.Tracker == tracker).first()
    if(data.Setting):
        opts = data.Setting
        opts = opts.split(',')
    else:
        opts = ''
    if form.validate_on_submit():
        this_log.Tracker = tracker
        this_log.Tracker_id = form.Tracker_id.data
        this_log.Last_Tracked = datetime.now()
        this_log.Description = form.Description.data
        this_log.Value = request.form['value']
        db.session.commit()
        flash(this_log.Tracker + ' Log Updated Successfully.', category='success')
        return redirect(url_for('dashboard'))
    print(form.errors)
    return render_template("logtracker.html", form = form, trackername = tracker, opts = opts, data = data)

@app.route('/delete_tracker/<tracker>/<time>', methods=["GET", "POST"])
@login_required
def deletelog(time, tracker):
    this_log = All.query.get(time)
    db.session.delete(this_log)
    db.session.commit()
    flash('Log Removed Successfully.', category='success')
    return redirect(url_for('dashboard'))

@app.route('/delete/<tracker>')
@login_required
def deletetracker(tracker):
    trackers = All.query.filter(All.Tracker == tracker, All.user_id == current_user.id)
    for tracker in trackers:
        db.session.delete(tracker)
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route('/register',  methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
        
    return render_template("register.html", form = form)

if __name__ == '__main__':
    app.run(debug=True)