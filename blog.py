from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
import os
from sqlalchemy import MetaData
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, PasswordField, SubmitField, DateTimeField, SelectField, validators
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from flask_bootstrap import Bootstrap
import requests
from itsdangerous import URLSafeTimedSerializer


app = Flask(__name__)
bootstrap = Bootstrap(app)
app.config['SECRET_KEY'] = 'hhhnnjnnnhnhnh'

ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])

POSTGRES = {
    'user': os.environ['PSQL_USER'],
    'pw': os.environ['PSQL_PWD'],
    'db': os.environ['PSQL_DB'],
    'host': os.environ['PSQL_HOST'],
    'port': os.environ['PSQL_PORT'],
}

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://%(user)s:%(pw)s@%(host)s:\
%(port)s/%(db)s' % POSTGRES
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

convention = {
    "ix": 'ix_%(column_0_label)s',
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}
metadata = MetaData(naming_convention=convention)

db = SQLAlchemy(app)

login = LoginManager(app)
login.login_view = 'login'
login.login_message_category = "info"


@login.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.route("/")
def index():
    return redirect(url_for('posts'))


@app.route('/posts')
def posts():
    return render_template('posts.html', title='Show posts', posts=Posts.query.all())


@app.route('/create', methods=['POST', 'GET'])
@login_required
def create():
    if request.method == 'POST':
        if not request.form['title'] or not request.form['body']:
            flash('Please enter all the fields', 'danger')
        else:
            post = Posts(title=request.form['title'], body=request.form['body'],
                         author_name=current_user.username, author=User.query.filter_by(
                             username=current_user.username).first())

            db.session.add(post)
            db.session.commit()

            flash('Post was added', 'success')
            return redirect(url_for('posts'))
    return render_template('create_form.html', title='New post')


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user is not None and user.check_password(password):
            flash(f'Welcome back {user.username} !!', 'success')
            login_user(user)
            next = request.args.get('next')
            return redirect(next or url_for('create'))
        else:
            flash('Something is wrong with ur email/password', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html', title='Login')


@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == "POST":
        if not request.form['email'] or not request.form['username'] or not request.form['password']:
            flash('Please fill in all the fields!!!', 'danger')
        else:
            email = request.form['email']
            password = request.form['password']
            username = request.form['username']
            if User.query.filter_by(email=email).first():
                flash('Email already exist, please try another email', 'danger')
                return redirect(url_for('signup'))
            elif User.query.filter_by(username=username).first():
                flash('User name already exist, please try another name', 'danger')
                return redirect(url_for('signup'))

            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Successfully Sign Up, login now to post to blog!', 'success')
            return redirect(url_for('login'))

    return render_template('signup.html', title='Sign Up')


@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')


@app.route('/logout')
def logout():
    logout_user()
    flash('Successfully logout!!!', 'info')
    return redirect(url_for('login'))


@app.route('/<username>/posts')
def user_posts(username):
    return render_template('user_posts.html', title='Show posts', posts=User.query.filter_by(username=username).first().posts.all())


class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80))
    body = db.Column(db.String(500))
    author_name = db.Column(db.String(80))
    created_at = db.Column(db.DateTime(timezone=True),
                           server_default=db.func.current_timestamp())
    updated_at = db.Column(
        db.DateTime(timezone=True), server_default=db.func.current_timestamp(), server_onupdate=db.func.current_timestamp())

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128), nullable=False)
    posts = db.relationship('Posts', backref='author', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class EmailForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class PasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm = PasswordField('Repeat Password', validators=[EqualTo('password', message='Passwords must match.')])
    submit = SubmitField('Request Password Reset')


def send_password_reset_email(email, name):
    token = ts.dumps(email, salt='recover-password-secret')
    apikey = "d34712c9091819894412d80173ba2345-7bce17e5-1b464f35"
    url = "https://api.mailgun.net/v3/sandbox7d108c5f562d48c39a80896f6f602cdf.mailgun.org/messages"
    requests.post(url, 
        auth=("api", apikey), 
        data={"from": "postmaster@sandbox7d108c5f562d48c39a80896f6f602cdf.mailgun.org",
        "to": [email], 
        "subject": "Reset Password", 
        "html": f"""<html><p>Dear {name.capitalize()},</p><p>To reset your password: <a href='http://localhost:5000/new_password/{token}'>Click this link!!</a></p><p>Alternatively, you can paste the following link in your browser's address bar:</p><p style='color: blue'>http://localhost:5000/new_password/{token}</p><p>If you have not requested a password reset simply ignore this message.</p><p>Sincerely,</p><p>Hung dep trai</p></html>"""},)   


@app.route('/reset', methods=["GET", "POST"])
def reset():
    form = EmailForm()
    if form.validate_on_submit():
        email=form.email.data
        user = User.query.filter_by(email=email).first_or_404()
        name=user.username
        if user:
            send_password_reset_email(email, name)
            flash('password reset email sent check your email to validate!', 'success')

    return render_template('reset.html', form=form)

@app.route('/new_password/<token>', methods=["GET", "POST"])
def actualreset(token):
    try:
        email = ts.loads(token, salt='recover-password-secret', max_age=3600)
    except:
        flash('The password reset link is invalid or has expired.', 'danger')
    form = PasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=email).first_or_404()
        user.set_password(form.confirm.data)
        db.session.add(user)
        db.session.commit()

        flash('set new password successfully', 'success')

    return render_template('actualreset.html', form=form)

db.create_all()
