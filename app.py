from flask import Flask, render_template, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from forms import RegistrationForm, LoginForm
from models import User, db, connect_db

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql:///user_db"
app.config['SECRET_KEY'] = 'your_secret_key'

connect_db(app)
db.create_all()


@app.route('/')
def index():
    return redirect(url_for('register'))

# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     form = RegistrationForm()
#     if form.validate_on_submit():
#         username = form.username.data
#         password = form.password.data
#         email = form.email.data
#         first_name = form.first_name.data
#         last_name = form.last_name.data

#         hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

#         user = User(username=username, password=hashed_password, email=email, first_name=first_name, last_name=last_name)
#         db.session.add(user)
#         db.session.commit()

#         return redirect(url_for('secret'))
#     return render_template('register.html', form=form)
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        user = User(username=username, password=hashed_password, email=email, first_name=first_name, last_name=last_name)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))  # Redirect to login page

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            # User is authenticated
            # Redirect to /secret or any other protected page
            flash('Login successful!', 'success')
            session['user_id'] = user.id  # Store user ID in session
            return redirect(url_for('secret'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html', form=form)

@app.route('/secret')
def secret():
    if 'user_id' not in session:
        flash('Please login first!', 'danger')
        return redirect('/')
    return render_template('secret.html')


@app.route('/logout')
def logout_user():
    session.pop('user_id')
    flash("Goodbye!", "info")
    return redirect('/')