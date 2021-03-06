from flask import render_template, url_for, flash, redirect, request, Blueprint
from flask_login import login_user, current_user, logout_user, login_required
from banking_system import db, bcrypt
from banking_system.models import User
from banking_system.users.forms import RegistrationForm, LoginForm


from flask import Blueprint

users = Blueprint('users', __name__)


@users.route("/register", methods = ['GET',  'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(user_name=form.username.data,user_password=form.password.data,user_email=form.email.data, user_phone_number=form.phone_number.data, user_role=form.role.data)
        db.session.add(user)
        db.session.commit()
        flash(f'your account has been created you are all set for login', 'success')
        return redirect(url_for('users.login'))
    return render_template('register.html', title='Register', form=form)


@users.route("/login", methods = ['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('main.home'))
        else:
            flash('Login unsuccessfull..please check email and password', 'danger')
    return render_template('login.html', title='login', form=form)
