from flask import Blueprint, render_template, request, redirect, url_for, flash
from . import db, login_manager, mail
from .models import User
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Message
import secrets

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/signup', methods=['GET','POST'])
def signup():
    if request.method=='POST':
        data = request.form
        if User.query.filter_by(cpf=data['cpf']).first():
            flash('CPF já cadastrado.', 'danger')
            return redirect(url_for('auth.signup'))
        hashed = generate_password_hash(data['password'])
        user = User(name=data['name'], cpf=data['cpf'], email=data['email'],
                    password=hashed, birth_date=data['birth_date'],
                    state=data['state'], study_area=data['study_area'],
                    prep_course=data['prep_course'])
        db.session.add(user); db.session.commit()
        flash('Cadastro realizado com sucesso.', 'success')
        return redirect(url_for('auth.login'))
    return render_template('signup.html')

@auth_bp.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        user = User.query.filter_by(cpf=request.form['cpf']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('questions.list_questions'))
        flash('Login inválido.', 'danger')
    return render_template('login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth_bp.route('/reset-password', methods=['GET','POST'])
def reset_password():
    if request.method=='POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = secrets.token_urlsafe(16)
            # Here you'd save token in DB and send email with link
            msg = Message('Recuperação de Senha', recipients=[email])
            msg.body = f'Use este token para resetar sua senha: {token}'
            mail.send(msg)
            flash('E-mail de recuperação enviado.', 'info')
        else:
            flash('E-mail não encontrado.', 'danger')
    return render_template('reset_password.html')
