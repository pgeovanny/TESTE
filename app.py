import os
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Simplified importer function
def generate_and_import_questions(text, count=10):
    # Placeholder implementation (no external module)
    return

# Simplified PDF exporter
def export_questions_pdf(user_id):
    return "PDF export not implemented", 200

# Simplified stats
def get_stats(user_id):
    return {'total': 0, 'correct': 0, 'per_difficulty': {}}

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_secret')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///gabarite.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(150))
    cpf = db.Column(db.String(11), unique=True)
    senha_hash = db.Column(db.String(200))
    is_admin = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        nome = request.form['nome']; cpf = request.form['cpf']; senha = request.form['senha']
        if User.query.filter_by(cpf=cpf).first():
            flash('CPF já cadastrado'); return redirect(url_for('signup'))
        user = User(nome=nome, cpf=cpf, senha_hash=generate_password_hash(senha))
        db.session.add(user); db.session.commit()
        flash('Cadastro realizado!'); return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        cpf = request.form['cpf']; senha = request.form['senha']
        user = User.query.filter_by(cpf=cpf).first()
        if user and check_password_hash(user.senha_hash, senha):
            login_user(user); return redirect(url_for('dashboard'))
        flash('Credenciais inválidas')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/questions')
@login_required
def questions():
    return render_template('questions.html')

@app.route('/admin', methods=['GET','POST'])
@login_required
def admin():
    if not current_user.is_admin:
        flash('Acesso negado'); return redirect(url_for('dashboard'))
    if request.method == 'POST':
        text = request.form['law_text']; count = int(request.form.get('count',10))
        generate_and_import_questions(text, count)
        flash('Importado!')
    return render_template('admin.html')

@app.route('/export')
@login_required
def export_pdf():
    return export_questions_pdf(current_user.id)

@app.route('/stats')
@login_required
def stats():
    data = get_stats(current_user.id)
    return render_template('stats.html', stats=data)

if __name__ == '__main__':
    app.run(host='0.0.0.0')