from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from . import db
from .models import Question, Law, Article
import csv
import openai

admin_bp = Blueprint('admin', __name__)

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role!='admin':
            flash('Acesso negado.', 'danger')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated

@admin_bp.route('/import', methods=['GET','POST'])
@admin_required
def import_csv():
    if request.method=='POST':
        file = request.files['csv_file']
        stream = file.stream.read().decode('utf-8').splitlines()
        reader = csv.DictReader(stream)
        count=0
        for row in reader:
            law = Law.query.filter_by(name=row['law']).first() or Law(name=row['law'])
            db.session.add(law); db.session.flush()
            article = Article.query.filter_by(number=row['article'], law=law).first() or Article(number=row['article'], law=law)
            db.session.add(article); db.session.flush()
            q = Question(text=row['text'], type=row['type'], difficulty=row['difficulty'], law=law, article=article)
            db.session.add(q)
            count+=1
        db.session.commit()
        flash(f'{count} questões importadas.', 'success')
    return render_template('admin_import.html')

@admin_bp.route('/generate', methods=['GET','POST'])
@admin_required
def generate_questions():
    if request.method=='POST':
        prompt = request.form['prompt']
        ai = openai.OpenAI(api_key=admin_bp.import_name="openai")
        response = ai.completions.create(model="text-davinci-003", prompt=prompt, max_tokens=500)
        # Parsing and saving logic should be implemented
        flash('Geração via IA concluída (implementar parsing).', 'info')
    return render_template('admin_generate.html')
