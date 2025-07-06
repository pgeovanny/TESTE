from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from .models import Question, Stat, Favorite, Comment, Article, Law
from . import db
from sqlalchemy import and_

questions_bp = Blueprint('questions', __name__)

@questions_bp.route('/')
@login_required
def list_questions():
    # Fetch filters
    args = request.args
    q = Question.query
    if args.get('law'): q = q.filter(Question.law_id==args['law'])
    if args.get('article'): q = q.filter(Question.article_id==args['article'])
    if args.get('type'): q = q.filter(Question.type==args['type'])
    if args.get('difficulty'): q = q.filter(Question.difficulty==args['difficulty'])
    questions = q.all()
    return render_template('questions.html', questions=questions)

@questions_bp.route('/<int:q_id>', methods=['GET','POST'])
@login_required
def question_detail(q_id):
    q = Question.query.get_or_404(q_id)
    if request.method=='POST':
        action = request.form['action']
        if action=='answer':
            correct = request.form['correct']=='true'
            stat = Stat(user=current_user, question=q, correct=correct)
            db.session.add(stat)
        elif action=='favorite':
            fav = Favorite(user=current_user, question=q)
            db.session.add(fav)
        elif action=='unfavorite':
            Favorite.query.filter_by(user=current_user, question=q).delete()
        elif action=='comment':
            comment = Comment(user=current_user, question=q, content=request.form['content'])
            db.session.add(comment)
        db.session.commit()
    comments = q.comments
    return render_template('question_detail.html', question=q, comments=comments)
