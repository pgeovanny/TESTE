from . import db, login_manager
from flask_login import UserMixin
from datetime import datetime

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    cpf = db.Column(db.String(14), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    birth_date = db.Column(db.Date, nullable=False)
    state = db.Column(db.String(50))
    study_area = db.Column(db.String(100))
    prep_course = db.Column(db.String(100))
    role = db.Column(db.String(20), default='user')
    comments = db.relationship('Comment', backref='user', lazy=True)
    favorites = db.relationship('Favorite', backref='user', lazy=True)
    stats = db.relationship('Stat', backref='user', lazy=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Law(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), unique=True, nullable=False)
    articles = db.relationship('Article', backref='law', lazy=True)

class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(50), nullable=False)
    law_id = db.Column(db.Integer, db.ForeignKey('law.id'), nullable=False)
    questions = db.relationship('Question', backref='article', lazy=True)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), nullable=False)
    difficulty = db.Column(db.String(50), nullable=False)
    law_id = db.Column(db.Integer, db.ForeignKey('law.id'), nullable=False)
    article_id = db.Column(db.Integer, db.ForeignKey('article.id'), nullable=False)
    comments = db.relationship('Comment', backref='question', lazy=True)
    favorites = db.relationship('Favorite', backref='question', lazy=True)
    stats = db.relationship('Stat', backref='question', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Stat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    correct = db.Column(db.Boolean, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
