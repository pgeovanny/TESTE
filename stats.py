from flask import Blueprint, render_template
from flask_login import login_required, current_user
from .models import Stat, Question, Law, Article
from sqlalchemy import func
from . import db

stats_bp = Blueprint('stats', __name__)

@stats_bp.route('/')
@login_required
def statistics():
    # Example aggregation by law
    by_law = db.session.query(Law.name, func.count(Stat.id)).join(Question).join(Stat).filter(Stat.user_id==current_user.id).group_by(Law.name).all()
    return render_template('stats.html', by_law=by_law)
