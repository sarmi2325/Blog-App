#import required modules
from flask import Blueprint, render_template,request,session,redirect,url_for
from flask_login import login_required,current_user
from app.model import Post,PostLike

#create main blueprint
main = Blueprint('main', __name__)

#route to dashboard
@main.route('/')
@main.route('/dashboard')
@login_required
def dashboard():
    query = request.args.get('q', '')  
    if query:
        if query.lower() in ['public', 'private']:
            # Filter by visibility (public/private)
            posts = Post.query.filter(
                Post.user_id == current_user.id,
                Post.is_public == (query.lower() == 'public')
            ).all()
        
        else:
            posts = Post.query.filter(
                Post.user_id == current_user.id,
                Post.content.contains(query)
            ).all()
    else:
        posts = Post.query.filter_by(user_id=current_user.id).all()

    return render_template('dashboard.html', current_user=current_user, posts=posts)

    

