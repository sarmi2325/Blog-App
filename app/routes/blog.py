#import required modules
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from app import db
from app.model import Post,PostLike
import os
from werkzeug.utils import secure_filename
from flask import current_app
from datetime import datetime
from app.routes.form import PostForm
from flask import abort
from flask import jsonify

#create blog blueprint
blog = Blueprint('blog', __name__)

#route to create a new post
@blog.route('/create', methods=['GET', 'POST'])
@login_required
def create_post():
    form = PostForm()   
    if form.validate_on_submit():
        title = form.title.data
        content = form.content.data
        link = form.link.data
        is_public = form.is_public.data == 'true'  

        image = request.files.get('image')
        image_url = None

        if image and image.filename != '':
           filename = secure_filename(image.filename)
           save_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
           os.makedirs(os.path.dirname(save_path), exist_ok=True)
           image.save(save_path)
           image_url = f"uploads/{filename}".replace('\\', '/')

        post = Post(title=title, content=content, image_url=image_url,link=link,is_public=is_public,author=current_user)
        db.session.add(post)
        db.session.commit()
        #flash('Post created!')
        return redirect(url_for('main.dashboard'))
    return render_template('create_post.html',form=form)


#route to delete a post
@blog.route('/delete/<int:post_id>')
@login_required
def delete(post_id):
    post=Post.query.get_or_404(post_id)
    if post.author!=current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('main.dashboard'))

#route to view a post
@blog.route('/post/<int:post_id>')
def post(post_id):
    post = Post.query.get_or_404(post_id)
    post.views+=1
    db.session.commit()
    return render_template('post.html', post=post)

#route to like a post
@blog.route('/like/<int:post_id>', methods=['POST'])
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    existing_like = PostLike.query.filter_by(user_id=current_user.id, post_id=post_id).first()
    if existing_like:
        flash('You have already liked this post!', 'warning')
    else:
        like = PostLike(user_id=current_user.id, post_id=post_id)
        post.likes += 1
        db.session.add(like)
        db.session.commit()
    return redirect(url_for('blog.public_posts'))

#route to view public post
@blog.route('/public')
def public_posts():
    posts = Post.query.filter_by(is_public=True).order_by(Post.id.desc()).all()
    return render_template('public.html', posts=posts)


@blog.route('/upload_image', methods=['POST'])
@login_required
def upload_image():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    filename = secure_filename(file.filename)
    upload_folder = current_app.config.get('UPLOAD_FOLDER', os.path.join('static', 'uploads'))
    os.makedirs(upload_folder, exist_ok=True)
    file_path = os.path.join(upload_folder, filename)
    file.save(file_path)

    image_url = url_for('static', filename=f'uploads/{filename}', _external=False)
    return jsonify({'location': image_url})
