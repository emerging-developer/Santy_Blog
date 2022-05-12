from flask import Flask, render_template, redirect, url_for, abort
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_ckeditor import CKEditor
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from functools import wraps
from sqlalchemy.orm import relationship
from flask_gravatar import Gravatar
import datetime as dt

app = Flask(__name__)
Bootstrap(app)
CKEditor(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


def admin_only(func):
    @wraps(func)
    def wrapper_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return func(*args, **kwargs)

    return wrapper_function


app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///blog.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "s141345s"
db = SQLAlchemy(app)


class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(500), unique=True, nullable=False)
    password = db.Column(db.String(500), nullable=False)
    name = db.Column(db.String(500), nullable=False)

    # Creating parent relationship with the BlogPost
    posts = relationship("BlogPost", back_populates="author")

    # creating a relationship with the Comment
    comments = relationship("Comment", back_populates="commented_user")


class BlogPost(db.Model):
    __tablename__ = "blog_post"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(500), nullable=False)
    subtitle = db.Column(db.String(500), nullable=False)
    date = db.Column(db.String(500), nullable=False)
    img_url = db.Column(db.String(500), nullable=False)
    body = db.Column(db.String, nullable=False)

    # creating children relationship with the User
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    author = relationship("User", back_populates="posts")

    # creating a parent relationship with Comment:
    comments = relationship("Comment", back_populates="post")


class Comment(db.Model):
    __tablename__ = "comment"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(1000), nullable=False)

    # creating a children relationship with BlogPost:
    post_id = db.Column(db.Integer, db.ForeignKey('blog_post.id'))
    post = relationship("BlogPost", back_populates="comments")

    # creating a children relationship with the User
    commented_user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    commented_user = relationship("User", back_populates="comments")


db.create_all()
db.session.commit()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template('index.html', all_posts=posts, current_user=current_user)


@app.route('/post/<int:post_id>', methods=["POST", "GET"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comments = Comment.query.filter_by(post=requested_post).all()
    form = CommentForm()
    if form.validate_on_submit():
        new_comment = Comment(
            text=form.text.data,
            post=requested_post,
            commented_user=current_user
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('get_all_posts',))
    return render_template('post.html', post=requested_post, form=form, comments=comments)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(pwhash=user.password, password=form.password.data):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                return "Wrong Password"
        else:
            return "Email Does not Exist"
    return render_template('login.html', form=form)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if not user:
            new_user = User(
                name=form.name.data,
                email=form.email.data,
                password=generate_password_hash(password=form.password.data,
                                                method="pbkdf2:sha256",
                                                salt_length=8)
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('get_all_posts'))
        else:
            return "Email Already Exist"
    return render_template('register.html', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/about')
@login_required
def about():
    return render_template('about.html')


@app.route('/contact')
@login_required
def contact():
    return render_template('contact.html')


@app.route('/new-post', methods=["POST", "GET"])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            img_url=form.img_url.data,
            body=form.body.data,
            author=current_user,
            date=dt.datetime.now().strftime("%B %m, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template('make-post.html', form=form)


@app.route("/edit/<int:post_id>", methods=["POST", "GET"])
@login_required
@admin_only
def edit_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CreatePostForm(
        title=requested_post.title,
        subtitle=requested_post.subtitle,
        img_url=requested_post.img_url,
        body=requested_post.body
    )
    if form.validate_on_submit():
        requested_post.title = form.title.data
        requested_post.subtitle = form.subtitle.data
        requested_post.img_url = form.img_url.data
        requested_post.body = form.body.data
        db.session.commit()
        return redirect(url_for('get_all_posts'))

    return render_template('make-post.html', form=form)


@app.route('/delete/<int:post_id>')
@login_required
@admin_only
def delete_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    db.session.delete(requested_post)
    db.session.commit()
    return redirect(url_for("get_all_posts"))


if __name__ == "__main__":
    app.run(debug=True)
