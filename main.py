from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Column
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar

from flask import Flask, render_template, redirect, url_for, request, abort
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditor, CKEditorField
import datetime
from functools import wraps

## Delete this code:
# import requests
# posts = requests.get("https://api.npoint.io/43644ec4f0013682fc0d").json()


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# Avatar Users
gravatar = Gravatar(app,
                    size=50,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#################################
# FLASK_LOGIN
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    username = db.Column(db.String(1000), unique=True)

    #This will act like a List of BlogPost objects attached to each User.
    #The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


##CONFIGURE TABLE
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    #Create Foreign Key, "users.id" the users refers t the tablename of Users
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    #Create reference to the User object, the "posts" referes to the posts property in the User class.
    author = relationship("User", back_populates="posts")


    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    #BlogPOst is the parent of ech of the comments in that post
    comments = relationship("Comment", back_populates="parent_post")



class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    # Comments are childrend of the users
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comment_author = relationship("User", back_populates="comments")
    #Comments are children of each post in BlogPost
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship("BlogPost", back_populates="comments")

    text = db.Column(db.Text, nullable=False)


# Line below only required once, when creating DB.
with app.app_context():
    db.create_all()




@app.route('/')
def get_all_posts():
    posts = db.session.query(BlogPost).all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route("/post/<int:index>", methods=["GET", "POST"])
def show_post(index):
    requested_post = BlogPost.query.get(index)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if current_user.is_authenticated:
            comment = comment_form.comment.data
            print(comment)
            new_comment = Comment(
                author_id=int(current_user.get_id()),
                post_id=index,
                text=comment
            )
            with app.app_context():
                db.session.add(new_comment)
                db.session.commit()

            return redirect(url_for("show_post", index=index))
        else:
            flash("You have to be logged to comment. Please log in.")
            return redirect(url_for('login'))
    return render_template("post.html", post=requested_post, form=comment_form, logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        user = User.query.filter_by(email=request.form.get("email")).first()
        #the email is not already registered
        if not user:
            hash_and_salted_password = generate_password_hash(
                register_form.password.data,
                method='pbkdf2:sha256',
                salt_length=12)
            new_user = User(
                name=register_form.name.data,
                email=register_form.email.data,
                password=hash_and_salted_password,
                username=register_form.username.data,
            )
            with app.app_context():
                db.session.add(new_user)
                db.session.commit()
            print("error is before")
            # Log in and authenticate user after adding details to database
            login_user(new_user)
            print("error is after")

            return redirect(url_for("get_all_posts"))
        else:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
    return render_template("register.html", form=register_form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():
        user = User.query.filter_by(email=login_form.email_or_username.data).first()
        if not user:
            user = User.query.filter_by(username=login_form.email_or_username.data).first()
        if not user:
            flash('Invalid credentials')
        else:
            if check_password_hash(user.password, request.form.get("password")):

                user = load_user(user_id=user.id)
                # if correct the credentials:
                login_user(user)

                #flask.flash('Logged in successfully  :).')

                return redirect(url_for("get_all_posts"))
            else:
                flash('Invalid credentials')
    return render_template("login.html", form=login_form, logged_in=current_user.is_authenticated)


# Create admin-only decorator
def admin_only(function):
    @wraps(function)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        if int(current_user.get_id()) == 1:
            return function(*args, **kwargs)
        else:
            abort(403)
    return decorated_function



@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def create_new_post():
    new_post = CreatePostForm()
    if request.method == "POST":
        new_post = BlogPost(
            title=new_post.title.data,
            subtitle=new_post.subtitle.data,
            date=datetime.datetime.now().strftime("%B %d, %Y"),
            body=new_post.body.data,
            author_id=int(current_user.get_id()),
            img_url=new_post.img_url.data
        )
        with app.app_context():
            db.session.add(new_post)
            db.session.commit()

        return redirect(url_for("get_all_posts"))

    return render_template("make-post.html", form=new_post, edit=False, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)

    load_post = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        #author=post.author,
        body=post.body
    )

    if load_post.validate_on_submit():
        post.title = load_post.title.data
        post.subtitle = load_post.subtitle.data
        # post.date = datetime.datetime.now().strftime("%B %d, %Y"),
        post.body = load_post.body.data
        #post.author = load_post.author.data
        post.img_url = load_post.img_url.data

        with app.app_context():
            db.session.commit()

        return redirect(url_for("show_post", index=post.id))

    return render_template("make-post.html", form=load_post, edit=True, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete(post_id):
    with app.app_context():
        post = BlogPost.query.get(post_id)

        db.session.delete(post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
