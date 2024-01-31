from functools import wraps
from flask import Flask, render_template, request, flash, redirect, url_for, abort, send_file, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, current_user, login_user, login_required, logout_user, login_manager
from werkzeug.security import generate_password_hash, check_password_hash
import os
app = Flask(__name__)
app.config["SECRET_KEY"] = "hadfjhbcdasbhadshajkdf"
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
db = SQLAlchemy()
db.init_app(app)


login_manager = LoginManager()
login_manager.init_app(app)

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)
#models
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    first_name = db.Column(db.String(255))

class Reviews(db.Model):
    __tablename__ = "contacts"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    message = db.Column(db.String(100), nullable=False)

with app.app_context():
    db.create_all()


#authenticatioin for admin



@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return redirect(url_for("edit_page"))
            else:
                flash('Incorrect Password ! Try Again', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route('/signup', methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form.get("email")
        name = request.form.get("name")
        password = request.form.get("password")
        new_user = User(
            email=email,
            first_name=name,
            password=generate_password_hash(password)
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))
    return render_template("signup.html", user=current_user)

@app.route('/')
def home():
    result = db.session.execute(db.select(Reviews))
    rev = result.scalars().all()
    return render_template("index.html", is_edit=False, reviews=rev)

@app.route('/edit')
def edit_page():
    result = db.session.execute(db.select(Reviews))
    rev = result.scalars().all()
    return render_template("index.html", is_edit=True, reviews=rev)

@app.route("/delete/<int:review_id>")
def delete_post(review_id):
    post_to_delete = db.get_or_404(Reviews, review_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('edit_page'))

@app.route("/reviews", methods=["GET", "POST"])
def reviews():

    if request.method == "POST":
        name = request.form.get("name")
        message = request.form.get("message")
        new_post = Reviews(
            name=name,
            message=message
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("make-post.html",  current_user=current_user)

@app.route("/download")
def download():
    return send_from_directory('static', path="files/my_cv.docx")
