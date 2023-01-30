from flask import Flask, render_template, redirect, request, url_for, flash
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import RegisterForm, LoginForm
from sqlalchemy.orm import relationship
from sqlalchemy.exc import InvalidRequestError
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from collections import Counter
import os


app = Flask(__name__)
csrf = CSRFProtect(app)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")
Bootstrap(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///to_do_list.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)

    list_title = relationship("ListTitle", back_populates="user")


class ListTitle(db.Model):
    __tablename__ = "list_titles"
    id = db.Column(db.Integer, primary_key=True)
    list_title = db.Column(db.String(255), nullable=False)
    datetime = db.Column(db.String(200), nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    user = relationship("User", back_populates="list_title")

    checklists = relationship("Checklist", back_populates="list_title", cascade='all,delete-orphan')


class Checklist(db.Model):
    __tablename__ = "checklists"
    id = db.Column(db.Integer, primary_key=True)

    list_title_id = db.Column(db.Integer, db.ForeignKey("list_titles.id", ondelete="CASCADE"), nullable=False)
    list_title = relationship("ListTitle", back_populates="checklists")

    list_description = db.Column(db.String(500), nullable=False)
    complete_task = db.Column(db.String(255))


db.create_all()


@app.route("/", methods=["GET", "POST"])
def home():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        if User.query.filter_by(email=email).first():
            flash("This email already exists. Please login instead.")
            return redirect(url_for("login"))
        else:
            salted_and_hash_password = generate_password_hash(
                password=form.password.data,
                method="pbkdf2:sha256",
                salt_length=8
            )
            new_user = User(
                name=form.name.data,
                email=email,
                password=salted_and_hash_password
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for("add_title"))
    return render_template("index.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("This user doesn't exist. Please register first.")
            return redirect(url_for("home"))
        else:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for("add_title"))
            else:
                flash("Incorrect password. Make sure you enter the correct password.")
                return redirect(url_for("login"))
    return render_template("login.html", form=form, current_user=current_user)


@login_required
@app.route("/add-title", methods=["GET", "POST"])
def add_title():
    if current_user.is_authenticated:
        titles = ListTitle.query.filter_by(user_id=current_user.id).all()
        if request.method == "POST":
            data = request.form.get("title-name")
            if data != "":
                new_list_title = ListTitle(
                    list_title=data,
                    datetime=datetime.now().strftime("%b %d, %Y"),
                    user=current_user
                )
                db.session.add(new_list_title)
                db.session.commit()
                return redirect(url_for("add_title"))
        return render_template("add_title.html", titles=titles, current_user=current_user, add_title=True, login=True)


@login_required
@app.route("/add-list/<int:title_id>", methods=["GET", "POST"])
def add_checklist(title_id):
    if current_user.is_authenticated:
        title = ListTitle.query.get(title_id)
        all_checklists = Checklist.query.filter_by(list_title_id=title_id).all()

        if request.method == "POST":
            data = request.form.get("checklist-name")
            if data != "":
                new_checklist = Checklist(
                    list_description=data,
                    list_title=title
                )
                db.session.add(new_checklist)
                db.session.commit()
                return redirect(url_for("add_checklist", title_id=title_id))
        return render_template("add_list.html", title=title, all_checklists=all_checklists,
                               current_user=current_user, add_checklist=True, login=True)


@login_required
@app.route("/my-checklist/<int:title_id>", methods=["GET", "POST"])
def show_checklist(title_id):
    if current_user.is_authenticated:
        title = ListTitle.query.get(title_id)
        all_checklists = Checklist.query.filter_by(list_title_id=title_id).all()
        incomplete_tasks = [checklist.list_description for checklist in all_checklists]

        try:
            all_complete_tasks = Checklist.query.filter_by(list_title_id=title_id).filter_by(complete_task="yes").all()
            complete_tasks = [task.list_description for task in all_complete_tasks]
        except InvalidRequestError:
            complete_tasks = []

        c1 = Counter(incomplete_tasks)
        c2 = Counter(complete_tasks)
        incomplete_tasks = list((c1 - c2).elements())

        if request.method == "POST":
            tasks_done = request.form.getlist("my-checkbox")
            for task_done in tasks_done:
                checklist_to_update = Checklist.query.filter_by(list_title_id=title_id).filter_by(list_description=task_done).first()
                checklist_to_update.complete_task = "yes"
                db.session.commit()

            c1 = Counter(incomplete_tasks)
            c2 = Counter(tasks_done)
            incomplete_tasks = list((c1 - c2).elements())
            all_complete_tasks = Checklist.query.filter_by(list_title_id=title_id).filter_by(complete_task="yes").all()
            complete_tasks = [task.list_description for task in all_complete_tasks]

            return render_template("show_list.html", title=title, incomplete_tasks=incomplete_tasks,
                                   complete_tasks=complete_tasks, show_list=True, current_user=current_user,
                                   login=True)

        return render_template("show_list.html", title=title, incomplete_tasks=incomplete_tasks,
                               complete_tasks=complete_tasks, show_list=True, current_user=current_user,
                               login=True)


@login_required
@app.route("/delete-title/<int:title_id>")
def delete_title(title_id):
    title_to_delete = ListTitle.query.get(title_id)
    db.session.delete(title_to_delete)
    db.session.commit()
    return redirect(url_for("add_title", login=True))


@login_required
@app.route("/delete-checklist/<int:title_id>/<int:checklist_id>")
def delete_checklist(title_id, checklist_id):
    checklist_to_delete = Checklist.query.get(checklist_id)
    db.session.delete(checklist_to_delete)
    db.session.commit()
    return redirect(url_for("add_checklist", title_id=title_id, login=True))


@login_required
@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(port=8000, debug=True)

