from flask_wtf import FlaskForm
from wtforms.fields import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email


class RegisterForm(FlaskForm):
    name = StringField("Enter Your Name", validators=[DataRequired()])
    email = StringField("Enter Your Email", validators=[DataRequired(), Email()])
    password = PasswordField("Enter Your Password", validators=[DataRequired()])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField("Your Email", validators=[DataRequired(), Email()])
    password = PasswordField("Your Password", validators=[DataRequired()])
    submit = SubmitField("Login")