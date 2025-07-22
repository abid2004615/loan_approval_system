from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FloatField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=150)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoanApplicationForm(FlaskForm):
    amount = SelectField('Loan Amount', choices=[
        ('5000', '₹5,000'),
        ('10000', '₹10,000'),
        ('20000', '₹20,000'),
        ('50000', '₹50,000'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    custom_amount = StringField('Other Amount (₹)', validators=[Length(max=20)])
    purpose = SelectField('Purpose', choices=[
        ('education', 'Education'),
        ('business', 'Business'),
        ('medical', 'Medical'),
        ('personal', 'Personal'),
        ('other', 'Other')
    ], validators=[DataRequired()])
    custom_purpose = StringField('Other Purpose', validators=[Length(max=255)])
    submit = SubmitField('Apply') 