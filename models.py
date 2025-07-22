from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'applicant' or 'admin'
    applications = db.relationship('LoanApplication', backref='user', lazy=True)

class LoanApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    purpose = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='Pending')  # Pending, Approved, Rejected
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

class Repayment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, server_default=db.func.now())
    note = db.Column(db.String(255))
    application_id = db.Column(db.Integer, db.ForeignKey('loan_application.id'), nullable=False)
    application = db.relationship('LoanApplication', backref=db.backref('repayments', lazy=True))