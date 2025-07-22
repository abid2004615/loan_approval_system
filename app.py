from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from forms import LoginForm, RegisterForm, LoanApplicationForm  # Import all forms
from werkzeug.security import check_password_hash, generate_password_hash
from models import db
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///loan_system.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    from models import User  # Import here to avoid circular import
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    from models import User
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        print("User from DB:", user)
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Logged in successfully!', 'success')
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        from models import User, db
        hashed_password = generate_password_hash(form.password.data)
        user = User(
            username=form.username.data,
            password=hashed_password,
            role='applicant'  # Default role
        )
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    from models import LoanApplication
    applications = LoanApplication.query.filter_by(user_id=current_user.id).order_by(LoanApplication.created_at.desc()).all()
    return render_template('dashboard.html', applications=applications)

@app.route('/apply', methods=['GET', 'POST'])
@login_required
def apply():
    from models import LoanApplication, db
    form = LoanApplicationForm()
    if form.validate_on_submit():
        # Use custom value if 'Other' is selected
        if form.amount.data == 'other':
            amount = (form.custom_amount.data or '').strip()
            if not amount:
                flash('Please enter a custom amount.', 'danger')
                return render_template('apply.html', form=form)
        else:
            amount = form.amount.data

        if form.purpose.data == 'other':
            purpose = (form.custom_purpose.data or '').strip()
            if not purpose:
                flash('Please enter a custom purpose.', 'danger')
                return render_template('apply.html', form=form)
        else:
            purpose = form.purpose.data

        application = LoanApplication(
            amount=amount,
            purpose=purpose,
            user_id=current_user.id
        )
        db.session.add(application)
        db.session.commit()
        flash('Your loan application has been submitted!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('apply.html', form=form)

@app.route('/application/<int:application_id>')
@login_required
def application_details(application_id):
    from models import LoanApplication, User
    application = LoanApplication.query.get_or_404(application_id)
    # Only allow the owner or an admin to view
    if application.user_id != current_user.id and current_user.role != 'admin':
        abort(403)
    return render_template('application_details.html', application=application)

@app.route('/application/<int:application_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_application(application_id):
    from models import LoanApplication, db
    application = LoanApplication.query.get_or_404(application_id)
    if application.user_id != current_user.id or application.status != 'Pending':
        abort(403)
    form = LoanApplicationForm(obj=application)
    if form.validate_on_submit():
        if form.amount.data == 'other':
            amount = (form.custom_amount.data or '').strip()
            if not amount:
                flash('Please enter a custom amount.', 'danger')
                return render_template('edit_application.html', form=form, application=application)
        else:
            amount = form.amount.data
        if form.purpose.data == 'other':
            purpose = (form.custom_purpose.data or '').strip()
            if not purpose:
                flash('Please enter a custom purpose.', 'danger')
                return render_template('edit_application.html', form=form, application=application)
        else:
            purpose = form.purpose.data
        application.amount = amount
        application.purpose = purpose
        db.session.commit()
        flash('Application updated successfully.', 'success')
        return redirect(url_for('application_details', application_id=application.id))
    return render_template('edit_application.html', form=form, application=application)

@app.route('/application/<int:application_id>/delete', methods=['POST'])
@login_required
def delete_application(application_id):
    from models import LoanApplication, db
    application = LoanApplication.query.get_or_404(application_id)
    if application.user_id != current_user.id or application.status != 'Pending':
        abort(403)
    db.session.delete(application)
    db.session.commit()
    flash('Application deleted successfully.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    from models import LoanApplication
    applications = LoanApplication.query.order_by(LoanApplication.created_at.desc()).all()
    return render_template('admin_dashboard.html', applications=applications)

@app.route('/admin/approve/<int:application_id>', methods=['POST'])
@login_required
@admin_required
def approve_application(application_id):
    from models import LoanApplication, db, User
    application = LoanApplication.query.get_or_404(application_id)
    application.status = 'Approved'
    db.session.commit()
    flash(f'Application #{application.id} has been approved.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/reject/<int:application_id>', methods=['POST'])
@login_required
@admin_required
def reject_application(application_id):
    from models import LoanApplication, db, User
    application = LoanApplication.query.get_or_404(application_id)
    application.status = 'Rejected'
    db.session.commit()
    flash(f'Application #{application.id} has been rejected.', 'danger')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)