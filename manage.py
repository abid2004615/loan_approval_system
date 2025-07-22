import click
from flask.cli import with_appcontext
from werkzeug.security import generate_password_hash
from app import app, db
from models import User

@click.group()
def cli():
    """User and application management."""
    pass

@cli.command("create-admin")
@click.argument("username")
@click.argument("password")
@with_appcontext
def create_admin(username, password):
    """Creates a new admin user."""
    if User.query.filter_by(username=username).first():
        print(f"Error: User '{username}' already exists.")
        return
    hashed_password = generate_password_hash(password)
    admin = User(username=username, password=hashed_password, role='admin')
    db.session.add(admin)
    db.session.commit()
    print(f"Admin user '{username}' created successfully.")

if __name__ == '__main__':
    cli()