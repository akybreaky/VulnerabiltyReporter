from flask import Flask
from database import db, init_db, update_repo, repo_to_db
from flask_apscheduler import APScheduler

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///advisory.db'
scheduler = APScheduler()

from routes import *

@scheduler.task('cron', id='update_database', hour=3, minute=0) # Every day at 3:00 AM
def update_all() -> bool:
    with scheduler.app.app_context():
        return update_repo() and repo_to_db()


if __name__ == '__main__':
    with app.app_context():
        db.init_app(app)
        db.create_all()
        init_db()

        scheduler.init_app(app)
        scheduler.start()

    app.run()
