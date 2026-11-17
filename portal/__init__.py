import os

from flask import Flask, Response
from flask_login import LoginManager

from .models import User, db


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config["SECRET_KEY"] = os.environ.get("PORTAL_SECRET", "dev-only-change-me")

    # Session cookie attributes (Part 4, step 22).
    #   HttpOnly  - JavaScript cannot read the cookie (works on plain http).
    #   SameSite=Lax - the browser withholds the cookie on cross-site POSTs
    #                  (works on plain http). Lax alone does not stop every
    #                  CSRF here, which is why we also add a CSRF token.
    #   Secure    - would require HTTPS; it is left off on this http:// lab,
    #               because a Secure cookie is never sent over http at all.
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # SESSION_COOKIE_SECURE=True,  # turn on once the portal is served over HTTPS
    )
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(
        app.instance_path, "portal.db")
    if os.environ.get("PORTAL_DB"):  # tooling hook: an explicit SQLite file path
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.environ["PORTAL_DB"]
    if test_config:
        app.config.update(test_config)
    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(uid):
        return db.session.get(User, int(uid))

    from . import auth
    app.register_blueprint(auth.bp)
    from . import api, courses, staff
    app.register_blueprint(courses.bp)
    app.register_blueprint(staff.bp)
    app.register_blueprint(api.bp)

    from . import policy

    @app.get("/robots.txt")
    @policy.public
    def robots():
        return Response("User-agent: *\nDisallow: /registrar-x9k2\n", mimetype="text/plain")

    # The single access-control hook in front of every route (Part 4, step 20).
    policy.install(app)

    with app.app_context():
        db.create_all()
        if not app.config.get("TESTING") and User.query.first() is None:
            from .seed import seed
            seed()
    return app
