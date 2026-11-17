import secrets
from datetime import timedelta

from flask import Blueprint, redirect, render_template, request, session
from flask_login import current_user, login_user, logout_user

from .models import Mail, ResetToken, User, db, utcnow
from .policy import authenticated, public

bp = Blueprint("auth", __name__)


def _new_csrf_token():
    # Step 22: a fresh, unguessable token at every login. Any token from before
    # the login is thrown away, so a pre-login token cannot be reused after it.
    session["csrf_token"] = secrets.token_urlsafe(32)


@bp.route("/login", methods=["GET", "POST"])
@public
def login():
    error = None
    if request.method == "POST":
        user = User.query.filter_by(username=request.form.get("username", "")).first()
        if user and user.check_password(request.form.get("password", "")):
            session.clear()          # drop any pre-login session state
            login_user(user)
            _new_csrf_token()
            return redirect("/")
        error = "Invalid username or password."
    return render_template("login.html", error=error), (401 if error else 200)


@bp.get("/logout")
@public
def logout():
    logout_user()
    session.clear()
    return redirect("/login")


@bp.route("/forgot", methods=["GET", "POST"])
@public
def forgot():
    sent = False
    if request.method == "POST":
        user = User.query.filter_by(username=request.form.get("username", "")).first()
        if user:
            token = secrets.token_urlsafe(32)
            db.session.add(ResetToken(token=token, user_id=user.id,
                                      expires_at=utcnow() + timedelta(minutes=30)))
            db.session.add(Mail(
                to_address=user.email,
                subject="Reset your Course Portal password",
                body=f"Open {request.host_url}reset?token={token} within 30 minutes."))
            db.session.commit()
        sent = True
    return render_template("forgot.html", sent=sent)


@bp.route("/reset", methods=["GET", "POST"])
@public
def reset():
    token = request.args.get("token", "")
    rt = db.session.get(ResetToken, token) if token else None
    if rt is None or rt.used or rt.expires_at < utcnow():
        return render_template("reset.html", error="This reset link is invalid or has expired.",
                               done=False, invalid=True), 400
    if request.method == "POST":
        pw = request.form.get("new_password", "")
        if len(pw) < 8:
            return render_template("reset.html", error="Password must be at least 8 characters.",
                                   done=False), 400
        rt.user.set_password(pw)
        rt.used = True
        db.session.commit()
        return render_template("reset.html", error=None, done=True)
    return render_template("reset.html", error=None, done=False)


@bp.get("/inbox")
@authenticated
def inbox():
    mails = (Mail.query.filter_by(to_address=current_user.email)
             .order_by(Mail.sent_at.desc(), Mail.id.desc()).all())
    return render_template("inbox.html", mails=mails)
