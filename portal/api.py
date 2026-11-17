from flask import Blueprint, jsonify, request

from .models import User, db
from .policy import authenticated, requires

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.get("/me")
@authenticated
def me():
    from flask_login import current_user
    return jsonify(id=current_user.id, username=current_user.username,
                   role=current_user.role, email=current_user.email)


# Rule: edit_email, on the user named in the URL. The hook loads that user and
# the condition (own account only) decides. The view no longer picks the target.
@bp.put("/users/<int:uid>/email")
@requires("edit_email", load=lambda: db.session.get(User, request.view_args["uid"]))
def set_email(uid):
    user = db.session.get(User, uid)
    user.email = request.get_json()["email"]
    db.session.commit()
    return jsonify(status="ok")
