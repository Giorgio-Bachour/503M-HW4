from markupsafe import escape
from datetime import datetime

from flask import Blueprint, render_template, request

from .models import Assignment, Course, CourseTA, Enrollment, Submission, User, db
from .policy import requires

bp = Blueprint("staff", __name__)


def _course_url():
    return db.session.get(Course, request.view_args["cid"])


def _course_form():
    try:
        return db.session.get(Course, int(request.form.get("course_id", "")))
    except (TypeError, ValueError):
        return None


# Releasing grades is an instructor action AND a write, so it is POST only:
# a GET (a link, an <img>) can no longer trigger it (attack 3 / step 8).
@bp.post("/staff/release/<int:cid>")
@requires("release_grades", load=_course_url)
def release(cid):
    course = db.get_or_404(Course, cid)
    for sub in Submission.query.join(Assignment).filter(Assignment.course_id == cid):
        sub.released = True
    db.session.commit()
    return f"Grades released for {escape(course.code)}."


@bp.get("/staff/assignments/new")
@requires("create_assignment")
def new_assignment_form():
    return render_template("course_new_assignment.html")


@bp.post("/staff/assignments/new")
@requires("create_assignment", load=_course_form)
def new_assignment():
    cid = int(request.form["course_id"])
    deadline = datetime.fromisoformat(request.form["deadline"])
    db.session.add(Assignment(course_id=cid, title=request.form["title"],
                              deadline=deadline))
    db.session.commit()
    return f"Assignment added to course {cid}."


# The registrar console is no longer protected by a secret path (attack 1):
# knowing /registrar-x9k2 is not authorisation. manage_roles is.
@bp.get("/registrar-x9k2")
@requires("manage_roles")
def registrar_console():
    return render_template("registrar_console.html", users=User.query.all())


@bp.post("/registrar-x9k2/role")
@requires("manage_roles")
def set_role():
    user = User.query.filter_by(username=request.form["username"]).first_or_404()
    user.role = request.form["role"]
    db.session.commit()
    return f"Role of {escape(user.username)} set to {escape(user.role)}."


@bp.post("/registrar-x9k2/enroll")
@requires("enroll", load=_course_form)
def enroll():
    user = User.query.filter_by(username=request.form["username"]).first_or_404()
    cid = int(request.form["course_id"])
    db.session.add(Enrollment(user_id=user.id, course_id=cid))
    db.session.commit()
    return f"{escape(user.username)} enrolled in course {cid}."


@bp.get("/registrar")
@requires("assign_staff")
def registrar():
    return render_template("registrar.html", courses=Course.query.all())


# The decision no longer comes from the Referer header (attack 7): a header the
# attacker writes is not authorisation. assign_staff (registrar only) is.
@bp.post("/courses/<int:cid>/staff/add")
@requires("assign_staff", load=_course_url)
def add_ta(cid):
    course = db.get_or_404(Course, cid)
    user = User.query.filter_by(username=request.form["username"]).first_or_404()
    db.session.add(CourseTA(user_id=user.id, course_id=cid))
    db.session.commit()
    return f"{escape(user.username)} added as TA of {escape(course.code)}."
