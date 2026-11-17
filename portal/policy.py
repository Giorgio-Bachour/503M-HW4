"""Access control model for the Course Portal (Part 4 of Level 4).

The whole point of the lab: one model, written once, that sits in front of
every route. Nothing in the views decides access any more.

  ROLE_PERMISSIONS   RBAC  - which roles could *ever* hold each permission
  CONDITIONS         ABAC  - one function per permission, (user, obj, ctx) -> bool
  can()                    - step 1 (RBAC) then step 2 (ABAC); unknown perm -> deny
  role_allows()            - just step 1, so the hook can split the two checks
  requires()/public()/...  - declare a route's rule next to the route
  install(app)             - the single before_request hook + CSRF check

Design notes for the worksheet
------------------------------
* The hook checks the *role* before it loads the object (step 20). A user whose
  role can never hold the permission is refused with 403 and the object is never
  touched, so it cannot leak which records exist.
* When the role is allowed but the *condition* fails on a specific object, the
  answer is 404, not 403 (step 20): a 403 would confirm that another student's
  submission exists. Horizontal failures hide the record; vertical ones don't.
* A route with no rule is denied (step 20 / test_8): forgetting a rule fails
  closed, not open.
* The current time comes from the server's clock (models.utcnow), never the
  request, so a client cannot backdate a deadline.
"""
import hmac
import ipaddress
from datetime import timedelta

from flask import abort, current_app, request, session
from flask_login import current_user

from .models import Extension, utcnow

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# ---------------------------------------------------------------------------
# RBAC: the permissions each role could ever use.
# ---------------------------------------------------------------------------
ROLE_PERMISSIONS = {
    # lecture table (R1-R6)
    "view_material":     {"student", "ta", "instructor"},   # R1
    "submit":            {"student"},                        # R2
    "view_grade":        {"student"},                        # R3
    "create_assignment": {"instructor"},                     # R4
    "grade":             {"ta", "instructor"},               # R5
    "change_grade":      {"instructor"},                     # R5
    "enroll":            {"registrar"},                      # R6

    # the four the attacks need
    "view_gradebook":    {"ta", "instructor", "chair"},      # attack 2 (+ N1 chair)
    "release_grades":    {"instructor"},                     # attack 3
    "manage_roles":      {"registrar"},                      # attack 1
    "assign_staff":      {"registrar"},                      # attack 7

    # supporting routes that still need a rule
    "view_submission":   {"student", "ta", "instructor"},    # attack 4 (the page)
    "edit_email":        {"student", "ta", "instructor", "registrar", "chair"},  # attack 5
}


# ---------------------------------------------------------------------------
# ABAC: one condition per permission. obj is the thing the route is about,
# ctx is the request context the hook builds (currently {"network": ...}).
# A permission with no condition here is RBAC-only (role is enough).
# ---------------------------------------------------------------------------
def _view_material(u, course, ctx):
    return course is not None and (course.id in u.enrolled_in or course.id in u.staff_of)


def _submit(u, assignment, ctx):
    if assignment is None or assignment.course_id not in u.enrolled_in:
        return False
    if utcnow() < assignment.deadline:
        return True
    # N2: an approved extension buys up to 3 more days.
    if _has_extension(u, assignment) and utcnow() < assignment.deadline + timedelta(days=3):
        return True
    return False


def _view_grade(u, sub, ctx):
    # R3: your own submission, and only once it is released.
    return sub is not None and sub.student_id == u.id and sub.released


def _view_submission(u, sub, ctx):
    # The /submissions/<id> page: the owner, or staff of that course.
    if sub is None:
        return False
    if u.role == "student":
        return sub.student_id == u.id
    return sub.course_id in u.staff_of


def _create_assignment(u, course, ctx):
    # R4. With no course chosen yet (the blank form), allow any instructor.
    if course is None:
        return bool(u.teaches)
    return course.id in u.teaches


def _grade(u, sub, ctx):
    # R5: staff of the course, grade not yet released.
    if sub is None or sub.course_id not in u.staff_of or sub.released:
        return False
    # N4: a TA enrolled in the course must never grade it.
    if sub.course_id in u.enrolled_in:
        return False
    return True


def _change_grade(u, sub, ctx):
    # R5: the course's instructor, before the grade deadline.
    if sub is None or sub.course_id not in u.teaches:
        return False
    if sub.course is not None and utcnow() >= sub.course.grade_deadline:
        return False
    # N3: changing a released grade is only allowed from the campus network.
    if sub.released and (ctx or {}).get("network") != "campus":
        return False
    return True


def _view_gradebook(u, course, ctx):
    if course is None:
        return False
    # N1: a department chair sees every gradebook in their department (read only).
    if u.role == "chair":
        return course.department == u.department
    return course.id in u.staff_of


def _release_grades(u, course, ctx):
    return course is not None and course.id in u.teaches


def _assign_staff(u, course, ctx):
    return True  # RBAC already limits this to the registrar


def _edit_email(u, target, ctx):
    # attack 5: you may change your own address, nobody else's.
    return target is not None and target.id == u.id


CONDITIONS = {
    "view_material":     _view_material,
    "submit":            _submit,
    "view_grade":        _view_grade,
    "view_submission":   _view_submission,
    "create_assignment": _create_assignment,
    "grade":             _grade,
    "change_grade":      _change_grade,
    "view_gradebook":    _view_gradebook,
    "release_grades":    _release_grades,
    "assign_staff":      _assign_staff,
    "edit_email":        _edit_email,
    # "enroll" and "manage_roles" are RBAC-only: the role is the whole rule.
}


# ---------------------------------------------------------------------------
# The decision functions.
# ---------------------------------------------------------------------------
def role_allows(user, perm):
    """Step 1 only: could this user's role ever hold this permission?"""
    roles = ROLE_PERMISSIONS.get(perm)
    return roles is not None and user is not None and user.role in roles


def can(user, perm, obj=None, ctx=None):
    """Step 1 (RBAC) then step 2 (ABAC). A permission nobody defined is denied."""
    if not role_allows(user, perm):
        return False
    cond = CONDITIONS.get(perm)
    if cond is None:            # RBAC-only permission
        return True
    return bool(cond(user, obj, ctx or {}))


def _has_extension(user, assignment):
    return Extension.query.filter_by(
        user_id=user.id, assignment_id=assignment.id, approved=True).first() is not None


# ---------------------------------------------------------------------------
# Route declarations (step 19). These only annotate the view function; the
# hook reads the annotations. The matching checks inside the views are deleted.
# ---------------------------------------------------------------------------
def requires(perm, load=None):
    """This route needs `perm`. `load` is a zero-arg callable (reads `request`)
    that returns the object the rule is about, or None if it does not exist."""
    def deco(f):
        f._access = "perm"
        f._perm = perm
        f._load = load
        return f
    return deco


def public(f):
    """No sign-in needed (login, forgot, reset, robots)."""
    f._access = "public"
    return f


def authenticated(f):
    """Any signed-in user; nothing more (dashboard, inbox, /api/me)."""
    f._access = "auth"
    return f


# ---------------------------------------------------------------------------
# The request context and the single hook.
# ---------------------------------------------------------------------------
# N3: campus is 127.0.0.0/8 (this machine) and 10.0.0.0/8.
CAMPUS_NETS = [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("10.0.0.0/8")]


def _client_network():
    """Campus or external, from the real TCP peer address only.

    We deliberately ignore X-Forwarded-For and friends: the client controls
    those headers, so trusting them would hand the attacker the answer (N3).
    """
    addr = request.remote_addr or ""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return "external"
    return "campus" if any(ip in net for net in CAMPUS_NETS) else "external"


def _build_context():
    return {"network": _client_network()}


def _csrf_ok():
    """The request carries this session's CSRF token (step 22)."""
    expected = session.get("csrf_token")
    if not expected:
        return False
    sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
    return bool(sent) and hmac.compare_digest(str(sent), str(expected))


def _deny(status):
    # Short page, no details (step 20). Every denial is logged.
    current_app.logger.warning(
        "access denied %s %s -> %s (user=%s)",
        request.method, request.path, status,
        getattr(current_user, "username", "anonymous"))
    messages = {401: "Sign in required.", 403: "Not allowed.", 404: "Not found."}
    abort(status, messages.get(status, "Denied."))


def install(app):
    """One hook that runs before every request and decides it."""

    @app.context_processor
    def inject_csrf():
        # So every template can drop the token into a form field and a <meta>.
        return {"csrf_token": session.get("csrf_token", "")}

    @app.before_request
    def enforce():
        endpoint = request.endpoint
        if endpoint is None:
            return  # no route matched; let Flask raise 404/405
        if endpoint == "static":
            return

        view = app.view_functions.get(endpoint)
        access = getattr(view, "_access", None)

        if access == "public":
            return  # login, forgot, reset, robots: no session needed

        # Everything else needs a signed-in user.
        if not current_user.is_authenticated:
            return _deny(401)

        # CSRF: every state-changing request must carry this session's token.
        # (Public routes are already returned above, so login/forgot/reset,
        # which have no token yet, are not caught here.)
        if request.method in UNSAFE_METHODS and not _csrf_ok():
            return _deny(403)

        if access == "auth":
            return  # a signed-in user is the whole rule

        if access != "perm":
            # A route nobody gave a rule. Fail closed (test_8).
            return _deny(403)

        perm = view._perm
        load = view._load

        # Step 20 order: role first, so we never load an object for a user
        # whose role could not touch it.
        if not role_allows(current_user, perm):
            return _deny(403)

        obj = load() if load else None
        if load is not None and obj is None:
            return _deny(404)  # object does not exist

        if not can(current_user, perm, obj, _build_context()):
            # Condition failed on a real object -> hide it with 404.
            return _deny(404 if obj is not None else 403)
        # allowed: fall through to the view
