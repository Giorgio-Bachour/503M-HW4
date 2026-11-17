"""The four new requirements N1-N4 (Part 4, steps 25-28).

Three cases per rule, at least two denials each -> twelve in all. For N3 one
case sends a forged header from an outside address and expects a refusal.

Each case says which part is RBAC and which is ABAC:
  N1  RBAC: chair gains view_gradebook. ABAC: course.department == chair.department.
  N2  RBAC: unchanged (student submits).  ABAC: deadline + 3 days when an
      approved Extension exists.
  N3  RBAC: unchanged (instructor).       ABAC: released grade needs network=campus.
  N4  RBAC: unchanged (TA/instructor).    ABAC: deny if the grader is enrolled.
"""
from conftest import login
from portal.models import Assignment, Enrollment, Extension, Submission, db
from portal.policy import can

CAMPUS = {"network": "campus"}
EXTERNAL = {"network": "external"}


# ---------------------------------------------------------------- N1: chair
def test_n1_chair_views_own_department_gradebook(world):
    assert can(world["chair"], "view_gradebook", world["cmps215"], CAMPUS) is True


def test_n1_chair_denied_other_department(world):
    world["cmps202"].department = "MATH"      # chair is in CS
    db.session.commit()
    assert can(world["chair"], "view_gradebook", world["cmps202"], CAMPUS) is False


def test_n1_chair_cannot_change_grades(world):
    # view, not change: change_grade's RBAC never lists chair.
    assert can(world["chair"], "change_grade", world["sub_rel_215"], CAMPUS) is False


# ---------------------------------------------------------------- N2: extension
def _a1(course_id=1):
    return Assignment.query.filter(Assignment.title.like("A1%")).first()


def test_n2_late_submit_denied_without_extension(world):
    assert can(world["lina"], "submit", world["a3_late"], CAMPUS) is False


def test_n2_extension_allows_submit_within_three_days(world):
    db.session.add(Extension(user_id=world["lina"].id,
                             assignment_id=world["a3_late"].id, approved=True))
    db.session.commit()
    assert can(world["lina"], "submit", world["a3_late"], CAMPUS) is True


def test_n2_extension_does_not_help_beyond_three_days(world):
    a1 = _a1()                                 # deadline was 10 days ago
    db.session.add(Extension(user_id=world["lina"].id, assignment_id=a1.id, approved=True))
    db.session.commit()
    assert can(world["lina"], "submit", a1, CAMPUS) is False


# ---------------------------------------------------------------- N3: network
def test_n3_change_released_grade_from_campus(world):
    assert can(world["dr_haddad"], "change_grade", world["sub_rel_215"], CAMPUS) is True


def test_n3_change_released_grade_from_outside_denied(world):
    assert can(world["dr_haddad"], "change_grade", world["sub_rel_215"], EXTERNAL) is False


def test_n3_forged_forwarded_header_is_ignored(client, world):
    # The real peer is an outside address; the attacker sets X-Forwarded-For to
    # a campus IP. The server reads remote_addr only, so this is still refused.
    login(client, "dr_haddad")
    r = client.post("/submissions/1/change", data={"grade": "A+"},
                    headers={"X-Forwarded-For": "10.0.0.1"},
                    environ_base={"REMOTE_ADDR": "203.0.113.9"})
    assert r.status_code in (403, 404)


# ---------------------------------------------------------------- N4: TA enrolled
def test_n4_ta_enrolled_in_course_cannot_grade_it(world):
    # rana is TA of CMPS 202 and also enrolled in it.
    assert can(world["rana_ta"], "grade", world["sub_open_202"], CAMPUS) is False


def test_n4_second_enrolled_ta_denial(world):
    sub = world["sub_sami"]
    sub.released = False                        # isolate N4 from the "released" rule
    db.session.commit()
    assert can(world["rana_ta"], "grade", sub, CAMPUS) is False


def test_n4_unenrolled_ta_may_grade(world):
    # omar is TA of CMPS 215 and not enrolled in it: grading is allowed.
    assert can(world["omar_ta"], "grade", world["sub_open_215"], CAMPUS) is True
