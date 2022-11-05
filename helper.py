from flask import redirect, session
from functools import wraps


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def valid_password(password):
    l, u, d = 0, 0, 0
    passw = password
    for i in passw:
        if (i.islower()):
            l += 1
        if (i.isupper()):
            u += 1
        if (i.isdigit()):
            d += 1
    if len(passw) >= 8 and l >= 1 and u >= 1 and d >= 1:
        return True
    else:
        return False

